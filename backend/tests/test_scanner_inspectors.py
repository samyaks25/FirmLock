"""Tests for the individual read-only scanner inspectors.

All external network access is mocked by injecting the probe/request/query
callables. No real sockets or DNS queries are made.

Covers:
    * ``tls_inspector.inspect_tls`` - valid, expiring, expired, mismatch,
      invalid certificate and connection-failure paths.
    * ``https_inspector.inspect_https`` - reachability, HTTP->HTTPS redirect,
      no-redirect, unsafe redirect destination.
    * ``header_inspector.inspect_headers`` - presence/weakness of HSTS, CSP,
      X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
      Permissions-Policy; HTTPS vs HTTP fallback; unreachable.
    * ``dns_inspector.inspect_dns`` - SPF, DMARC, CAA (missing/malformed/
      present) and DNS query failure handling.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

import dns.exception
import dns.resolver

from app.services.scanner import dns_inspector, header_inspector, https_inspector, tls_inspector
from app.services.scanner.config import DEFAULT_CONFIG
from app.services.scanner.findings import Finding
from app.services.scanner.pinned_http import HttpResponse
from app.services.scanner.target_validator import ValidatedTarget
from app.services.scanner.tls_inspector import TlsProbeResult


def _target() -> ValidatedTarget:
    return ValidatedTarget(
        hostname="example.com",
        pinned_ip="8.8.8.8",
        addresses=["8.8.8.8"],
        safe_addresses=["8.8.8.8"],
    )


def _codes(findings):
    return {f.check_code for f in findings}


def _by_code(findings):
    return {f.check_code: f for f in findings}


def _probe_returning(result: TlsProbeResult):
    def _probe(hostname, pinned_ip, port, config):
        return result

    return _probe


class TlsInspectorTests(unittest.TestCase):
    def test_valid_certificate(self) -> None:
        future = datetime.now(timezone.utc) + timedelta(days=200)
        result = TlsProbeResult(
            connected=True, verified=True, not_after=future, issuer="Test CA",
            subject_cn="example.com", san_count=1,
        )
        findings = tls_inspector.inspect_tls(_target(), DEFAULT_CONFIG, _probe_returning(result))
        codes = _codes(findings)
        self.assertIn("TLS_CONNECTION", codes)
        self.assertIn("TLS_CERT_VALID", codes)
        self.assertNotIn("TLS_CERT_EXPIRING", codes)

    def test_certificate_expiring_soon(self) -> None:
        soon = datetime.now(timezone.utc) + timedelta(days=10)
        result = TlsProbeResult(connected=True, verified=True, not_after=soon, issuer="Test CA")
        findings = tls_inspector.inspect_tls(_target(), DEFAULT_CONFIG, _probe_returning(result))
        self.assertIn("TLS_CERT_EXPIRING", _codes(findings))
        expiring = _by_code(findings)["TLS_CERT_EXPIRING"]
        self.assertEqual(expiring.severity, "medium")

    def test_certificate_expired(self) -> None:
        past = datetime.now(timezone.utc) - timedelta(days=1)
        result = TlsProbeResult(
            connected=True, verified=False, not_after=past,
            verification_error="certificate has expired",
        )
        findings = tls_inspector.inspect_tls(_target(), DEFAULT_CONFIG, _probe_returning(result))
        expired = _by_code(findings).get("TLS_CERT_EXPIRED")
        self.assertIsNotNone(expired)
        self.assertEqual(expired.severity, "critical")

    def test_hostname_mismatch(self) -> None:
        result = TlsProbeResult(
            connected=True, verified=False,
            verification_error="Hostname mismatch, certificate is not valid for 'example.com'.",
        )
        findings = tls_inspector.inspect_tls(_target(), DEFAULT_CONFIG, _probe_returning(result))
        self.assertIn("TLS_CERT_MISMATCH", _codes(findings))
        self.assertEqual(_by_code(findings)["TLS_CERT_MISMATCH"].severity, "high")

    def test_untrusted_certificate(self) -> None:
        result = TlsProbeResult(
            connected=True, verified=False,
            verification_error="certificate verify failed: self signed certificate",
        )
        findings = tls_inspector.inspect_tls(_target(), DEFAULT_CONFIG, _probe_returning(result))
        self.assertIn("TLS_CERT_INVALID", _codes(findings))

    def test_connection_failure(self) -> None:
        result = TlsProbeResult(connected=False, verified=False, connection_error="timeout")
        findings = tls_inspector.inspect_tls(_target(), DEFAULT_CONFIG, _probe_returning(result))
        connection = _by_code(findings)["TLS_CONNECTION"]
        self.assertEqual(connection.severity, "high")


class HttpsInspectorTests(unittest.TestCase):
    def _requester(self, https_response, http_response):
        def _request(scheme, host, pinned_ip, port, config, path="/"):
            return https_response if scheme == "https" else http_response

        return _request

    def test_https_accessible_and_redirect(self) -> None:
        https = HttpResponse(status=200)
        http = HttpResponse(status=301, headers={"location": "https://8.8.8.8/"})
        findings = https_inspector.inspect_https(
            _target(), DEFAULT_CONFIG, self._requester(https, http)
        )
        codes = _codes(findings)
        self.assertIn("HTTPS_ACCESSIBLE", codes)
        self.assertIn("HTTP_TO_HTTPS_REDIRECT", codes)

    def test_https_not_accessible(self) -> None:
        https = HttpResponse(error="timeout", error_type="timeout")
        http = HttpResponse(status=301, headers={"location": "https://8.8.8.8/"})
        findings = https_inspector.inspect_https(
            _target(), DEFAULT_CONFIG, self._requester(https, http)
        )
        self.assertIn("HTTPS_NOT_ACCESSIBLE", _codes(findings))
        self.assertEqual(_by_code(findings)["HTTPS_NOT_ACCESSIBLE"].severity, "high")

    def test_http_no_redirect_serves_content(self) -> None:
        https = HttpResponse(status=200)
        http = HttpResponse(status=200, headers={})
        findings = https_inspector.inspect_https(
            _target(), DEFAULT_CONFIG, self._requester(https, http)
        )
        codes = _codes(findings)
        self.assertIn("HTTP_NO_REDIRECT", codes)
        self.assertIn("HTTP_INSECURE_ACCESSIBLE", codes)

    def test_redirect_to_private_ip_is_flagged(self) -> None:
        https = HttpResponse(status=200)
        http = HttpResponse(status=302, headers={"location": "http://127.0.0.1/"})
        findings = https_inspector.inspect_https(
            _target(), DEFAULT_CONFIG, self._requester(https, http)
        )
        self.assertIn("REDIRECT_INVALID", _codes(findings))
        self.assertEqual(_by_code(findings)["REDIRECT_INVALID"].severity, "high")

    def test_redirect_without_location_header(self) -> None:
        https = HttpResponse(status=200)
        http = HttpResponse(status=301, headers={})
        findings = https_inspector.inspect_https(
            _target(), DEFAULT_CONFIG, self._requester(https, http)
        )
        self.assertIn("REDIRECT_INVALID", _codes(findings))

    def test_http_unreachable(self) -> None:
        https = HttpResponse(status=200)
        http = HttpResponse(error="connection refused", error_type="connection")
        findings = https_inspector.inspect_https(
            _target(), DEFAULT_CONFIG, self._requester(https, http)
        )
        self.assertIn("HTTP_UNREACHABLE", _codes(findings))


class HeaderInspectorTests(unittest.TestCase):
    _GOOD_HEADERS = {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=()",
    }

    def _requester(self, https_response, http_response):
        def _request(scheme, host, pinned_ip, port, config, path="/"):
            return https_response if scheme == "https" else http_response

        return _request

    def test_all_headers_present_no_findings(self) -> None:
        https = HttpResponse(status=200, headers=dict(self._GOOD_HEADERS))
        findings = header_inspector.inspect_headers(
            _target(), DEFAULT_CONFIG, self._requester(https, HttpResponse(status=200))
        )
        self.assertEqual(findings, [])

    def test_missing_headers_reported(self) -> None:
        https = HttpResponse(status=200, headers={})
        findings = header_inspector.inspect_headers(
            _target(), DEFAULT_CONFIG, self._requester(https, HttpResponse(status=200))
        )
        codes = _codes(findings)
        for expected in (
            "HSTS_MISSING",
            "CSP_MISSING",
            "X_CONTENT_TYPE_OPTIONS_MISSING",
            "X_FRAME_OPTIONS_MISSING",
            "REFERRER_POLICY_MISSING",
            "PERMISSIONS_POLICY_MISSING",
        ):
            self.assertIn(expected, codes)
        # HSTS missing over HTTPS is high severity.
        self.assertEqual(_by_code(findings)["HSTS_MISSING"].severity, "high")

    def test_weak_hsts_max_age(self) -> None:
        headers = dict(self._GOOD_HEADERS)
        headers["strict-transport-security"] = "max-age=100"
        https = HttpResponse(status=200, headers=headers)
        findings = header_inspector.inspect_headers(
            _target(), DEFAULT_CONFIG, self._requester(https, HttpResponse(status=200))
        )
        self.assertIn("HSTS_WEAK", _codes(findings))

    def test_csp_unsafe_inline(self) -> None:
        headers = dict(self._GOOD_HEADERS)
        headers["content-security-policy"] = "default-src 'self'; script-src 'unsafe-inline'"
        https = HttpResponse(status=200, headers=headers)
        findings = header_inspector.inspect_headers(
            _target(), DEFAULT_CONFIG, self._requester(https, HttpResponse(status=200))
        )
        self.assertIn("CSP_WEAK", _codes(findings))

    def test_x_content_type_options_wrong_value(self) -> None:
        headers = dict(self._GOOD_HEADERS)
        headers["x-content-type-options"] = "sniff"
        https = HttpResponse(status=200, headers=headers)
        findings = header_inspector.inspect_headers(
            _target(), DEFAULT_CONFIG, self._requester(https, HttpResponse(status=200))
        )
        self.assertIn("X_CONTENT_TYPE_OPTIONS_WEAK", _codes(findings))

    def test_x_frame_options_wrong_value(self) -> None:
        headers = dict(self._GOOD_HEADERS)
        headers["x-frame-options"] = "ALLOW-FROM https://example.com"
        https = HttpResponse(status=200, headers=headers)
        findings = header_inspector.inspect_headers(
            _target(), DEFAULT_CONFIG, self._requester(https, HttpResponse(status=200))
        )
        self.assertIn("X_FRAME_OPTIONS_WEAK", _codes(findings))

    def test_http_fallback_hsts_is_medium(self) -> None:
        https = HttpResponse(error="ssl error", error_type="ssl")
        http = HttpResponse(status=200, headers={})
        findings = header_inspector.inspect_headers(
            _target(), DEFAULT_CONFIG, self._requester(https, http)
        )
        hsts = _by_code(findings).get("HSTS_MISSING")
        self.assertIsNotNone(hsts)
        self.assertEqual(hsts.severity, "medium")

    def test_unreachable_reports_unavailable(self) -> None:
        https = HttpResponse(error="ssl error", error_type="ssl")
        http = HttpResponse(error="refused", error_type="connection")
        findings = header_inspector.inspect_headers(
            _target(), DEFAULT_CONFIG, self._requester(https, http)
        )
        self.assertIn("HEADERS_UNAVAILABLE", _codes(findings))


class _FakeDnsQuery:
    """Dispatch fake DNS query function keyed by (name, rdtype)."""

    def __init__(self, mapping):
        self.mapping = mapping

    def __call__(self, name, rdtype, config):
        value = self.mapping.get((name, rdtype), dns.resolver.NoAnswer())
        if isinstance(value, Exception):
            raise value
        return list(value)


class DnsInspectorTests(unittest.TestCase):
    def _run(self, mapping):
        return dns_inspector.inspect_dns(
            "example.com", DEFAULT_CONFIG, _FakeDnsQuery(mapping)
        )

    def test_valid_spf_dmarc_and_caa_present(self) -> None:
        mapping = {
            ("example.com", "TXT"): ["v=spf1 include:_spf.example.com -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=quarantine; rua=mailto:d@example.com"],
            ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
        }
        findings = self._run(mapping)
        codes = _codes(findings)
        self.assertNotIn("SPF_MISSING", codes)
        self.assertNotIn("DMARC_MISSING", codes)
        self.assertIn("CAA_RECORD", codes)

    def test_spf_missing(self) -> None:
        mapping = {
            ("example.com", "TXT"): dns.resolver.NoAnswer(),
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
            ("example.com", "CAA"): dns.resolver.NoAnswer(),
        }
        findings = self._run(mapping)
        self.assertIn("SPF_MISSING", _codes(findings))

    def test_multiple_spf_records(self) -> None:
        mapping = {
            ("example.com", "TXT"): ["v=spf1 -all", "v=spf1 +all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
            ("example.com", "CAA"): dns.resolver.NoAnswer(),
        }
        findings = self._run(mapping)
        self.assertIn("SPF_MULTIPLE", _codes(findings))

    def test_malformed_spf(self) -> None:
        mapping = {
            ("example.com", "TXT"): ["v=spf1 include:_spf.example.com"],  # no all
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
            ("example.com", "CAA"): dns.resolver.NoAnswer(),
        }
        findings = self._run(mapping)
        self.assertIn("SPF_MALFORMED", _codes(findings))

    def test_dmarc_missing(self) -> None:
        mapping = {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): dns.resolver.NoAnswer(),
            ("example.com", "CAA"): dns.resolver.NoAnswer(),
        }
        findings = self._run(mapping)
        self.assertIn("DMARC_MISSING", _codes(findings))

    def test_dmarc_malformed(self) -> None:
        mapping = {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; rua=mailto:d@example.com"],  # no p=
            ("example.com", "CAA"): dns.resolver.NoAnswer(),
        }
        findings = self._run(mapping)
        self.assertIn("DMARC_MALFORMED", _codes(findings))

    def test_caa_absent(self) -> None:
        mapping = {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
            ("example.com", "CAA"): dns.resolver.NoAnswer(),
        }
        findings = self._run(mapping)
        self.assertIn("CAA_ABSENT", _codes(findings))

    def test_dns_query_failure_is_unknown_not_vulnerability(self) -> None:
        mapping = {
            ("example.com", "TXT"): dns.exception.Timeout(),
            ("_dmarc.example.com", "TXT"): dns.exception.Timeout(),
            ("example.com", "CAA"): dns.exception.Timeout(),
        }
        findings = self._run(mapping)
        self.assertIn("DNS_TIMEOUT", _codes(findings))
        self.assertTrue(all(f.severity == "info" for f in findings if f.check_code == "DNS_TIMEOUT"))


if __name__ == "__main__":
    unittest.main()