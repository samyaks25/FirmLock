"""Tests for target validation, SSRF protection and DNS-pinned transport.

Covers:
    * ``validate_hostname`` - syntax and rejection of IP literals / URLs.
    * ``is_ip_literal`` / ``is_safe_ip`` - private, loopback, reserved,
      link-local, multicast, unspecified and cloud-metadata rejection.
    * ``resolve_and_validate`` - DNS resolution, pinning, fail-closed.
    * ``validate_redirect_target`` - independent redirect validation.
    * ``pinned_http`` - response helper, verifying TLS context, and that
      connection errors are converted (never raised).

No real network access is performed: the resolver and socket layer are
injected/patched.
"""

from __future__ import annotations

import socket
import ssl
import unittest
from unittest import mock

import dns.exception  # noqa: F401  (ensures dnspython importable in this env)

from app.services.scanner import pinned_http
from app.services.scanner.config import DEFAULT_CONFIG
from app.services.scanner.target_validator import (
    InvalidTargetError,
    TargetDNSResolutionError,
    UnsafeTargetError,
    ValidatedTarget,
    is_ip_literal,
    is_safe_ip,
    resolve_and_validate,
    validate_hostname,
    validate_redirect_target,
)


def _resolver_returning(addresses):
    """Build a fake resolver that always returns ``addresses``."""

    def _resolve(hostname, config):
        return list(addresses)

    return _resolve


def _resolver_raising(exc):
    def _resolve(hostname, config):
        raise exc

    return _resolve


class ValidateHostnameTests(unittest.TestCase):
    def test_accepts_valid_hostname(self) -> None:
        self.assertEqual(validate_hostname("Example.COM"), "example.com")

    def test_accepts_subdomain_and_trailing_dot(self) -> None:
        self.assertEqual(validate_hostname("sub.example.co.uk."), "sub.example.co.uk")

    def test_rejects_empty(self) -> None:
        with self.assertRaises(InvalidTargetError):
            validate_hostname("")

    def test_rejects_ip_literals(self) -> None:
        for value in ("192.168.1.1", "8.8.8.8", "::1", "2001:4860:4860::8888"):
            with self.subTest(value=value):
                with self.assertRaises(InvalidTargetError):
                    validate_hostname(value)

    def test_rejects_urls_and_paths(self) -> None:
        for value in (
            "https://example.com",
            "example.com/path",
            "example.com?q=1",
            "user@example.com",
            "example.com:443",
            "exa mple.com",
        ):
            with self.subTest(value=value):
                with self.assertRaises(InvalidTargetError):
                    validate_hostname(value)

    def test_rejects_single_label(self) -> None:
        with self.assertRaises(InvalidTargetError):
            validate_hostname("localhost")


class IsIpLiteralTests(unittest.TestCase):
    def test_ipv4_literal(self) -> None:
        self.assertTrue(is_ip_literal("1.2.3.4"))

    def test_ipv6_literal(self) -> None:
        self.assertTrue(is_ip_literal("::1"))
        self.assertTrue(is_ip_literal("[::1]"))

    def test_hostname_not_literal(self) -> None:
        self.assertFalse(is_ip_literal("example.com"))


class IsSafeIpTests(unittest.TestCase):
    def test_public_ipv4_is_safe(self) -> None:
        for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
            with self.subTest(ip=ip):
                self.assertTrue(is_safe_ip(ip))

    def test_public_ipv6_is_safe(self) -> None:
        self.assertTrue(is_safe_ip("2001:4860:4860::8888"))

    def test_rejects_loopback(self) -> None:
        self.assertFalse(is_safe_ip("127.0.0.1"))
        self.assertFalse(is_safe_ip("::1"))

    def test_rejects_private_ranges(self) -> None:
        for ip in ("10.0.0.1", "172.16.5.4", "192.168.1.1", "fc00::1", "fd12::1"):
            with self.subTest(ip=ip):
                self.assertFalse(is_safe_ip(ip))

    def test_rejects_link_local_and_metadata(self) -> None:
        for ip in ("169.254.1.1", "169.254.169.254", "169.254.169.253", "fe80::1"):
            with self.subTest(ip=ip):
                self.assertFalse(is_safe_ip(ip))

    def test_rejects_unspecified_and_multicast(self) -> None:
        self.assertFalse(is_safe_ip("0.0.0.0"))
        self.assertFalse(is_safe_ip("224.0.0.1"))

    def test_rejects_reserved_and_documentation(self) -> None:
        self.assertFalse(is_safe_ip("192.0.2.10"))  # TEST-NET-1
        self.assertFalse(is_safe_ip("240.0.0.1"))  # reserved

    def test_rejects_cloud_metadata_explicit(self) -> None:
        self.assertFalse(is_safe_ip("100.100.100.200"))

    def test_rejects_garbage_fails_closed(self) -> None:
        self.assertFalse(is_safe_ip("not-an-ip"))


class ResolveAndValidateTests(unittest.TestCase):
    def test_pins_public_ipv4(self) -> None:
        target = resolve_and_validate(
            "example.com", DEFAULT_CONFIG, _resolver_returning(["8.8.8.8", "1.1.1.1"])
        )
        self.assertIsInstance(target, ValidatedTarget)
        self.assertEqual(target.hostname, "example.com")
        self.assertEqual(target.pinned_ip, "8.8.8.8")  # prefers IPv4
        self.assertEqual(target.safe_addresses, ["8.8.8.8", "1.1.1.1"])

    def test_pins_ipv4_when_mixed_with_ipv6(self) -> None:
        target = resolve_and_validate(
            "example.com", DEFAULT_CONFIG, _resolver_returning(["2001:4860::1", "9.9.9.9"])
        )
        self.assertEqual(target.pinned_ip, "9.9.9.9")

    def test_rejects_when_all_addresses_unsafe(self) -> None:
        with self.assertRaises(UnsafeTargetError):
            resolve_and_validate(
                "internal.example", DEFAULT_CONFIG, _resolver_returning(["10.0.0.5"])
            )

    def test_rejects_mixed_but_keeps_safe(self) -> None:
        target = resolve_and_validate(
            "example.com", DEFAULT_CONFIG, _resolver_returning(["10.0.0.5", "8.8.8.8"])
        )
        self.assertEqual(target.pinned_ip, "8.8.8.8")

    def test_empty_resolution_is_dns_error(self) -> None:
        with self.assertRaises(TargetDNSResolutionError):
            resolve_and_validate("example.com", DEFAULT_CONFIG, _resolver_returning([]))

    def test_invalid_hostname_raises_invalid(self) -> None:
        with self.assertRaises(InvalidTargetError):
            resolve_and_validate("not a domain", DEFAULT_CONFIG, _resolver_returning(["8.8.8.8"]))


class ValidateRedirectTargetTests(unittest.TestCase):
    def test_public_https_redirect_is_valid(self) -> None:
        check = validate_redirect_target("https://8.8.8.8/", "http://example.com/")
        self.assertTrue(check.valid)
        self.assertEqual(check.scheme, "https")
        self.assertEqual(check.port, 443)
        self.assertEqual(check.pinned_ip, "8.8.8.8")

    def test_private_ip_redirect_is_rejected(self) -> None:
        check = validate_redirect_target("http://127.0.0.1/", "http://example.com/")
        self.assertFalse(check.valid)
        self.assertIn("non-public", check.reason)

    def test_metadata_ip_redirect_is_rejected(self) -> None:
        check = validate_redirect_target("http://169.254.169.254/", "http://example.com/")
        self.assertFalse(check.valid)

    def test_disallowed_scheme_is_rejected(self) -> None:
        check = validate_redirect_target("ftp://example.com/", "http://example.com/")
        self.assertFalse(check.valid)
        self.assertIn("scheme", check.reason.lower())

    def test_disallowed_port_is_rejected(self) -> None:
        check = validate_redirect_target("https://example.com:8443/", "http://example.com/")
        self.assertFalse(check.valid)
        self.assertIn("port", check.reason.lower())

    def test_empty_location_is_rejected(self) -> None:
        check = validate_redirect_target("", "http://example.com/")
        self.assertFalse(check.valid)

    def test_hostname_resolving_public_is_valid(self) -> None:
        check = validate_redirect_target(
            "https://secure.example.com/", "http://example.com/",
            resolver=_resolver_returning(["8.8.8.8"]),
        )
        self.assertTrue(check.valid)
        self.assertEqual(check.host, "secure.example.com")

    def test_hostname_resolving_private_is_rejected(self) -> None:
        check = validate_redirect_target(
            "https://internal.example.com/", "http://example.com/",
            resolver=_resolver_returning(["10.1.2.3"]),
        )
        self.assertFalse(check.valid)
        self.assertIn("non-public", check.reason)


class PinnedHttpTests(unittest.TestCase):
    def test_response_ok_property(self) -> None:
        self.assertTrue(pinned_http.HttpResponse(status=200).ok)
        self.assertFalse(pinned_http.HttpResponse(error="boom").ok)

    def test_build_ssl_context_verifies(self) -> None:
        context = pinned_http.build_ssl_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_unsupported_scheme_returns_error(self) -> None:
        response = pinned_http.http_request("ftp", "example.com", "8.8.8.8", 21)
        self.assertFalse(response.ok)
        self.assertEqual(response.error_type, "scheme")

    def test_connection_error_is_converted(self) -> None:
        with mock.patch.object(
            pinned_http.socket, "create_connection", side_effect=OSError("refused")
        ):
            response = pinned_http.http_request("http", "example.com", "8.8.8.8", 80)
        self.assertFalse(response.ok)
        self.assertEqual(response.error_type, "connection")

    def test_timeout_is_converted(self) -> None:
        with mock.patch.object(
            pinned_http.socket, "create_connection", side_effect=socket.timeout("slow")
        ):
            response = pinned_http.http_request("http", "example.com", "8.8.8.8", 80)
        self.assertFalse(response.ok)
        self.assertEqual(response.error_type, "timeout")


if __name__ == "__main__":
    unittest.main()