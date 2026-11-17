"""Read-only TLS/SSL certificate inspection.

Responsibilities:
    * Determine whether a verified HTTPS connection can be established.
    * Report certificate validity, hostname match, issuer, expiry date and the
      remaining validity period in days.
    * Detect expired certificates and certificates expiring within 30 days.

Certificate verification is never bypassed for the assessment. When a verified
handshake fails (for example because the certificate has expired or the
hostname does not match), a second, clearly-labelled *unverified* handshake is
performed only to retrieve the peer certificate metadata needed to explain the
failure. The resulting finding still reflects the verification failure.
"""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional

from app.services.scanner.config import (
    DEFAULT_CONFIG,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
    CheckCodes,
    ScannerConfig,
)
from app.services.scanner.findings import Finding
from app.services.scanner.target_validator import ValidatedTarget

DEFAULT_TLS_PORT = 443


@dataclass
class TlsProbeResult:
    """Outcome of a TLS probe against a pinned IP."""

    connected: bool
    verified: bool
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    issuer: Optional[str] = None
    subject_cn: Optional[str] = None
    san_count: int = 0
    verification_error: Optional[str] = None
    connection_error: Optional[str] = None


def _parse_asn1_time(value: Optional[str]) -> Optional[datetime]:
    """Parse an ASN.1 UTCTime/GeneralizedTime string into an aware datetime."""
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _extract_metadata(cert: dict) -> dict:
    """Extract issuer, subject CN, validity window and SAN count from a cert dict."""
    issuer_map = dict(entry[0] for entry in cert.get("issuer", ()))
    subject_map = dict(entry[0] for entry in cert.get("subject", ()))
    san = cert.get("subjectAltName", ())
    return {
        "not_before": _parse_asn1_time(cert.get("notBefore")),
        "not_after": _parse_asn1_time(cert.get("notAfter")),
        "issuer": issuer_map.get("organizationName")
        or issuer_map.get("commonName")
        or "Unknown",
        "subject_cn": subject_map.get("commonName"),
        "san_count": len(san),
    }


def _decode_der_certificate(der: bytes) -> Optional[dict]:
    """Decode a DER certificate into the stdlib dict representation.

    Uses the CPython ``ssl`` certificate decoder via a temporary PEM file. If
    the decoder is unavailable, returns ``None`` and callers degrade to the
    verification error message only.
    """
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None:
        return None
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(pem)
        return decoder(path)
    except Exception:
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _retrieve_unverified_metadata(
    hostname: str, pinned_ip: str, port: int, config: ScannerConfig
) -> dict:
    """Retrieve peer certificate metadata without verification.

    Used only to explain a verification failure. No application data is sent
    and no verification decision is derived from this connection.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        raw = socket.create_connection((pinned_ip, port), timeout=config.connect_timeout)
    except (socket.timeout, TimeoutError, ConnectionError, OSError):
        return {}

    try:
        raw.settimeout(config.read_timeout)
        ssock = context.wrap_socket(raw, server_hostname=hostname)
    except Exception:
        try:
            raw.close()
        except OSError:
            pass
        return {}

    try:
        der = ssock.getpeercert(binary_form=True)
    except Exception:
        der = None
    finally:
        try:
            ssock.close()
        except OSError:
            pass

    if not der:
        return {}
    cert = _decode_der_certificate(der)
    return _extract_metadata(cert) if cert else {}


def probe_tls(
    hostname: str,
    pinned_ip: str,
    port: int = DEFAULT_TLS_PORT,
    config: ScannerConfig = DEFAULT_CONFIG,
) -> TlsProbeResult:
    """Perform a verified TLS handshake against a pinned IP.

    The connection is made to ``pinned_ip`` while SNI and certificate hostname
    verification use ``hostname``.
    """
    context = ssl.create_default_context()
    try:
        raw = socket.create_connection((pinned_ip, port), timeout=config.connect_timeout)
    except (socket.timeout, TimeoutError) as exc:
        return TlsProbeResult(connected=False, verified=False, connection_error=f"timeout: {exc}")
    except (ConnectionError, OSError) as exc:
        return TlsProbeResult(connected=False, verified=False, connection_error=str(exc))

    try:
        raw.settimeout(config.read_timeout)
        ssock = context.wrap_socket(raw, server_hostname=hostname)
    except ssl.SSLCertVerificationError as exc:
        try:
            raw.close()
        except OSError:
            pass
        meta = _retrieve_unverified_metadata(hostname, pinned_ip, port, config)
        return TlsProbeResult(connected=True, verified=False, verification_error=str(exc), **meta)
    except (socket.timeout, TimeoutError) as exc:
        try:
            raw.close()
        except OSError:
            pass
        return TlsProbeResult(connected=False, verified=False, connection_error=f"timeout: {exc}")
    except ssl.SSLError as exc:
        try:
            raw.close()
        except OSError:
            pass
        return TlsProbeResult(connected=False, verified=False, connection_error=f"TLS error: {exc}")
    except OSError as exc:
        try:
            raw.close()
        except OSError:
            pass
        return TlsProbeResult(connected=False, verified=False, connection_error=str(exc))

    try:
        cert = ssock.getpeercert() or {}
        return TlsProbeResult(connected=True, verified=True, **_extract_metadata(cert))
    except Exception as exc:  # pragma: no cover - defensive
        return TlsProbeResult(connected=False, verified=False, connection_error=str(exc))
    finally:
        try:
            ssock.close()
        except OSError:
            pass


def _days_remaining(not_after: Optional[datetime], now: datetime) -> Optional[int]:
    if not_after is None:
        return None
    return (not_after - now).days


def inspect_tls(
    target: ValidatedTarget,
    config: ScannerConfig = DEFAULT_CONFIG,
    probe: Optional[Callable[[str, str, int, ScannerConfig], TlsProbeResult]] = None,
) -> List[Finding]:
    """Inspect the TLS certificate of a validated target.

    ``probe`` can be injected for testing; it defaults to :func:`probe_tls`.
    """
    probe_fn = probe or probe_tls
    result = probe_fn(target.hostname, target.pinned_ip, DEFAULT_TLS_PORT, config)
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    if not result.connected:
        findings.append(
            Finding(
                check_code=CheckCodes.TLS_CONNECTION,
                title="TLS connection could not be established",
                description=(
                    f"Could not establish a TLS connection to {target.hostname}: "
                    f"{result.connection_error}"
                ),
                severity=SEVERITY_HIGH,
                recommendation=(
                    "Ensure the host exposes a working HTTPS endpoint on port 443 "
                    "with a supported TLS configuration."
                ),
                evidence=result.connection_error,
            )
        )
        return findings

    if result.verified:
        days_remaining = _days_remaining(result.not_after, now)
        findings.append(
            Finding(
                check_code=CheckCodes.TLS_CONNECTION,
                title="TLS connection established and certificate verified",
                description=f"A verified TLS connection to {target.hostname} succeeded.",
                severity=SEVERITY_INFO,
                recommendation="No action required.",
                evidence=f"pinned_ip={target.pinned_ip}; port={DEFAULT_TLS_PORT}",
            )
        )
        findings.append(
            Finding(
                check_code=CheckCodes.TLS_CERT_ISSUER,
                title="Certificate issuer",
                description=f"The certificate is issued by {result.issuer or 'Unknown'}.",
                severity=SEVERITY_INFO,
                recommendation="Ensure the certificate chains to a trusted certificate authority.",
                evidence=(
                    f"issuer={result.issuer}; subject_cn={result.subject_cn}; "
                    f"san_count={result.san_count}; notBefore={result.not_before}; "
                    f"notAfter={result.not_after}"
                ),
            )
        )

        if result.not_after is not None and result.not_after < now:
            findings.append(
                Finding(
                    check_code=CheckCodes.TLS_CERT_EXPIRED,
                    title="TLS certificate has expired",
                    description=(
                        "The TLS certificate presented by the server has expired. "
                        "Browsers will warn visitors and may block access."
                    ),
                    severity=SEVERITY_CRITICAL,
                    recommendation="Renew or replace the TLS certificate immediately.",
                    evidence=f"notAfter={result.not_after.isoformat()}",
                )
            )
        elif days_remaining is not None and days_remaining <= config.cert_expiring_soon_threshold_days:
            findings.append(
                Finding(
                    check_code=CheckCodes.TLS_CERT_EXPIRING,
                    title="TLS certificate expiring soon",
                    description=(
                        f"The TLS certificate expires in {days_remaining} day(s), "
                        "within the 30-day warning window."
                    ),
                    severity=SEVERITY_MEDIUM,
                    recommendation="Renew the TLS certificate before it expires.",
                    evidence=(
                        f"notAfter={result.not_after.isoformat()}; "
                        f"days_remaining={days_remaining}"
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    check_code=CheckCodes.TLS_CERT_VALID,
                    title="TLS certificate is valid",
                    description=(
                        "The TLS certificate is valid and matches the requested hostname."
                        + (
                            f" It has {days_remaining} day(s) of validity remaining."
                            if days_remaining is not None
                            else ""
                        )
                    ),
                    severity=SEVERITY_INFO,
                    recommendation="No action required.",
                    evidence=(
                        f"notAfter={result.not_after}; days_remaining={days_remaining}; "
                        f"issuer={result.issuer}"
                    ),
                )
            )
        return findings

    # Handshake reached the server but certificate verification failed.
    verify_message = (result.verification_error or "").lower()
    days_remaining = _days_remaining(result.not_after, now)

    if result.not_after is not None and result.not_after < now:
        findings.append(
            Finding(
                check_code=CheckCodes.TLS_CERT_EXPIRED,
                title="TLS certificate has expired",
                description="The TLS certificate presented by the server has expired.",
                severity=SEVERITY_CRITICAL,
                recommendation="Renew or replace the TLS certificate immediately.",
                evidence=(
                    f"notAfter={result.not_after.isoformat()}; "
                    f"verification_error={result.verification_error}"
                ),
            )
        )
    elif "hostname" in verify_message or "doesn't match" in verify_message or "not valid for" in verify_message:
        findings.append(
            Finding(
                check_code=CheckCodes.TLS_CERT_MISMATCH,
                title="TLS certificate hostname mismatch",
                description=(
                    "The certificate presented by the server does not match the requested "
                    "hostname."
                ),
                severity=SEVERITY_HIGH,
                recommendation=(
                    "Install a certificate that includes the requested hostname "
                    "(as a CN or Subject Alternative Name)."
                ),
                evidence=f"verification_error={result.verification_error}",
            )
        )
    else:
        findings.append(
            Finding(
                check_code=CheckCodes.TLS_CERT_INVALID,
                title="TLS certificate could not be verified",
                description=(
                    "The certificate presented by the server could not be verified against "
                    "the system trust store (for example it is self-signed or issued by an "
                    "untrusted CA)."
                ),
                severity=SEVERITY_HIGH,
                recommendation=(
                    "Install a certificate issued by a trusted certificate authority and "
                    "serve the full certificate chain."
                ),
                evidence=f"verification_error={result.verification_error}",
            )
        )

    if result.issuer:
        findings.append(
            Finding(
                check_code=CheckCodes.TLS_CERT_ISSUER,
                title="Certificate issuer",
                description=f"The certificate is issued by {result.issuer}.",
                severity=SEVERITY_INFO,
                recommendation="Ensure the certificate chains to a trusted certificate authority.",
                evidence=(
                    f"issuer={result.issuer}; subject_cn={result.subject_cn}; "
                    f"notAfter={result.not_after}; days_remaining={days_remaining}"
                ),
            )
        )

    return findings