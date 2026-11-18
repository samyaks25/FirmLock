"""Scanner configuration constants and severity heuristics.

Centralises tunable limits, check identifiers and severity rules so that the
scanner behaves consistently and can be audited without touching business
logic. The scanner is passive, read-only and fails closed when it cannot
verify the safety of a target.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerConfig:
    """Runtime configuration for the security scanner.

    All values are intentionally conservative. The scanner only performs a
    small, bounded number of requests per scan and never follows redirects
    automatically.
    """

    # --- Network timeouts (seconds) -------------------------------------
    connect_timeout: float = 8.0
    read_timeout: float = 10.0
    write_timeout: float = 8.0
    total_timeout: float = 25.0

    # --- DNS resolution timeout (seconds) -------------------------------
    dns_timeout: float = 5.0

    # --- Resource limits -------------------------------------------------
    # Maximum number of bytes to read from any HTTP response body. The scanner
    # only needs response headers, so bodies are never fully downloaded.
    max_response_bytes: int = 64 * 1024  # 64 KiB
    # Upper bound on how many Location headers the scanner will validate in a
    # single scan. Redirects are never followed automatically.
    max_redirect_checks: int = 3
    # Maximum number of scans that may run concurrently. Kept low so a single
    # process never performs aggressive parallel scanning.
    max_concurrent_scans: int = 2
    # How long a background scan may wait to acquire a concurrency slot.
    scan_acquire_timeout: float = 300.0

    # --- Certificate expiry thresholds (days) ---------------------------
    cert_expired_threshold_days: int = 0
    cert_expiring_soon_threshold_days: int = 30

    # --- Allowed schemes and ports --------------------------------------
    allowed_schemes: tuple[str, ...] = ("http", "https")
    allowed_ports: tuple[int, ...] = (80, 443)

    # --- Cloud metadata endpoints (must never be contacted) -------------
    cloud_metadata_ips: tuple[str, ...] = (
        "169.254.169.254",  # AWS / Azure / OpenStack / DigitalOcean
        "169.254.169.253",  # AWS VPC
        "169.254.169.252",  # AWS VPC
        "100.100.100.200",  # Alibaba Cloud
        "fd00:ec2::254",    # AWS IPv6 metadata
    )

    # --- HTTP ------------------------------------------------------------
    user_agent: str = "FirmLock-Scanner/1.0 (+passive-security-scan)"


# ---------------------------------------------------------------------------
# Severity heuristics (preliminary, documented, and conservative).
#
# These rules are intentionally simple so that reviewers can audit the
# rationale behind every severity assignment. They are NOT a security score;
# scoring belongs to Stage 04.
#
# - critical: A condition that breaks trust or is directly exploitable with no
#   user interaction (e.g. an expired TLS certificate on a public site, which
#   causes browsers to warn every visitor).
# - high:     A clear security misconfiguration that materially weakens
#             protection (e.g. missing HSTS on an HTTPS site, an invalid TLS
#             certificate, or an unsafe redirect destination).
# - medium:   A missing defence-in-depth control or a partially insecure
#             configuration (e.g. missing CSP, missing SPF/DMARC, an HTTP
#             endpoint that does not redirect to HTTPS).
# - low:      A minor hardening gap with limited direct impact (e.g. missing
#             X-Content-Type-Options or Referrer-Policy).
# - info:     Observational findings with no direct security impact (e.g. a
#             certificate issuer, CAA records present, successful connection).
# ---------------------------------------------------------------------------

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

VALID_SEVERITIES = (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
)


class CheckCodes:
    """Canonical check identifiers for scanner findings.

    Reusing the same code within a scan prevents duplicate findings. Codes are
    grouped by the module that emits them.
    """

    # --- Target validation (target_validator.py) ---
    TARGET_VALID = "TARGET_VALID"
    TARGET_INVALID = "TARGET_INVALID"
    TARGET_SSRF_REJECTED = "TARGET_SSRF_REJECTED"
    TARGET_DNS_FAILED = "TARGET_DNS_FAILED"

    # --- TLS / SSL (tls_inspector.py) ---
    TLS_CONNECTION = "TLS_CONNECTION"
    TLS_CERT_VALID = "TLS_CERT_VALID"
    TLS_CERT_EXPIRED = "TLS_CERT_EXPIRED"
    TLS_CERT_MISMATCH = "TLS_CERT_MISMATCH"
    TLS_CERT_EXPIRING = "TLS_CERT_EXPIRING"
    TLS_CERT_ISSUER = "TLS_CERT_ISSUER"
    TLS_CERT_INVALID = "TLS_CERT_INVALID"

    # --- HTTPS behaviour (https_inspector.py) ---
    HTTPS_ACCESSIBLE = "HTTPS_ACCESSIBLE"
    HTTPS_NOT_ACCESSIBLE = "HTTPS_NOT_ACCESSIBLE"
    HTTP_TO_HTTPS_REDIRECT = "HTTP_TO_HTTPS_REDIRECT"
    HTTP_NO_REDIRECT = "HTTP_NO_REDIRECT"
    HTTP_INSECURE_ACCESSIBLE = "HTTP_INSECURE_ACCESSIBLE"
    HTTP_UNREACHABLE = "HTTP_UNREACHABLE"
    REDIRECT_INVALID = "REDIRECT_INVALID"

    # --- HTTP security headers (header_inspector.py) ---
    HSTS_MISSING = "HSTS_MISSING"
    HSTS_WEAK = "HSTS_WEAK"
    CSP_MISSING = "CSP_MISSING"
    CSP_WEAK = "CSP_WEAK"
    X_CONTENT_TYPE_OPTIONS_MISSING = "X_CONTENT_TYPE_OPTIONS_MISSING"
    X_CONTENT_TYPE_OPTIONS_WEAK = "X_CONTENT_TYPE_OPTIONS_WEAK"
    X_FRAME_OPTIONS_MISSING = "X_FRAME_OPTIONS_MISSING"
    X_FRAME_OPTIONS_WEAK = "X_FRAME_OPTIONS_WEAK"
    REFERRER_POLICY_MISSING = "REFERRER_POLICY_MISSING"
    PERMISSIONS_POLICY_MISSING = "PERMISSIONS_POLICY_MISSING"
    HEADERS_UNAVAILABLE = "HEADERS_UNAVAILABLE"

    # --- DNS security (dns_inspector.py) ---
    SPF_MISSING = "SPF_MISSING"
    SPF_MULTIPLE = "SPF_MULTIPLE"
    SPF_MALFORMED = "SPF_MALFORMED"
    DMARC_MISSING = "DMARC_MISSING"
    DMARC_MALFORMED = "DMARC_MALFORMED"
    CAA_RECORD = "CAA_RECORD"
    CAA_ABSENT = "CAA_ABSENT"
    DNS_TIMEOUT = "DNS_TIMEOUT"


DEFAULT_CONFIG = ScannerConfig()