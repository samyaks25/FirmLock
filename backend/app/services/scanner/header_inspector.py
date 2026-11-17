"""HTTP security header inspection.

Responsibilities:
    * Check for the presence of key security response headers.
    * Detect clearly insecure header values.
    * Avoid overstating severity: a missing header is a hardening gap, not a
      critical vulnerability.

Headers are fetched over HTTPS when possible (with certificate verification
left enabled), falling back to HTTP only when HTTPS is unavailable. HSTS is
only meaningful over HTTPS, which is reflected in the findings.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from app.services.scanner.config import (
    DEFAULT_CONFIG,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    CheckCodes,
    ScannerConfig,
)
from app.services.scanner.findings import Finding
from app.services.scanner.pinned_http import HttpResponse, http_request
from app.services.scanner.target_validator import ValidatedTarget

RequestFn = Callable[[str, str, str, int, ScannerConfig, str], HttpResponse]

# HSTS max-age below this (seconds) is considered weak. 180 days.
_HSTS_RECOMMENDED_MAX_AGE = 15552000


def _default_request(
    scheme: str,
    host: str,
    pinned_ip: str,
    port: int,
    config: ScannerConfig,
    path: str = "/",
) -> HttpResponse:
    return http_request(scheme, host, pinned_ip, port, config=config, path=path)


def _parse_hsts_max_age(value: str) -> Optional[int]:
    for part in value.split(";"):
        name, _, raw = part.strip().partition("=")
        if name.strip().lower() == "max-age":
            try:
                return int(raw.strip().strip('"'))
            except ValueError:
                return None
    return None


def _inspect_hsts(headers: Dict[str, str], over_https: bool) -> List[Finding]:
    value = headers.get("strict-transport-security")
    if value is None:
        severity = SEVERITY_HIGH if over_https else SEVERITY_MEDIUM
        return [
            Finding(
                check_code=CheckCodes.HSTS_MISSING,
                title="Strict-Transport-Security (HSTS) header is missing",
                description=(
                    "The server does not send a Strict-Transport-Security header. "
                    "Without HSTS, browsers may access the site over plain HTTP and "
                    "users are more exposed to downgrade and man-in-the-middle attacks."
                ),
                severity=severity,
                recommendation=(
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                ),
                evidence="header missing",
            )
        ]

    max_age = _parse_hsts_max_age(value)
    if max_age is None:
        return [
            Finding(
                check_code=CheckCodes.HSTS_WEAK,
                title="HSTS max-age is missing or invalid",
                description=(
                    "The Strict-Transport-Security header is present but does not "
                    "contain a valid max-age directive."
                ),
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    "Set a valid max-age, for example: max-age=31536000; includeSubDomains"
                ),
                evidence=value,
            )
        ]
    if max_age < _HSTS_RECOMMENDED_MAX_AGE:
        return [
            Finding(
                check_code=CheckCodes.HSTS_WEAK,
                title="HSTS max-age is too short",
                description=(
                    f"The HSTS max-age is {max_age}s, below the recommended "
                    f"{_HSTS_RECOMMENDED_MAX_AGE}s (180 days)."
                ),
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    "Increase max-age to at least 31536000 (1 year), then consider "
                    "includeSubDomains and preload."
                ),
                evidence=value,
            )
        ]
    return []


def _inspect_csp(headers: Dict[str, str]) -> List[Finding]:
    value = headers.get("content-security-policy")
    if value is None:
        return [
            Finding(
                check_code=CheckCodes.CSP_MISSING,
                title="Content-Security-Policy (CSP) header is missing",
                description=(
                    "No Content-Security-Policy header was found. CSP mitigates "
                    "cross-site scripting and data injection by restricting the "
                    "sources from which content can be loaded."
                ),
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    "Define and deploy a Content-Security-Policy, starting with "
                    "default-src 'self' and tightening directives."
                ),
                evidence="header missing",
            )
        ]
    lowered = value.lower()
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        return [
            Finding(
                check_code=CheckCodes.CSP_WEAK,
                title="Content-Security-Policy allows unsafe inline/eval",
                description=(
                    "The CSP includes 'unsafe-inline' or 'unsafe-eval', which "
                    "significantly weakens its protection against script injection."
                ),
                severity=SEVERITY_LOW,
                recommendation=(
                    "Remove 'unsafe-inline'/'unsafe-eval' where possible by using "
                    "nonces or hashes and avoiding eval()."
                ),
                evidence=value,
            )
        ]
    return []


def _inspect_content_type_options(headers: Dict[str, str]) -> List[Finding]:
    value = headers.get("x-content-type-options")
    if value is None:
        return [
            Finding(
                check_code=CheckCodes.X_CONTENT_TYPE_OPTIONS_MISSING,
                title="X-Content-Type-Options header is missing",
                description=(
                    "The server does not send X-Content-Type-Options, so browsers "
                    "may MIME-sniff responses and interpret them differently than "
                    "declared."
                ),
                severity=SEVERITY_LOW,
                recommendation="Add: X-Content-Type-Options: nosniff",
                evidence="header missing",
            )
        ]
    if value.strip().lower() != "nosniff":
        return [
            Finding(
                check_code=CheckCodes.X_CONTENT_TYPE_OPTIONS_WEAK,
                title="X-Content-Type-Options is not set to nosniff",
                description=(
                    "The X-Content-Type-Options header is present but not set to "
                    "'nosniff'."
                ),
                severity=SEVERITY_LOW,
                recommendation="Set X-Content-Type-Options: nosniff",
                evidence=value,
            )
        ]
    return []


def _inspect_frame_options(headers: Dict[str, str]) -> List[Finding]:
    value = headers.get("x-frame-options")
    if value is None:
        return [
            Finding(
                check_code=CheckCodes.X_FRAME_OPTIONS_MISSING,
                title="X-Frame-Options header is missing",
                description=(
                    "The server does not send X-Frame-Options, so the page may be "
                    "embedded in frames (clickjacking risk)."
                ),
                severity=SEVERITY_LOW,
                recommendation=(
                    "Add: X-Frame-Options: DENY (or SAMEORIGIN), or use CSP "
                    "frame-ancestors."
                ),
                evidence="header missing",
            )
        ]
    if value.strip().upper() not in {"DENY", "SAMEORIGIN"}:
        return [
            Finding(
                check_code=CheckCodes.X_FRAME_OPTIONS_WEAK,
                title="X-Frame-Options has an invalid value",
                description=(
                    "The X-Frame-Options header is present but its value is not "
                    "DENY or SAMEORIGIN."
                ),
                severity=SEVERITY_LOW,
                recommendation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                evidence=value,
            )
        ]
    return []


def _inspect_referrer_policy(headers: Dict[str, str]) -> List[Finding]:
    value = headers.get("referrer-policy")
    if value is None:
        return [
            Finding(
                check_code=CheckCodes.REFERRER_POLICY_MISSING,
                title="Referrer-Policy header is missing",
                description=(
                    "No Referrer-Policy header was found, so the browser may send "
                    "full referrer URLs to third parties."
                ),
                severity=SEVERITY_LOW,
                recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
                evidence="header missing",
            )
        ]
    return []


def _inspect_permissions_policy(headers: Dict[str, str]) -> List[Finding]:
    value = headers.get("permissions-policy")
    if value is None:
        return [
            Finding(
                check_code=CheckCodes.PERMISSIONS_POLICY_MISSING,
                title="Permissions-Policy header is missing",
                description=(
                    "No Permissions-Policy header was found. Without it, the site "
                    "does not explicitly restrict powerful browser features."
                ),
                severity=SEVERITY_LOW,
                recommendation=(
                    "Add a Permissions-Policy header disabling features the site does "
                    "not need (for example camera=(), microphone=(), geolocation=())."
                ),
                evidence="header missing",
            )
        ]
    return []


def inspect_headers(
    target: ValidatedTarget,
    config: ScannerConfig = DEFAULT_CONFIG,
    requester: Optional[RequestFn] = None,
) -> List[Finding]:
    """Inspect HTTP security headers for a validated target."""
    request = requester or _default_request

    response = request("https", target.hostname, target.pinned_ip, 443, config, "/")
    over_https = True
    if not response.ok:
        response = request("http", target.hostname, target.pinned_ip, 80, config, "/")
        over_https = False

    if not response.ok:
        return [
            Finding(
                check_code=CheckCodes.HEADERS_UNAVAILABLE,
                title="Security headers could not be inspected",
                description=(
                    "Neither HTTPS nor HTTP returned a response, so security headers "
                    f"could not be evaluated: {response.error}"
                ),
                severity=SEVERITY_INFO,
                recommendation="Ensure the endpoint is reachable to inspect its headers.",
                evidence=f"error_type={response.error_type}; error={response.error}",
            )
        ]

    headers = response.headers
    findings: List[Finding] = []
    findings.extend(_inspect_hsts(headers, over_https))
    findings.extend(_inspect_csp(headers))
    findings.extend(_inspect_content_type_options(headers))
    findings.extend(_inspect_frame_options(headers))
    findings.extend(_inspect_referrer_policy(headers))
    findings.extend(_inspect_permissions_policy(headers))
    return findings