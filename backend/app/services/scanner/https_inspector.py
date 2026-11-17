"""HTTPS behaviour inspection.

Responsibilities:
    * Determine whether HTTPS is reachable.
    * Determine whether plain HTTP redirects to HTTPS.
    * Validate redirect destinations independently (never follow them).
    * Determine whether an insecure HTTP endpoint remains accessible.

Redirects are never followed automatically. The ``Location`` header is parsed
and validated with the same SSRF rules as the original target before any
conclusion is drawn.
"""

from __future__ import annotations

from typing import Callable, List, Optional

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
from app.services.scanner.target_validator import ValidatedTarget, validate_redirect_target

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

RequestFn = Callable[[str, str, str, int, ScannerConfig, str], HttpResponse]


def _default_request(
    scheme: str,
    host: str,
    pinned_ip: str,
    port: int,
    config: ScannerConfig,
    path: str = "/",
) -> HttpResponse:
    return http_request(scheme, host, pinned_ip, port, config=config, path=path)


def _base_url(host: str, port: int) -> str:
    return f"http://{host}:{port}/"


def inspect_https(
    target: ValidatedTarget,
    config: ScannerConfig = DEFAULT_CONFIG,
    requester: Optional[RequestFn] = None,
) -> List[Finding]:
    """Inspect HTTPS reachability and HTTP-to-HTTPS redirect behaviour."""
    request = requester or _default_request
    findings: List[Finding] = []

    # 1. Is HTTPS reachable?
    https_response = request("https", target.hostname, target.pinned_ip, 443, config, "/")
    if https_response.ok:
        if https_response.status < 500:
            findings.append(
                Finding(
                    check_code=CheckCodes.HTTPS_ACCESSIBLE,
                    title="HTTPS is accessible",
                    description=(
                        f"The HTTPS endpoint responded with status {https_response.status}."
                    ),
                    severity=SEVERITY_INFO,
                    recommendation="No action required.",
                    evidence=f"status={https_response.status}",
                )
            )
        else:
            findings.append(
                Finding(
                    check_code=CheckCodes.HTTPS_NOT_ACCESSIBLE,
                    title="HTTPS endpoint returned a server error",
                    description=(
                        "The HTTPS endpoint responded with a server-side error "
                        f"(status {https_response.status})."
                    ),
                    severity=SEVERITY_HIGH,
                    recommendation="Investigate the HTTPS service and server logs.",
                    evidence=f"status={https_response.status}",
                )
            )
    else:
        findings.append(
            Finding(
                check_code=CheckCodes.HTTPS_NOT_ACCESSIBLE,
                title="HTTPS is not accessible",
                description=(
                    f"Could not establish an HTTPS connection to {target.hostname}: "
                    f"{https_response.error}"
                ),
                severity=SEVERITY_HIGH,
                recommendation=(
                    "Ensure HTTPS is enabled on port 443 with a valid, trusted certificate."
                ),
                evidence=f"error_type={https_response.error_type}; error={https_response.error}",
            )
        )

    # 2. Does plain HTTP redirect to HTTPS?
    http_response = request("http", target.hostname, target.pinned_ip, 80, config, "/")
    if not http_response.ok:
        findings.append(
            Finding(
                check_code=CheckCodes.HTTP_UNREACHABLE,
                title="HTTP endpoint is not reachable",
                description=(
                    f"Could not reach the HTTP endpoint on port 80: {http_response.error}. "
                    "This may be intentional if HTTP is disabled."
                ),
                severity=SEVERITY_INFO,
                recommendation=(
                    "If HTTP is intentionally disabled, no action is required. "
                    "Otherwise verify the HTTP service."
                ),
                evidence=f"error_type={http_response.error_type}; error={http_response.error}",
            )
        )
        return findings

    location = http_response.headers.get("location")

    if http_response.status in _REDIRECT_STATUSES:
        if not location:
            findings.append(
                Finding(
                    check_code=CheckCodes.REDIRECT_INVALID,
                    title="HTTP redirect without a Location header",
                    description=(
                        f"HTTP returned status {http_response.status} but no Location header."
                    ),
                    severity=SEVERITY_MEDIUM,
                    recommendation="Ensure redirects include a valid absolute Location header.",
                    evidence=f"status={http_response.status}",
                )
            )
            return findings

        check = validate_redirect_target(
            location, _base_url(target.hostname, 80), config
        )

        if not check.valid:
            findings.append(
                Finding(
                    check_code=CheckCodes.REDIRECT_INVALID,
                    title="HTTP redirect destination failed validation",
                    description=(
                        "The HTTP redirect points to a destination that failed safety "
                        f"validation: {check.reason}"
                    ),
                    severity=SEVERITY_HIGH,
                    recommendation=(
                        "Point the redirect at a public HTTPS destination and ensure the "
                        "target cannot be redirected to internal networks."
                    ),
                    evidence=f"location={location}; reason={check.reason}",
                )
            )
        elif check.scheme == "https" and check.port == 443:
            findings.append(
                Finding(
                    check_code=CheckCodes.HTTP_TO_HTTPS_REDIRECT,
                    title="HTTP redirects to HTTPS",
                    description=(
                        f"HTTP redirects to a validated HTTPS destination ({check.host})."
                    ),
                    severity=SEVERITY_INFO,
                    recommendation="No action required.",
                    evidence=(
                        f"status={http_response.status}; location={location}; "
                        f"resolved={check.addresses}"
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    check_code=CheckCodes.REDIRECT_INVALID,
                    title="HTTP redirect does not upgrade to HTTPS",
                    description=(
                        f"HTTP redirects to {check.scheme}://{check.host}:{check.port}, "
                        "which does not upgrade the connection to HTTPS."
                    ),
                    severity=SEVERITY_MEDIUM,
                    recommendation="Redirect all HTTP traffic to HTTPS (scheme https, port 443).",
                    evidence=f"status={http_response.status}; location={location}",
                )
            )
        return findings

    # No redirect.
    findings.append(
        Finding(
            check_code=CheckCodes.HTTP_NO_REDIRECT,
            title="HTTP does not redirect to HTTPS",
            description=(
                "The HTTP endpoint does not redirect to HTTPS, so visitors using "
                "http:// are not upgraded to a secure connection."
            ),
            severity=SEVERITY_MEDIUM,
            recommendation="Configure a permanent (301) redirect from HTTP to HTTPS.",
            evidence=f"status={http_response.status}",
        )
    )

    if 200 <= http_response.status < 300:
        findings.append(
            Finding(
                check_code=CheckCodes.HTTP_INSECURE_ACCESSIBLE,
                title="Insecure HTTP endpoint serves content",
                description=(
                    "The plain HTTP endpoint returns content, allowing visitors to "
                    "communicate over an unencrypted connection."
                ),
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    "Redirect HTTP to HTTPS and consider refusing to serve content over HTTP."
                ),
                evidence=f"status={http_response.status}",
            )
        )

    return findings