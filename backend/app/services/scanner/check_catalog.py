"""Catalogue of scanner checks and outcome derivation.

The scanner's inspectors return *findings* (things worth reporting) rather than
an explicit pass/fail record for every check. That is sufficient for display,
but the risk engine needs to know which checks were actually evaluated so that
it can:

* distinguish a **security finding** (a failed check) from a **technical
  scanning failure** (an unknown result);
* calculate scan coverage; and
* avoid treating a check that never ran as if it had passed.

This module defines the expected check groups for each scanner module and
derives an explicit outcome (``passed`` / ``failed`` / ``unknown``) for every
group from the findings a module produced. The scan manager persists those
outcomes in ``check_results``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from app.services.scanner.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    CheckCodes,
)
from app.services.scanner.findings import Finding

# --- Outcome constants ------------------------------------------------------
OUTCOME_PASSED = "passed"
OUTCOME_FAILED = "failed"
OUTCOME_UNKNOWN = "unknown"
OUTCOME_NOT_APPLICABLE = "not_applicable"

VALID_OUTCOMES = (
    OUTCOME_PASSED,
    OUTCOME_FAILED,
    OUTCOME_UNKNOWN,
    OUTCOME_NOT_APPLICABLE,
)

# Higher rank == more severe. Unknown severities rank below informational.
SEVERITY_RANK: Dict[str, int] = {
    SEVERITY_INFO: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}


def severity_rank(severity: Optional[str]) -> int:
    """Return a sortable rank for ``severity`` (unknown values rank lowest)."""
    return SEVERITY_RANK.get((severity or "").strip().lower(), -1)


@dataclass(frozen=True)
class CheckGroup:
    """A logical check that should produce exactly one conclusive outcome.

    A group may map to several check codes because some checks are mutually
    exclusive (for example a certificate can be valid, expiring or expired, but
    only one of those outcomes applies to a given scan).
    """

    check_id: str
    module: str
    description: str
    codes: Tuple[str, ...]
    blocking: bool = False


@dataclass(frozen=True)
class ModuleSpec:
    """The checks expected from one scanner module."""

    name: str
    label: str
    groups: Tuple[CheckGroup, ...]
    # Finding codes that indicate a technical failure rather than a security
    # finding. If any of these appear, every group in the module is unknown.
    unknown_codes: Tuple[str, ...] = ()


@dataclass
class CheckOutcome:
    """Derived outcome for a single check group."""

    check_id: str
    module: str
    outcome: str
    severity: Optional[str] = None
    check_code: Optional[str] = None
    detail: Optional[str] = None


# --- Module catalogues ------------------------------------------------------
TLS_MODULE = "tls"
HTTPS_MODULE = "https"
HEADERS_MODULE = "headers"
DNS_MODULE = "dns"

MODULE_SPECS: Dict[str, ModuleSpec] = {
    TLS_MODULE: ModuleSpec(
        name=TLS_MODULE,
        label="TLS",
        groups=(
            CheckGroup(
                check_id="TLS_HANDSHAKE",
                module=TLS_MODULE,
                description="TLS handshake and certificate verification",
                codes=(CheckCodes.TLS_CONNECTION,),
                blocking=True,
            ),
            CheckGroup(
                check_id="TLS_CERTIFICATE",
                module=TLS_MODULE,
                description="TLS certificate validity and hostname match",
                codes=(
                    CheckCodes.TLS_CERT_VALID,
                    CheckCodes.TLS_CERT_EXPIRED,
                    CheckCodes.TLS_CERT_EXPIRING,
                    CheckCodes.TLS_CERT_MISMATCH,
                    CheckCodes.TLS_CERT_INVALID,
                ),
            ),
            CheckGroup(
                check_id="TLS_ISSUER",
                module=TLS_MODULE,
                description="TLS certificate issuer",
                codes=(CheckCodes.TLS_CERT_ISSUER,),
            ),
        ),
    ),
    HTTPS_MODULE: ModuleSpec(
        name=HTTPS_MODULE,
        label="HTTPS",
        groups=(
            CheckGroup(
                check_id="HTTPS_REACHABILITY",
                module=HTTPS_MODULE,
                description="HTTPS reachability",
                codes=(CheckCodes.HTTPS_ACCESSIBLE, CheckCodes.HTTPS_NOT_ACCESSIBLE),
            ),
            CheckGroup(
                check_id="HTTP_REDIRECT",
                module=HTTPS_MODULE,
                description="HTTP to HTTPS redirect behaviour",
                codes=(
                    CheckCodes.HTTP_TO_HTTPS_REDIRECT,
                    CheckCodes.HTTP_NO_REDIRECT,
                    CheckCodes.REDIRECT_INVALID,
                    CheckCodes.HTTP_INSECURE_ACCESSIBLE,
                    CheckCodes.HTTP_UNREACHABLE,
                ),
            ),
        ),
    ),
    HEADERS_MODULE: ModuleSpec(
        name=HEADERS_MODULE,
        label="Headers",
        groups=(
            CheckGroup(
                check_id="HSTS",
                module=HEADERS_MODULE,
                description="Strict-Transport-Security header",
                codes=(CheckCodes.HSTS_MISSING, CheckCodes.HSTS_WEAK),
            ),
            CheckGroup(
                check_id="CSP",
                module=HEADERS_MODULE,
                description="Content-Security-Policy header",
                codes=(CheckCodes.CSP_MISSING, CheckCodes.CSP_WEAK),
            ),
            CheckGroup(
                check_id="X_CONTENT_TYPE_OPTIONS",
                module=HEADERS_MODULE,
                description="X-Content-Type-Options header",
                codes=(
                    CheckCodes.X_CONTENT_TYPE_OPTIONS_MISSING,
                    CheckCodes.X_CONTENT_TYPE_OPTIONS_WEAK,
                ),
            ),
            CheckGroup(
                check_id="X_FRAME_OPTIONS",
                module=HEADERS_MODULE,
                description="X-Frame-Options header",
                codes=(
                    CheckCodes.X_FRAME_OPTIONS_MISSING,
                    CheckCodes.X_FRAME_OPTIONS_WEAK,
                ),
            ),
            CheckGroup(
                check_id="REFERRER_POLICY",
                module=HEADERS_MODULE,
                description="Referrer-Policy header",
                codes=(CheckCodes.REFERRER_POLICY_MISSING,),
            ),
            CheckGroup(
                check_id="PERMISSIONS_POLICY",
                module=HEADERS_MODULE,
                description="Permissions-Policy header",
                codes=(CheckCodes.PERMISSIONS_POLICY_MISSING,),
            ),
        ),
        unknown_codes=(CheckCodes.HEADERS_UNAVAILABLE,),
    ),
    DNS_MODULE: ModuleSpec(
        name=DNS_MODULE,
        label="DNS",
        groups=(
            CheckGroup(
                check_id="SPF",
                module=DNS_MODULE,
                description="SPF TXT record",
                codes=(
                    CheckCodes.SPF_MISSING,
                    CheckCodes.SPF_MULTIPLE,
                    CheckCodes.SPF_MALFORMED,
                ),
            ),
            CheckGroup(
                check_id="DMARC",
                module=DNS_MODULE,
                description="DMARC TXT record",
                codes=(CheckCodes.DMARC_MISSING, CheckCodes.DMARC_MALFORMED),
            ),
            CheckGroup(
                check_id="CAA",
                module=DNS_MODULE,
                description="CAA records",
                codes=(CheckCodes.CAA_RECORD, CheckCodes.CAA_ABSENT),
            ),
        ),
        unknown_codes=(CheckCodes.DNS_TIMEOUT,),
    ),
}

MODULE_NAMES: Tuple[str, ...] = tuple(MODULE_SPECS.keys())

# Finding codes that represent a technical scanning failure rather than a
# security finding. They are excluded from risk scoring.
UNKNOWN_CHECK_CODES = frozenset(
    code for spec in MODULE_SPECS.values() for code in spec.unknown_codes
)

ALL_GROUPS: Tuple[CheckGroup, ...] = tuple(
    group for spec in MODULE_SPECS.values() for group in spec.groups
)

# Map each concrete finding code back to its module. Used when deriving
# outcomes for legacy scans that predate check-result persistence.
_CODE_TO_MODULE: Dict[str, str] = {
    code: spec.name for spec in MODULE_SPECS.values() for group in spec.groups for code in group.codes
}


def module_for_code(check_code: str) -> Optional[str]:
    """Return the scanner module that owns ``check_code``, if known."""
    return _CODE_TO_MODULE.get(check_code)


def _unknown_outcomes(spec: ModuleSpec, detail: str) -> List[CheckOutcome]:
    return [
        CheckOutcome(
            check_id=group.check_id,
            module=spec.name,
            outcome=OUTCOME_UNKNOWN,
            detail=detail,
        )
        for group in spec.groups
    ]


def derive_outcomes(
    module_name: str,
    findings: Sequence[Finding],
    error: Optional[str] = None,
) -> List[CheckOutcome]:
    """Derive explicit outcomes for every check group in ``module_name``.

    Rules:
        * If the module raised an error, every group is ``unknown``.
        * If the module reported a known technical-failure code (for example a
          DNS timeout), groups with no concrete result are ``unknown``. Groups
          that did produce a concrete finding are still classified normally.
          This is deliberately conservative: a query failure must never be
          reported as a secure result, but a confirmed finding is still
          reported.
        * If a blocking check failed (for example the TLS handshake), the
          remaining groups in that module are ``unknown`` because they could
          not be evaluated.
        * Otherwise a group is ``failed`` when a matching finding has a
          non-informational severity, ``passed`` when the matching finding is
          informational, and ``passed`` when the module completed without
          emitting a finding for that group (the inspector would have reported
          a problem if one existed).
    """
    spec = MODULE_SPECS.get(module_name)
    if spec is None:
        return []

    if error:
        return _unknown_outcomes(spec, f"Module error: {error}")

    has_unknown_result = any(
        finding.check_code in spec.unknown_codes for finding in findings
    )
    if has_unknown_result and not any(
        finding.check_code not in spec.unknown_codes for finding in findings
    ):
        # No concrete check produced a result, so the whole module is unknown.
        return _unknown_outcomes(spec, "Module reported a technical failure")

    blocking_failure = any(
        finding.severity != SEVERITY_INFO
        and finding.check_code in group.codes
        for group in spec.groups
        if group.blocking
        for finding in findings
    )

    outcomes: List[CheckOutcome] = []
    for group in spec.groups:
        matches = [finding for finding in findings if finding.check_code in group.codes]

        if blocking_failure and not group.blocking:
            outcomes.append(
                CheckOutcome(
                    check_id=group.check_id,
                    module=spec.name,
                    outcome=OUTCOME_UNKNOWN,
                    detail="Skipped because a blocking check in the same module failed",
                )
            )
            continue

        if not matches:
            if has_unknown_result:
                outcomes.append(
                    CheckOutcome(
                        check_id=group.check_id,
                        module=spec.name,
                        outcome=OUTCOME_UNKNOWN,
                        detail="Module reported a technical failure for this check",
                    )
                )
            else:
                # The module ran to completion and reported no issue for this
                # group, which means the check passed.
                outcomes.append(
                    CheckOutcome(
                        check_id=group.check_id,
                        module=spec.name,
                        outcome=OUTCOME_PASSED,
                        detail="No issue reported",
                    )
                )
            continue

        primary = max(matches, key=lambda finding: severity_rank(finding.severity))
        if primary.severity == SEVERITY_INFO:
            outcomes.append(
                CheckOutcome(
                    check_id=group.check_id,
                    module=spec.name,
                    outcome=OUTCOME_PASSED,
                    severity=primary.severity,
                    check_code=primary.check_code,
                    detail=primary.title,
                )
            )
        else:
            outcomes.append(
                CheckOutcome(
                    check_id=group.check_id,
                    module=spec.name,
                    outcome=OUTCOME_FAILED,
                    severity=primary.severity,
                    check_code=primary.check_code,
                    detail=primary.title,
                )
            )

    return outcomes


def expected_check_ids() -> List[str]:
    """Return all check IDs in catalogue order."""
    return [group.check_id for group in ALL_GROUPS]