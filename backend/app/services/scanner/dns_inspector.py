"""DNS security record inspection (SPF, DMARC, CAA).

Responsibilities:
    * Check for an SPF TXT record and detect multiple/malformed SPF records.
    * Check for a DMARC TXT record at ``_dmarc.<domain>``.
    * Report CAA records when present.
    * Distinguish *missing* records (NXDOMAIN / no answer) from *query
      failures* (timeouts, SERVFAIL). A failed query is reported as an unknown
      result, never as a confirmed vulnerability.

This module performs only standard, non-aggressive DNS queries. It does not
enumerate subdomains or attempt zone transfers.
"""

from __future__ import annotations

from typing import Callable, List, Optional

import dns.exception
import dns.resolver

from app.services.scanner.config import (
    DEFAULT_CONFIG,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    CheckCodes,
    ScannerConfig,
)
from app.services.scanner.findings import Finding

QueryFn = Callable[[str, str, ScannerConfig], List[str]]


def _join_txt(rdata) -> str:
    parts = []
    for chunk in getattr(rdata, "strings", ()):  # pragma: no cover - trivial
        parts.append(chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else chunk)
    return "".join(parts)


def _default_query(name: str, rdtype: str, config: ScannerConfig) -> List[str]:
    """Resolve ``name``/``rdtype`` using dnspython and return text values."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = config.dns_timeout
    resolver.lifetime = config.dns_timeout
    answer = resolver.resolve(name, rdtype)
    results: List[str] = []
    for rdata in answer:
        if rdtype == "TXT":
            results.append(_join_txt(rdata))
        else:
            results.append(rdata.to_text())
    return results


def _dns_failure_finding(exc: Exception) -> Finding:
    return Finding(
        check_code=CheckCodes.DNS_TIMEOUT,
        title="DNS query could not be completed",
        description=(
            "A DNS query failed or timed out. The result is unknown and must not be "
            "interpreted as a confirmed missing record."
        ),
        severity=SEVERITY_INFO,
        recommendation="Retry the scan later; verify the domain's DNS configuration.",
        evidence=f"error={type(exc).__name__}: {exc}",
    )


def _spf_malformed(record: str) -> Optional[str]:
    tokens = record.split()
    if not tokens or tokens[0].lower() != "v=spf1":
        return "Record does not start with 'v=spf1'."
    if len(tokens) < 2:
        return "SPF record has no mechanisms."
    all_tokens = [token for token in tokens[1:] if token.lower().endswith("all")]
    if len(all_tokens) != 1:
        return (
            "SPF record must contain exactly one 'all' mechanism "
            f"(found {len(all_tokens)})."
        )
    return None


def _dmarc_valid(record: str) -> bool:
    lowered = record.lower()
    if not lowered.startswith("v=dmarc1"):
        return False
    if "p=" not in lowered:
        return False
    return True


def _inspect_spf(domain: str, config: ScannerConfig, query: QueryFn) -> List[Finding]:
    try:
        records = query(domain, "TXT", config)
    except dns.resolver.NXDOMAIN:
        return [
            Finding(
                check_code=CheckCodes.SPF_MISSING,
                title="SPF record is missing",
                description=(
                    "The domain does not exist (NXDOMAIN), so no SPF record can be "
                    "published."
                ),
                severity=SEVERITY_MEDIUM,
                recommendation="Verify that the domain exists and is correctly configured.",
                evidence="NXDOMAIN",
            )
        ]
    except dns.resolver.NoAnswer:
        return [
            Finding(
                check_code=CheckCodes.SPF_MISSING,
                title="SPF record is missing",
                description="No TXT records exist for the domain, so no SPF record is published.",
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    "Publish an SPF TXT record, for example: v=spf1 include:_spf.example.com -all"
                ),
                evidence="no TXT answer",
            )
        ]
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        return [_dns_failure_finding(exc)]
    except Exception as exc:  # pragma: no cover - defensive
        return [_dns_failure_finding(exc)]

    spf_records = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf_records:
        return [
            Finding(
                check_code=CheckCodes.SPF_MISSING,
                title="SPF record is missing",
                description=(
                    "No TXT record beginning with 'v=spf1' was found for the domain."
                ),
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    "Publish an SPF TXT record authorising your legitimate sending "
                    "sources and ending with an 'all' mechanism (e.g. -all)."
                ),
                evidence="no v=spf1 TXT record",
            )
        ]

    if len(spf_records) > 1:
        return [
            Finding(
                check_code=CheckCodes.SPF_MULTIPLE,
                title="Multiple SPF records found",
                description=(
                    f"The domain publishes {len(spf_records)} SPF records. Multiple SPF "
                    "records are invalid and cause SPF evaluation to fail with permerror."
                ),
                severity=SEVERITY_MEDIUM,
                recommendation="Consolidate all sending sources into a single SPF record.",
                evidence=str(spf_records),
            )
        ]

    reason = _spf_malformed(spf_records[0])
    if reason is not None:
        return [
            Finding(
                check_code=CheckCodes.SPF_MALFORMED,
                title="SPF record is malformed",
                description=f"The SPF record appears malformed: {reason}",
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    "Correct the SPF record so it is a single valid policy with exactly "
                    "one 'all' mechanism."
                ),
                evidence=spf_records[0],
            )
        ]

    return []


def _inspect_dmarc(domain: str, config: ScannerConfig, query: QueryFn) -> List[Finding]:
    name = f"_dmarc.{domain}"
    try:
        records = query(name, "TXT", config)
    except dns.resolver.NXDOMAIN:
        return [
            Finding(
                check_code=CheckCodes.DMARC_MISSING,
                title="DMARC record is missing",
                description=(
                    f"No DMARC record exists at {name} (NXDOMAIN)."
                ),
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    "Publish a DMARC TXT record at "
                    f"{name}, for example: v=DMARC1; p=none; rua=mailto:dmarc@{domain}"
                ),
                evidence="NXDOMAIN",
            )
        ]
    except dns.resolver.NoAnswer:
        return [
            Finding(
                check_code=CheckCodes.DMARC_MISSING,
                title="DMARC record is missing",
                description=f"No TXT records exist at {name}.",
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    f"Publish a DMARC TXT record at {name}, for example: "
                    f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}"
                ),
                evidence="no TXT answer",
            )
        ]
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        return [_dns_failure_finding(exc)]
    except Exception as exc:  # pragma: no cover - defensive
        return [_dns_failure_finding(exc)]

    dmarc_records = [r for r in records if "v=dmarc1" in r.lower()]
    if not dmarc_records:
        return [
            Finding(
                check_code=CheckCodes.DMARC_MISSING,
                title="DMARC record is missing",
                description=(
                    f"No TXT record beginning with 'v=DMARC1' was found at {name}."
                ),
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    f"Publish a DMARC record at {name}, for example: "
                    f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}"
                ),
                evidence="no v=DMARC1 TXT record",
            )
        ]

    if len(dmarc_records) > 1 or not _dmarc_valid(dmarc_records[0]):
        return [
            Finding(
                check_code=CheckCodes.DMARC_MALFORMED,
                title="DMARC record is malformed",
                description=(
                    "The DMARC record is malformed or duplicated. A DMARC record must "
                    "start with 'v=DMARC1' and include a policy ('p=') tag."
                ),
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    "Publish exactly one valid DMARC record with a 'p=' policy tag."
                ),
                evidence=str(dmarc_records),
            )
        ]

    return []


def _inspect_caa(domain: str, config: ScannerConfig, query: QueryFn) -> List[Finding]:
    try:
        records = query(domain, "CAA", config)
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return [
            Finding(
                check_code=CheckCodes.CAA_ABSENT,
                title="No CAA records found",
                description=(
                    "The domain publishes no Certification Authority Authorization (CAA) "
                    "records, so any CA may issue certificates for it."
                ),
                severity=SEVERITY_INFO,
                recommendation=(
                    "Consider adding CAA records to restrict which certificate "
                    "authorities may issue certificates for the domain."
                ),
                evidence="no CAA answer",
            )
        ]
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        return [_dns_failure_finding(exc)]
    except Exception as exc:  # pragma: no cover - defensive
        return [_dns_failure_finding(exc)]

    if records:
        return [
            Finding(
                check_code=CheckCodes.CAA_RECORD,
                title="CAA records are present",
                description=(
                    "The domain publishes CAA records restricting certificate issuance."
                ),
                severity=SEVERITY_INFO,
                recommendation="No action required.",
                evidence=str(records),
            )
        ]

    return [
        Finding(
            check_code=CheckCodes.CAA_ABSENT,
            title="No CAA records found",
            description=(
                "The domain publishes no CAA records, so any CA may issue certificates."
            ),
            severity=SEVERITY_INFO,
            recommendation="Consider adding CAA records to restrict certificate issuance.",
            evidence="empty CAA answer",
        )
    ]


def inspect_dns(
    domain: str,
    config: ScannerConfig = DEFAULT_CONFIG,
    query: Optional[QueryFn] = None,
) -> List[Finding]:
    """Inspect SPF, DMARC and CAA records for ``domain``."""
    query_fn = query or _default_query
    findings: List[Finding] = []
    findings.extend(_inspect_spf(domain, config, query_fn))
    findings.extend(_inspect_dmarc(domain, config, query_fn))
    findings.extend(_inspect_caa(domain, config, query_fn))
    return findings