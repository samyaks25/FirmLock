"""Security report generation service.

Builds structured scan reports and historical scan summaries from stored scan
findings and risk assessments. Reports never invent findings or scores: missing
or unavailable data is reported explicitly.
"""

from __future__ import annotations

import csv
import io
from typing import Any, List, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.models import Asset, Business, Finding, RiskAssessment, Scan
from app.schemas.report import (
    AssetReportHistoryEntry,
    AssetReportsResponse,
    ReportFinding,
    ReportRiskAssessment,
    ScanReportResponse,
)
from app.services import risk_service
from app.services.scanner.check_catalog import severity_rank

_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class ScanNotFoundError(LookupError):
    pass


class AssetNotFoundError(LookupError):
    pass


def _sanitize_csv_value(value: Any) -> Any:
    """Prevent spreadsheet formula injection for untrusted CSV cell values."""
    if not isinstance(value, str):
        return value
    if value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _severity_counts(findings: Sequence[Finding]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for finding in findings:
        sev = (finding.severity or "").strip().lower()
        if sev in counts:
            counts[sev] += 1
        counts["total"] += 1
    return counts


def _ordered_findings(findings: Sequence[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (-severity_rank(f.severity), f.check_code, f.id),
    )


def _assessment_for_scan(db: Session, scan: Scan) -> Optional[RiskAssessment]:
    if scan.status != "completed":
        return None
    try:
        return risk_service.get_or_create_assessment(db, scan)
    except Exception:
        return None


def _report_risk(db: Session, scan: Scan) -> Optional[ReportRiskAssessment]:
    assessment = _assessment_for_scan(db, scan)
    if assessment is None:
        return None
    counts = assessment.severity_counts or {}
    return ReportRiskAssessment(
        security_score=assessment.security_score,
        score_available=assessment.score_available,
        unavailable_reason=assessment.unavailable_reason,
        risk_level=assessment.risk_level,
        grade=assessment.grade,
        coverage_percent=assessment.coverage_percent,
        checks_total=assessment.checks_total,
        checks_evaluated=assessment.checks_evaluated,
        checks_unknown=assessment.checks_unknown,
        checks_not_applicable=assessment.checks_not_applicable,
        coverage_sufficient=assessment.coverage_sufficient,
        coverage_unknown_checks=list(assessment.coverage_unknown_checks or []),
        findings_by_severity=counts,
        findings_total=assessment.findings_total,
        highest_priority_issues=list(assessment.highest_priority or []),
        recommended_actions=list(assessment.recommendations or []),
        score_source=assessment.score_source,
    )


def get_scan(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ScanNotFoundError("Scan not found")
    return scan


def build_scan_report(db: Session, scan_id: int) -> ScanReportResponse:
    scan = get_scan(db, scan_id)
    asset = db.get(Asset, scan.asset_id)
    if asset is None:
        raise AssetNotFoundError("Asset not found")
    business = db.get(Business, asset.business_id)
    if business is None:
        raise LookupError("Business not found")

    findings = _ordered_findings(list(scan.findings))
    counts = _severity_counts(findings)
    risk = _report_risk(db, scan)

    recommendations: List[str] = []
    seen = set()
    for finding in findings:
        if severity_rank(finding.severity) <= 0:
            continue
        rec = (finding.recommendation or "").strip()
        if rec and rec not in seen:
            seen.add(rec)
            recommendations.append(rec)

    # Prefer assessment recommendations when available.
    if risk and risk.recommended_actions:
        recommendations = list(risk.recommended_actions)

    return ScanReportResponse(
        scan_id=scan.id,
        scan_status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        business_id=business.id,
        business_name=business.name,
        asset_id=asset.id,
        asset_domain=asset.domain,
        security_score=(risk.security_score if risk else scan.security_score),
        score_available=(risk.score_available if risk else False),
        unavailable_reason=(
            risk.unavailable_reason if risk else (
                f"Scan status is '{scan.status}'. A risk assessment is only available for completed scans."
                if scan.status != "completed" else "No risk assessment is available for this scan."
            )
        ),
        risk_assessment=risk,
        scan_coverage=(
            {
                "percentage": risk.coverage_percent,
                "evaluated": risk.checks_evaluated,
                "total": risk.checks_total,
                "unknown": risk.checks_unknown,
                "not_applicable": risk.checks_not_applicable,
                "sufficient": risk.coverage_sufficient,
                "unknown_checks": risk.coverage_unknown_checks,
            }
            if risk
            else None
        ),
        findings_total=len(findings),
        findings_by_severity=counts,
        findings=[ReportFinding.model_validate(finding) for finding in findings],
        recommendations=recommendations,
    )


def build_scan_csv(db: Session, scan_id: int) -> str:
    report = build_scan_report(db, scan_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "scan_id",
            "scan_status",
            "business_id",
            "business_name",
            "asset_id",
            "asset_domain",
            "security_score",
            "score_available",
            "unavailable_reason",
            "risk_level",
            "grade",
            "coverage_percent",
            "finding_id",
            "check_code",
            "severity",
            "title",
            "description",
            "evidence",
            "recommendation",
        ]
    )

    risk = report.risk_assessment
    base = [
        report.scan_id,
        report.scan_status,
        report.business_id,
        report.business_name,
        report.asset_id,
        report.asset_domain,
        report.security_score if report.security_score is not None else "",
        report.score_available,
        report.unavailable_reason or "",
        (risk.risk_level if risk and risk.risk_level else ""),
        (risk.grade if risk and risk.grade else ""),
        (risk.coverage_percent if risk else ""),
    ]

    if not report.findings:
        writer.writerow([_sanitize_csv_value(value) for value in base + ["", "", "", "", "", "", ""]])
        return output.getvalue()

    for finding in report.findings:
        row = base + [
            finding.id,
            finding.check_code,
            finding.severity,
            finding.title,
            finding.description,
            finding.evidence or "",
            finding.recommendation,
        ]
        writer.writerow([_sanitize_csv_value(value) for value in row])
    return output.getvalue()


def list_asset_reports(db: Session, asset_id: int) -> AssetReportsResponse:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise AssetNotFoundError("Asset not found")
    business = db.get(Business, asset.business_id)
    if business is None:
        raise LookupError("Business not found")

    scans = list(
        db.scalars(
            select(Scan).where(Scan.asset_id == asset_id).order_by(Scan.id.desc())
        ).all()
    )

    summaries: List[AssetReportHistoryEntry] = []
    for scan in scans:
        findings = list(scan.findings)
        assessment = _assessment_for_scan(db, scan)
        summaries.append(
            AssetReportHistoryEntry(
                scan_id=scan.id,
                scan_status=scan.status,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                created_at=scan.created_at,
                security_score=(
                    assessment.security_score if assessment else scan.security_score
                ),
                score_available=(assessment.score_available if assessment else False),
                unavailable_reason=(
                    assessment.unavailable_reason
                    if assessment
                    else (
                        f"Scan status is '{scan.status}'. A risk assessment is only available for completed scans."
                        if scan.status != "completed"
                        else "No risk assessment is available for this scan."
                    )
                ),
                risk_level=(assessment.risk_level if assessment else None),
                grade=(assessment.grade if assessment else None),
                coverage_percent=(assessment.coverage_percent if assessment else None),
                findings_total=len(findings),
                findings_by_severity=_severity_counts(findings),
            )
        )

    return AssetReportsResponse(
        asset_id=asset.id,
        asset_domain=asset.domain,
        business_id=business.id,
        business_name=business.name,
        scans=summaries,
    )
