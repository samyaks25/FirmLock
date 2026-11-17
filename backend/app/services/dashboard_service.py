"""Business dashboard aggregation service.

All statistics are derived from actual stored database records. No values are
invented; missing information is represented explicitly (for example ``None``
for latest scan fields when a business has no scans).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.models import Alert, Asset, Business, Finding, Scan
from app.schemas.dashboard import (
    CriticalFindingSummary,
    DashboardAlertCounts,
    DashboardResponse,
    DashboardScanSummary,
    DashboardSecurityOverview,
    RecentActivityItem,
)
from app.services import alert_service, risk_service
from app.services.scanner.check_catalog import severity_rank


class BusinessNotFoundError(LookupError):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_business(db: Session, business_id: int) -> Business:
    business = db.get(Business, business_id)
    if business is None:
        raise BusinessNotFoundError("Business not found")
    return business


def _latest_scan_for_business(db: Session, business_id: int) -> Optional[Scan]:
    return db.scalars(
        select(Scan)
        .join(Asset, Scan.asset_id == Asset.id)
        .where(Asset.business_id == business_id)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    ).first()


def _latest_completed_scans_per_asset(db: Session, business_id: int) -> List[Scan]:
    """Return the latest completed scan for each business asset (if any)."""
    assets = list(
        db.scalars(select(Asset).where(Asset.business_id == business_id)).all()
    )
    latest: List[Scan] = []
    for asset in assets:
        scan = db.scalars(
            select(Scan)
            .where(Scan.asset_id == asset.id, Scan.status == "completed")
            .order_by(Scan.completed_at.desc(), Scan.id.desc())
            .limit(1)
        ).first()
        if scan is not None:
            latest.append(scan)
    return latest


def build_dashboard(db: Session, business_id: int) -> DashboardResponse:
    business = get_business(db, business_id)

    assets = list(
        db.scalars(select(Asset).where(Asset.business_id == business_id)).all()
    )
    total_assets = len(assets)
    active_assets = sum(1 for a in assets if a.status == "active")
    paused_assets = sum(1 for a in assets if a.status == "paused")

    latest_scan = _latest_scan_for_business(db, business_id)
    latest_scan_summary: Optional[DashboardScanSummary] = None
    if latest_scan is not None:
        scan_asset = db.get(Asset, latest_scan.asset_id)
        assessment = None
        if latest_scan.status == "completed":
            try:
                assessment = risk_service.get_or_create_assessment(db, latest_scan)
            except Exception:
                assessment = None
        latest_scan_summary = DashboardScanSummary(
            scan_id=latest_scan.id,
            asset_id=latest_scan.asset_id,
            asset_domain=(scan_asset.domain if scan_asset else "unknown"),
            status=latest_scan.status,
            security_score=(
                assessment.security_score
                if assessment
                else latest_scan.security_score
            ),
            score_available=(assessment.score_available if assessment else False),
            unavailable_reason=(
                assessment.unavailable_reason
                if assessment
                else (
                    f"Scan status is '{latest_scan.status}'. A risk assessment is only available for completed scans."
                    if latest_scan.status != "completed"
                    else None
                )
            ),
            risk_level=(assessment.risk_level if assessment else None),
            grade=(assessment.grade if assessment else None),
            started_at=latest_scan.started_at,
            completed_at=latest_scan.completed_at,
            created_at=latest_scan.created_at,
        )

    latest_completed = _latest_completed_scans_per_asset(db, business_id)
    scored = []
    risk_levels = []
    for scan in latest_completed:
        try:
            assessment = risk_service.get_or_create_assessment(db, scan)
        except Exception:
            continue
        if assessment.score_available and assessment.security_score is not None:
            scored.append(assessment.security_score)
        if assessment.risk_level:
            risk_levels.append(assessment.risk_level)

    average_score = round(sum(scored) / len(scored), 1) if scored else None
    # overall risk: highest (most severe) risk level among latest completed scans
    overall_risk = "unknown"
    if risk_levels:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "minimal": 0}
        overall_risk = max(risk_levels, key=lambda r: order.get(r, -1))

    overview = DashboardSecurityOverview(
        average_security_score=average_score,
        scored_assets=len(scored),
        overall_risk_level=overall_risk,
        latest_completed_scans=len(latest_completed),
    )

    # Critical security findings across latest completed scans per asset.
    critical_findings: List[CriticalFindingSummary] = []
    for scan in latest_completed:
        asset = db.get(Asset, scan.asset_id)
        findings = list(
            db.scalars(
                select(Finding).where(
                    Finding.scan_id == scan.id,
                    Finding.severity == "critical",
                )
            ).all()
        )
        for finding in findings:
            critical_findings.append(
                CriticalFindingSummary(
                    scan_id=scan.id,
                    asset_id=scan.asset_id,
                    asset_domain=(asset.domain if asset else "unknown"),
                    finding_id=finding.id,
                    check_code=finding.check_code,
                    title=finding.title,
                    severity=finding.severity,
                    recommendation=finding.recommendation,
                    detected_at=scan.completed_at or scan.created_at,
                )
            )
    critical_findings.sort(
        key=lambda f: (f.detected_at or _utcnow(), f.finding_id), reverse=True
    )

    # Alert counts from actual alert records.
    summary = alert_service.get_alert_summary(db, business_id)
    alert_counts = DashboardAlertCounts(
        total_unread=summary.unread,
        total=summary.total,
        critical=summary.critical,
        high=summary.high,
        medium=summary.medium,
        low=summary.low,
        resolved=summary.resolved,
    )

    # Recent security activity: latest scans and latest alerts.
    recent: List[RecentActivityItem] = []
    recent_scans = list(
        db.scalars(
            select(Scan)
            .join(Asset, Scan.asset_id == Asset.id)
            .where(Asset.business_id == business_id)
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .limit(10)
        ).all()
    )
    for scan in recent_scans:
        scan_asset = db.get(Asset, scan.asset_id)
        domain = scan_asset.domain if scan_asset else "unknown"
        recent.append(
            RecentActivityItem(
                type="scan",
                occurred_at=scan.completed_at or scan.started_at or scan.created_at,
                title=f"Scan {scan.status} for {domain}",
                severity=None,
                asset_id=scan.asset_id,
                asset_domain=domain,
                scan_id=scan.id,
                alert_id=None,
                status=scan.status,
            )
        )

    recent_alerts = list(
        db.scalars(
            select(Alert)
            .where(Alert.business_id == business_id)
            .order_by(Alert.created_at.desc(), Alert.id.desc())
            .limit(10)
        ).all()
    )
    for alert in recent_alerts:
        alert_asset = db.get(Asset, alert.asset_id)
        domain = alert_asset.domain if alert_asset else "unknown"
        recent.append(
            RecentActivityItem(
                type="alert",
                occurred_at=alert.created_at,
                title=alert.title,
                severity=alert.severity,
                asset_id=alert.asset_id,
                asset_domain=domain,
                scan_id=None,
                alert_id=alert.id,
                status=alert.status,
            )
        )

    recent.sort(key=lambda item: item.occurred_at or _utcnow(), reverse=True)

    return DashboardResponse(
        business_id=business.id,
        business_name=business.name,
        total_monitored_websites=total_assets,
        active_websites=active_assets,
        paused_websites=paused_assets,
        latest_scan=latest_scan_summary,
        latest_security_scores={
            "average_security_score": average_score,
            "scored_assets": len(scored),
            "latest_completed_scans": len(latest_completed),
        },
        critical_security_findings=critical_findings,
        alert_counts=alert_counts,
        recent_security_activity=recent[:15],
        security_overview=overview,
    )
