"""Alert generation and management service.

Automatically generates in-app alerts from actionable scan findings and
provides listing, detail, summary and lifecycle (read/resolve) operations.

Generation rules (Stage 05):

* Alerts are generated for ``critical``, ``high``, ``medium`` and ``low``
  findings only. ``info`` findings and any technical-scanning markers that
  are not security findings do not create alerts.
* Duplicate unresolved alerts are not created for the same issue (same
  asset, check code and active status ``unread``/``read``).
* If a previously resolved issue reappears in a later completed scan, a new
  alert is created and the resolved alert history is preserved.
* Alert history is never deleted by this module.

All operations are scoped to a business/asset relationship where applicable.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import List, Optional, Sequence, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.models import Alert, Asset, Business, Finding, Scan
from app.schemas.alert import AlertSummary, AlertUpdate
from app.services.scanner.check_catalog import UNKNOWN_CHECK_CODES

ALERTABLE_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
UNRESOLVED_STATUSES = ("unread", "read")


class AlertNotFoundError(LookupError):
    """Raised when an alert does not exist."""


class BusinessNotFoundError(LookupError):
    """Raised when a business does not exist."""


class AssetNotFoundError(LookupError):
    """Raised when an asset does not exist."""


class InvalidAlertUpdateError(ValueError):
    """Raised when an alert update payload is invalid."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _is_alertable(finding: Finding) -> bool:
    severity = (finding.severity or "").strip().lower()
    if severity not in ALERTABLE_SEVERITIES:
        return False
    if finding.check_code in UNKNOWN_CHECK_CODES:
        return False
    return True


def _build_message(finding: Finding, asset_domain: str) -> str:
    parts = [
        f"Security issue detected on {asset_domain}.",
        (finding.description or "").strip(),
    ]
    if finding.evidence:
        parts.append(f"Evidence: {finding.evidence.strip()}")
    if finding.recommendation:
        parts.append(f"Recommendation: {finding.recommendation.strip()}")
    return " ".join(part for part in parts if part)


def generate_alerts_for_scan(db: Session, scan_id: int) -> List[Alert]:
    """Create alerts for actionable findings in ``scan_id``.

    The scan, its asset and findings must already be persisted and committed.
    The function is idempotent with respect to unresolved duplicates: calling
    it again for the same scan will not create a second unresolved alert for a
    finding whose alert already exists, because each finding is unique per
    ``(scan_id, check_code)`` and alerts are deduplicated by unresolved
    ``(asset_id, check_code)`` state.

    Returns the list of newly created alerts (possibly empty).
    """
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise LookupError(f"Scan {scan_id} not found.")

    asset = db.get(Asset, scan.asset_id)
    if asset is None:
        raise LookupError(f"Asset {scan.asset_id} not found for scan {scan_id}.")

    findings = list(
        db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
    )
    actionable = [finding for finding in findings if _is_alertable(finding)]
    if not actionable:
        return []

    # Unresolved alert check codes for this asset.
    unresolved_codes = set(
        db.scalars(
            select(Finding.check_code)
            .join(Alert, Alert.finding_id == Finding.id)
            .where(
                Alert.asset_id == asset.id,
                Alert.status.in_(UNRESOLVED_STATUSES),
            )
        ).all()
    )

    created: List[Alert] = []
    for finding in actionable:
        if finding.check_code in unresolved_codes:
            continue

        alert = Alert(
            business_id=asset.business_id,
            asset_id=asset.id,
            finding_id=finding.id,
            title=finding.title,
            message=_build_message(finding, asset.domain),
            severity=(finding.severity or "").strip().lower(),
            status="unread",
            created_at=_utcnow(),
        )
        db.add(alert)
        created.append(alert)
        unresolved_codes.add(finding.check_code)

    if created:
        db.commit()
        for alert in created:
            db.refresh(alert)
    return created


def get_business(db: Session, business_id: int) -> Business:
    business = db.get(Business, business_id)
    if business is None:
        raise BusinessNotFoundError("Business not found")
    return business


def get_alert(db: Session, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise AlertNotFoundError("Alert not found")
    return alert


def get_business_alert(db: Session, business_id: int, alert_id: int) -> Alert:
    get_business(db, business_id)
    alert = get_alert(db, alert_id)
    if alert.business_id != business_id:
        raise AlertNotFoundError("Alert not found")
    return alert


def list_alerts(
    db: Session,
    business_id: int,
    *,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
) -> Tuple[List[Alert], int]:
    get_business(db, business_id)

    stmt = select(Alert).where(Alert.business_id == business_id)
    count_stmt = select(func.count()).select_from(Alert).where(Alert.business_id == business_id)

    if severity:
        stmt = stmt.where(Alert.severity == severity)
        count_stmt = count_stmt.where(Alert.severity == severity)
    if status:
        stmt = stmt.where(Alert.status == status)
        count_stmt = count_stmt.where(Alert.status == status)

    total = int(db.scalar(count_stmt) or 0)
    stmt = (
        stmt.order_by(Alert.created_at.desc(), Alert.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return list(db.scalars(stmt).all()), total


def update_alert(db: Session, alert: Alert, payload: AlertUpdate) -> Alert:
    if payload.read is None and payload.resolved is None:
        raise InvalidAlertUpdateError("Provide 'read' and/or 'resolved'.")

    now = _utcnow()

    if payload.resolved is True:
        if alert.status != "resolved":
            alert.status = "resolved"
            alert.resolved_at = now
        if alert.read_at is None:
            alert.read_at = now
    elif payload.resolved is False and alert.status == "resolved":
        raise InvalidAlertUpdateError("Resolved alerts cannot be reopened.")

    if payload.read is True and alert.status == "unread":
        alert.status = "read"
        alert.read_at = now
    elif payload.read is False and alert.status == "read":
        alert.status = "unread"
        alert.read_at = None

    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def get_alert_summary(db: Session, business_id: int) -> AlertSummary:
    get_business(db, business_id)

    rows = db.execute(
        select(Alert.severity, Alert.status, func.count(Alert.id))
        .where(Alert.business_id == business_id)
        .group_by(Alert.severity, Alert.status)
    ).all()

    summary = AlertSummary()
    for severity, status, count in rows:
        count = int(count)
        summary.total += count
        if status == "unread":
            summary.unread += count
        elif status == "read":
            summary.read += count
        elif status == "resolved":
            summary.resolved += count

        sev = (severity or "").lower()
        if sev == "critical":
            summary.critical += count
        elif sev == "high":
            summary.high += count
        elif sev == "medium":
            summary.medium += count
        elif sev == "low":
            summary.low += count
        elif sev == "info":
            summary.info += count

    return summary
