"""Alert REST API routes."""

from __future__ import annotations

import math
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database.connection import get_db
from app.models.models import Alert, User
from app.schemas.alert import AlertListResponse, AlertResponse, AlertSummary, AlertUpdate
from app.services import alert_service, business_service, membership_service

router = APIRouter(tags=["Alerts"])

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_STATUSES = {"unread", "read", "resolved"}


@router.get(
    "/api/businesses/{business_id}/alerts",
    response_model=AlertListResponse,
    summary="List alerts for a business",
)
def list_business_alerts(
    business_id: int,
    severity: Optional[str] = Query(default=None),
    alert_status: Optional[str] = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertListResponse:
    # Check business exists first
    business = business_service.get_business(db, business_id)
    if business is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business not found")
    if not membership_service.can_access_reports(db, current_user.id, business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    if severity is not None and severity not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid severity filter.",
        )
    if alert_status is not None and alert_status not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid status filter.",
        )
    try:
        items, total = alert_service.list_alerts(
            db,
            business_id,
            severity=severity,
            status=alert_status,
            page=page,
            page_size=page_size,
        )
    except alert_service.BusinessNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    pages = math.ceil(total / page_size) if total else 0
    return AlertListResponse(
        items=[AlertResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get(
    "/api/alerts/{alert_id}",
    response_model=AlertResponse,
    summary="Get alert details",
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    try:
        alert = alert_service.get_alert(db, alert_id)
    except alert_service.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if not membership_service.can_access_reports(db, current_user.id, alert.business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    return AlertResponse.model_validate(alert)


@router.patch(
    "/api/alerts/{alert_id}",
    response_model=AlertResponse,
    summary="Update alert status (read/resolve)",
)
def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    try:
        alert = alert_service.get_alert(db, alert_id)
    except alert_service.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if not membership_service.can_manage_alerts(db, current_user.id, alert.business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    try:
        updated = alert_service.update_alert(db, alert, payload)
    except alert_service.InvalidAlertUpdateError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return AlertResponse.model_validate(updated)


@router.get(
    "/api/businesses/{business_id}/alerts/summary",
    response_model=AlertSummary,
    summary="Get alert summary counts for a business",
)
def get_alert_summary(
    business_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertSummary:
    # Check business exists first
    business = business_service.get_business(db, business_id)
    if business is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business not found")
    if not membership_service.can_access_reports(db, current_user.id, business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    try:
        return alert_service.get_alert_summary(db, business_id)
    except alert_service.BusinessNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
