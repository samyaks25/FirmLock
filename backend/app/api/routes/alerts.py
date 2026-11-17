"""Alert REST API routes."""

from __future__ import annotations

import math
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.schemas.alert import AlertListResponse, AlertResponse, AlertSummary, AlertUpdate
from app.services import alert_service

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
) -> AlertListResponse:
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
def get_alert(alert_id: int, db: Session = Depends(get_db)) -> AlertResponse:
    try:
        alert = alert_service.get_alert(db, alert_id)
    except alert_service.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return AlertResponse.model_validate(alert)


@router.patch(
    "/api/alerts/{alert_id}",
    response_model=AlertResponse,
    summary="Update alert status (read/resolve)",
)
def update_alert(
    alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db)
) -> AlertResponse:
    try:
        alert = alert_service.get_alert(db, alert_id)
    except alert_service.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
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
def get_alert_summary(business_id: int, db: Session = Depends(get_db)) -> AlertSummary:
    try:
        return alert_service.get_alert_summary(db, business_id)
    except alert_service.BusinessNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
