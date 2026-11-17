"""Scanner REST API routes."""

from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.api.rate_limit import scan_rate_limit
from app.database.connection import get_db
from app.models.models import Asset, Scan, User
from app.schemas.report import ScanReportResponse
from app.schemas.scan import ScanAcceptedResponse, ScanResponse
from app.services import membership_service, report_service
from app.services.scanner.scan_manager import run_scan

logger = logging.getLogger("firmlock.scanner")

router = APIRouter(tags=["Scans"])


@router.post(
    "/api/assets/{asset_id}/scan",
    response_model=ScanAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a security scan for an authorised asset",
    dependencies=[Depends(scan_rate_limit)],
)
def start_scan(
    asset_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanAcceptedResponse:
    """Queue a read-only security scan for an authorised, active asset.

    Returns ``202 Accepted`` with the new scan ID and ``pending`` status. The
    scan itself runs in a FastAPI background task with its own DB session.
    """
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not membership_service.can_manage_assets(db, current_user.id, asset.business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    if not asset.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Asset authorization has not been confirmed.",
        )
    if asset.status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Asset is not active.",
        )
    if not asset.monitoring_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Monitoring is disabled for this asset.",
        )

    scan = Scan(asset_id=asset_id, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    logger.info("Queued scan %s for asset %s (%s)", scan.id, asset_id, asset.domain)
    background_tasks.add_task(run_scan, scan.id)

    return ScanAcceptedResponse(scan_id=scan.id, asset_id=asset_id, status=scan.status)


@router.get(
    "/api/scans/{scan_id}",
    response_model=ScanResponse,
    summary="Get a scan and its findings",
)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanResponse:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    asset = db.get(Asset, scan.asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not membership_service.can_access_reports(db, current_user.id, asset.business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    return ScanResponse.model_validate(scan)


@router.get(
    "/api/scans/{scan_id}/report",
    response_model=ScanReportResponse,
    summary="Get a structured security report for a scan",
)
def get_scan_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanReportResponse:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    asset = db.get(Asset, scan.asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not membership_service.can_access_reports(db, current_user.id, asset.business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    try:
        return report_service.build_scan_report(db, scan_id)
    except report_service.ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except report_service.AssetNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get(
    "/api/scans/{scan_id}/report.csv",
    summary="Export scan findings as CSV",
    response_class=PlainTextResponse,
)
def get_scan_report_csv(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PlainTextResponse:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    asset = db.get(Asset, scan.asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not membership_service.can_access_reports(db, current_user.id, asset.business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    try:
        csv_data = report_service.build_scan_csv(db, scan_id)
    except report_service.ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except report_service.AssetNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return PlainTextResponse(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-report.csv"'},
    )


@router.get(
    "/api/assets/{asset_id}/scans",
    response_model=List[ScanResponse],
    summary="List scan history for an asset",
)
def list_scans(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[ScanResponse]:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not membership_service.can_access_reports(db, current_user.id, asset.business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    stmt = select(Scan).where(Scan.asset_id == asset_id).order_by(Scan.id.desc())
    scans = list(db.scalars(stmt).all())
    return [ScanResponse.model_validate(scan) for scan in scans]
