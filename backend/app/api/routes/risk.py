"""Risk assessment REST API routes."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.models import Asset, Scan
from app.schemas.risk import AssetRiskResponse, RiskAssessmentResponse, RiskHistoryEntry
from app.services import risk_service

router = APIRouter(tags=["Risk"])


@router.get(
    "/api/scans/{scan_id}/risk",
    response_model=RiskAssessmentResponse,
    summary="Get the risk assessment for a scan",
)
def get_scan_risk(scan_id: int, db: Session = Depends(get_db)) -> RiskAssessmentResponse:
    """Return the risk assessment for ``scan_id``.

    Failed, pending and running scans return ``200`` with
    ``score_available: false`` and an explanation instead of a misleading
    score. Unknown scan IDs return ``404``.
    """
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return risk_service.get_scan_risk(db, scan)


@router.get(
    "/api/assets/{asset_id}/risk",
    response_model=AssetRiskResponse,
    summary="Get the latest completed scan's risk assessment for an asset",
)
def get_asset_risk(asset_id: int, db: Session = Depends(get_db)) -> AssetRiskResponse:
    """Return the latest completed scan's risk assessment for an asset.

    Returns ``404`` when the asset does not exist or has no completed scan.
    """
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    assessment = risk_service.get_asset_risk(db, asset)
    if assessment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No completed scan found for this asset.",
        )
    return assessment


@router.get(
    "/api/assets/{asset_id}/risk/history",
    response_model=List[RiskHistoryEntry],
    summary="List completed-scan risk assessments for historical comparison",
)
def get_asset_risk_history(
    asset_id: int, db: Session = Depends(get_db)
) -> List[RiskHistoryEntry]:
    """Return completed-scan assessments for an asset, newest first.

    Assessments are persisted snapshots, so previous scores are never
    recomputed or overwritten.
    """
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return risk_service.list_asset_risk_history(db, asset)