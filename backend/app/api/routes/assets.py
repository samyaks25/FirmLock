"""Asset API routes."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database.connection import get_db
from app.models.models import Asset, User
from app.schemas.asset import AssetCreate, AssetResponse, AssetUpdate
from app.schemas.report import AssetReportsResponse
from app.services import asset_service, business_service, membership_service, report_service

router = APIRouter(tags=["Assets"])


@router.post(
    "/api/businesses/{business_id}/assets",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_asset(
    business_id: int,
    payload: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AssetResponse:
    business = business_service.get_business(db, business_id)
    if business is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business not found")
    if not membership_service.can_manage_assets(db, current_user.id, business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    try:
        return asset_service.register_asset(db, business_id, payload)
    except asset_service.DuplicateAssetError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except asset_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get(
    "/api/businesses/{business_id}/assets",
    response_model=List[AssetResponse],
)
def list_assets(
    business_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[AssetResponse]:
    business = business_service.get_business(db, business_id)
    if business is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business not found")
    if not membership_service.can_access_reports(db, current_user.id, business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    return asset_service.list_assets_for_business(db, business_id)


@router.get("/api/assets/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AssetResponse:
    asset = asset_service.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not membership_service.can_access_reports(db, current_user.id, asset.business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    return asset


@router.get(
    "/api/assets/{asset_id}/reports",
    response_model=AssetReportsResponse,
    summary="List historical scan report summaries for an asset",
)
def get_asset_reports(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AssetReportsResponse:
    asset = asset_service.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not membership_service.can_access_reports(db, current_user.id, asset.business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    try:
        return report_service.list_asset_reports(db, asset_id)
    except report_service.AssetNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.patch("/api/assets/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    payload: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AssetResponse:
    asset = asset_service.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not membership_service.can_manage_assets(db, current_user.id, asset.business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    return asset_service.update_asset(db, asset, payload)

