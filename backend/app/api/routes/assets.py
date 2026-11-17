"""Asset API routes."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.schemas.asset import AssetCreate, AssetResponse, AssetUpdate
from app.services import asset_service, business_service

router = APIRouter(tags=["Assets"])


@router.post(
    "/api/businesses/{business_id}/assets",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_asset(
    business_id: int, payload: AssetCreate, db: Session = Depends(get_db)
) -> AssetResponse:
    business = business_service.get_business(db, business_id)
    if business is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business not found")
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
def list_assets(business_id: int, db: Session = Depends(get_db)) -> List[AssetResponse]:
    business = business_service.get_business(db, business_id)
    if business is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business not found")
    return asset_service.list_assets_for_business(db, business_id)


@router.get("/api/assets/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db)) -> AssetResponse:
    asset = asset_service.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


@router.patch("/api/assets/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int, payload: AssetUpdate, db: Session = Depends(get_db)
) -> AssetResponse:
    asset = asset_service.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset_service.update_asset(db, asset, payload)
