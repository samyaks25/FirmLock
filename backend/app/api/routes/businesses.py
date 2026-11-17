"""Business API routes."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.schemas.business import BusinessCreate, BusinessResponse
from app.schemas.dashboard import DashboardResponse
from app.services import business_service, dashboard_service

router = APIRouter(prefix="/api/businesses", tags=["Businesses"])


@router.post("", response_model=BusinessResponse, status_code=status.HTTP_201_CREATED)
def create_business(payload: BusinessCreate, db: Session = Depends(get_db)) -> BusinessResponse:
    return business_service.create_business(db, payload)


@router.get("", response_model=List[BusinessResponse])
def list_businesses(db: Session = Depends(get_db)) -> List[BusinessResponse]:
    return business_service.list_businesses(db)


@router.get("/{business_id}", response_model=BusinessResponse)
def get_business(business_id: int, db: Session = Depends(get_db)) -> BusinessResponse:
    business = business_service.get_business(db, business_id)
    if business is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business not found")
    return business


@router.get("/{business_id}/dashboard", response_model=DashboardResponse)
def get_business_dashboard(
    business_id: int, db: Session = Depends(get_db)
) -> DashboardResponse:
    try:
        return dashboard_service.build_dashboard(db, business_id)
    except dashboard_service.BusinessNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

