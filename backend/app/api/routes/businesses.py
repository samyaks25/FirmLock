"""Business API routes."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database.connection import get_db
from app.models.models import User
from app.schemas.business import BusinessCreate, BusinessResponse
from app.schemas.dashboard import DashboardResponse
from app.services import business_service, dashboard_service, membership_service

router = APIRouter(prefix="/api/businesses", tags=["Businesses"])


@router.post("", response_model=BusinessResponse, status_code=status.HTTP_201_CREATED)
def create_business(
    payload: BusinessCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BusinessResponse:
    return business_service.create_business(db, payload, current_user.id)


@router.get("", response_model=List[BusinessResponse])
def list_businesses(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[BusinessResponse]:
    return business_service.list_businesses(db, current_user.id)


@router.get("/{business_id}", response_model=BusinessResponse)
def get_business(
    business_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BusinessResponse:
    business = business_service.get_business(db, business_id)
    if business is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business not found")
    if not membership_service.can_access_reports(db, current_user.id, business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    return business


@router.get("/{business_id}/dashboard", response_model=DashboardResponse)
def get_business_dashboard(
    business_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DashboardResponse:
    business = business_service.get_business(db, business_id)
    if business is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business not found")
    if not membership_service.can_access_dashboard(db, current_user.id, business_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this business")
    try:
        return dashboard_service.build_dashboard(db, business_id)
    except dashboard_service.BusinessNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

