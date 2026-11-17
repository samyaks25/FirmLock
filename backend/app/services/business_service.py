"""Business service layer."""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.models import Business
from app.schemas.business import BusinessCreate


def create_business(db: Session, payload: BusinessCreate) -> Business:
    business = Business(name=payload.name, industry=payload.industry)
    db.add(business)
    db.commit()
    db.refresh(business)
    return business


def get_business(db: Session, business_id: int) -> Optional[Business]:
    return db.get(Business, business_id)


def list_businesses(db: Session) -> List[Business]:
    stmt = select(Business).order_by(Business.id.asc())
    return list(db.scalars(stmt).all())
