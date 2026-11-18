"""Business service layer."""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.models import Business
from app.schemas.business import BusinessCreate
from app.services import membership_service


def create_business(db: Session, payload: BusinessCreate, owner_id: int) -> Business:
    """Create a new business and assign the creator as owner."""
    business = Business(name=payload.name, industry=payload.industry)
    db.add(business)
    db.commit()
    db.refresh(business)

    # Auto-assign owner role to the creator
    membership_service.create_membership(db, owner_id, business.id, role="owner")

    return business


def get_business(db: Session, business_id: int) -> Optional[Business]:
    return db.get(Business, business_id)


def list_businesses(db: Session, user_id: int | None = None) -> List[Business]:
    """List businesses, optionally filtered by user membership."""
    if user_id is not None:
        stmt = (
            select(Business)
            .join(Business.memberships)
            .where(Business.memberships.any(user_id=user_id))
            .order_by(Business.id.asc())
        )
    else:
        stmt = select(Business).order_by(Business.id.asc())
    return list(db.scalars(stmt).all())
