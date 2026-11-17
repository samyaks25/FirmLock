"""Asset service layer."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.models import Asset
from app.schemas.asset import AssetCreate, AssetUpdate


class DuplicateAssetError(ValueError):
    """Raised when an asset domain is already registered for a business."""


class NotFoundError(LookupError):
    """Raised when a referenced entity does not exist."""


def register_asset(db: Session, business_id: int, payload: AssetCreate) -> Asset:
    # Business existence is checked by caller for clearer HTTP mapping, but we
    # also guard against races/inconsistency here.
    now = datetime.now(timezone.utc)
    asset = Asset(
        business_id=business_id,
        domain=payload.domain,
        authorization_confirmed=True,
        authorization_confirmed_at=now,
        monitoring_enabled=True,
        status="active",
    )
    db.add(asset)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        # Unique constraint or FK violation.
        msg = str(exc.orig).lower() if getattr(exc, "orig", None) else str(exc).lower()
        if "unique" in msg or "uq_asset_business_domain" in msg:
            raise DuplicateAssetError("Domain is already registered for this business.") from exc
        if "foreign key" in msg:
            raise NotFoundError("Business does not exist.") from exc
        raise
    db.refresh(asset)
    return asset


def get_asset(db: Session, asset_id: int) -> Optional[Asset]:
    return db.get(Asset, asset_id)


def list_assets_for_business(db: Session, business_id: int) -> List[Asset]:
    stmt = (
        select(Asset)
        .where(Asset.business_id == business_id)
        .order_by(Asset.id.asc())
    )
    return list(db.scalars(stmt).all())


def update_asset(db: Session, asset: Asset, payload: AssetUpdate) -> Asset:
    if payload.monitoring_enabled is not None:
        asset.monitoring_enabled = payload.monitoring_enabled
    if payload.status is not None:
        asset.status = payload.status
        # Keep monitoring flag aligned with status for clarity.
        if payload.status == "paused":
            asset.monitoring_enabled = False
        elif payload.status == "active":
            asset.monitoring_enabled = True
    asset.updated_at = datetime.now(timezone.utc)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset
