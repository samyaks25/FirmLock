"""Business membership and role-based access control service."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.models import Business, BusinessMembership, User


class MembershipNotFoundError(LookupError):
    """Raised when a membership is not found."""


class BusinessNotFoundError(LookupError):
    """Raised when a business is not found."""


class InsufficientPermissionError(ValueError):
    """Raised when user lacks required permission."""


class InvalidRoleError(ValueError):
    """Raised when an invalid role is specified."""


VALID_ROLES = ("owner", "admin", "member")


def validate_role(role: str) -> None:
    """Validate that role is one of the allowed values."""
    if role not in VALID_ROLES:
        raise InvalidRoleError(f"Invalid role '{role}'. Must be one of: {', '.join(VALID_ROLES)}")


def get_membership(db: Session, user_id: int, business_id: int) -> BusinessMembership | None:
    """Get membership for user in business."""
    stmt = select(BusinessMembership).where(
        BusinessMembership.user_id == user_id,
        BusinessMembership.business_id == business_id,
    )
    return db.scalars(stmt).first()


def get_user_memberships(db: Session, user_id: int) -> list[BusinessMembership]:
    """Get all memberships for a user."""
    stmt = select(BusinessMembership).where(BusinessMembership.user_id == user_id)
    return list(db.scalars(stmt).all())


def get_user_business_ids(db: Session, user_id: int) -> list[int]:
    """Get all business IDs the user has membership in."""
    stmt = select(BusinessMembership.business_id).where(BusinessMembership.user_id == user_id)
    return list(db.scalars(stmt).all())


def get_user_role(db: Session, user_id: int, business_id: int) -> str | None:
    """Get user's role in a business."""
    membership = get_membership(db, user_id, business_id)
    return membership.role if membership else None


def require_membership(db: Session, user_id: int, business_id: int) -> BusinessMembership:
    """Require user to be a member of the business, return membership."""
    membership = get_membership(db, user_id, business_id)
    if membership is None:
        raise MembershipNotFoundError("User is not a member of this business.")
    return membership


def require_role(
    db: Session,
    user_id: int,
    business_id: int,
    allowed_roles: tuple[str, ...],
) -> BusinessMembership:
    """Require user to have one of the allowed roles in the business."""
    membership = require_membership(db, user_id, business_id)
    if membership.role not in allowed_roles:
        raise InsufficientPermissionError(
            f"Role '{membership.role}' does not have permission. Required: {', '.join(allowed_roles)}"
        )
    return membership


def require_owner_or_admin(db: Session, user_id: int, business_id: int) -> BusinessMembership:
    """Require user to be owner or admin of the business."""
    return require_role(db, user_id, business_id, ("owner", "admin"))


def require_any_role(db: Session, user_id: int, business_id: int) -> BusinessMembership:
    """Require user to have any role in the business (member, admin, or owner)."""
    return require_role(db, user_id, business_id, ("owner", "admin", "member"))


def create_membership(
    db: Session,
    user_id: int,
    business_id: int,
    role: str = "member",
) -> BusinessMembership:
    """Create a new business membership."""
    validate_role(role)
    business = db.get(Business, business_id)
    if business is None:
        raise BusinessNotFoundError("Business not found.")
    user = db.get(User, user_id)
    if user is None:
        raise ValueError("User not found.")

    membership = BusinessMembership(user_id=user_id, business_id=business_id, role=role)
    db.add(membership)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(membership)
    return membership


def update_membership_role(
    db: Session,
    user_id: int,
    business_id: int,
    new_role: str,
) -> BusinessMembership:
    """Update a user's role in a business."""
    validate_role(new_role)
    membership = get_membership(db, user_id, business_id)
    if membership is None:
        raise MembershipNotFoundError("Membership not found.")
    membership.role = new_role
    db.add(membership)
    db.commit()
    db.refresh(membership)
    return membership


def remove_membership(db: Session, user_id: int, business_id: int) -> None:
    """Remove a user's membership from a business."""
    membership = get_membership(db, user_id, business_id)
    if membership is None:
        raise MembershipNotFoundError("Membership not found.")
    db.delete(membership)
    db.commit()


def can_manage_assets(db: Session, user_id: int, business_id: int) -> bool:
    """Check if user can manage assets (owner, admin)."""
    role = get_user_role(db, user_id, business_id)
    return role in ("owner", "admin")


def can_start_scans(db: Session, user_id: int, business_id: int) -> bool:
    """Check if user can start scans (owner, admin)."""
    role = get_user_role(db, user_id, business_id)
    return role in ("owner", "admin")


def can_manage_alerts(db: Session, user_id: int, business_id: int) -> bool:
    """Check if user can manage alerts (owner, admin)."""
    role = get_user_role(db, user_id, business_id)
    return role in ("owner", "admin")


def can_access_reports(db: Session, user_id: int, business_id: int) -> bool:
    """Check if user can access reports (owner, admin, member)."""
    role = get_user_role(db, user_id, business_id)
    return role in ("owner", "admin", "member")


def can_access_dashboard(db: Session, user_id: int, business_id: int) -> bool:
    """Check if user can access dashboard (owner, admin, member)."""
    role = get_user_role(db, user_id, business_id)
    return role in ("owner", "admin", "member")