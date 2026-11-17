"""User authentication and management service."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import hash_password, validate_password_strength, verify_password
from app.models.models import User
from app.schemas.auth import UserCreate, UserLogin


class DuplicateEmailError(ValueError):
    """Raised when attempting to register with an already-registered email."""


class InvalidCredentialsError(ValueError):
    """Raised when login credentials are invalid."""


class UserNotFoundError(LookupError):
    """Raised when a user is not found."""


def create_user(db: Session, payload: UserCreate) -> User:
    """Register a new user."""
    is_valid, error_msg = validate_password_strength(payload.password)
    if not is_valid:
        raise ValueError(error_msg)

    email = payload.email.strip().lower()
    user = User(
        email=email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        msg = str(exc.orig).lower() if getattr(exc, "orig", None) else str(exc).lower()
        if "unique" in msg or "users.email" in msg:
            raise DuplicateEmailError("Email is already registered.") from exc
        raise
    db.refresh(user)
    return user


def get_user_by_email(db: Session, email: str) -> User | None:
    """Get user by email (case-insensitive)."""
    email = email.strip().lower()
    stmt = select(User).where(User.email == email)
    return db.scalars(stmt).first()


def get_user_by_id(db: Session, user_id: int) -> User | None:
    """Get user by ID."""
    return db.get(User, user_id)


def authenticate_user(db: Session, payload: UserLogin) -> User:
    """Verify user credentials and return the user if valid."""
    user = get_user_by_email(db, payload.email)
    if user is None or not user.is_active:
        raise InvalidCredentialsError("Invalid credentials.")
    if not verify_password(payload.password, user.hashed_password):
        raise InvalidCredentialsError("Invalid credentials.")
    return user