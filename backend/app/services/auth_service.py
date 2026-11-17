"""User authentication and management service."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.login_protection import get_login_protection
from app.core.security import hash_password, validate_password_strength, verify_password
from app.models.models import User
from app.schemas.auth import UserCreate, UserLogin


class DuplicateEmailError(ValueError):
    """Raised when attempting to register with an already-registered email."""


class InvalidCredentialsError(ValueError):
    """Raised when login credentials are invalid."""


class UserNotFoundError(LookupError):
    """Raised when a user is not found."""


class AccountLockedError(ValueError):
    """Raised when account is temporarily locked due to too many failed attempts."""

    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(f"Too many failed attempts. Try again in {retry_after} seconds.")


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


def authenticate_user(db: Session, payload: UserLogin, client_ip: str) -> User:
    """Verify user credentials and return the user if valid.

    Implements brute-force protection:
    - Tracks failures per IP+email combination (prevents cross-user lockout)
    - Uses generic error messages to avoid email enumeration
    - Applies temporary lockouts only (never permanent)
    - Does not log passwords or tokens
    """
    email = payload.email.strip().lower()
    login_protection = get_login_protection()

    # Check if locked out
    is_locked, retry_after = login_protection.is_locked(client_ip, email)
    if is_locked:
        raise AccountLockedError(retry_after)

    user = get_user_by_email(db, email)

    # Always verify password (even for non-existent users) to prevent timing attacks
    # and to track failures consistently (prevents enumeration)
    password_valid = False
    if user is not None and user.is_active:
        password_valid = verify_password(payload.password, user.hashed_password)

    if user is None or not user.is_active or not password_valid:
        # Record failure (same for non-existent, inactive, or wrong password)
        login_protection.record_failure(client_ip, email)
        raise InvalidCredentialsError("Invalid credentials.")

    # Success - reset failure tracking for this IP+email
    login_protection.record_success(client_ip, email)
    return user