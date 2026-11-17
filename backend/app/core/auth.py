"""JWT authentication utilities for FirmLock."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from app.core.config import settings
from app.models.models import User


def create_access_token(
    user: User,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT access token for the given user."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.jwt_access_token_expire_minutes
        )

    to_encode = {
        "sub": str(user.id),
        "email": user.email,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token.

    Returns the payload dict if valid.
    Raises JWTError if invalid.
    """
    payload = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )
    return payload


def get_token_expiry_minutes() -> int:
    """Return the configured access token expiry in minutes."""
    return settings.jwt_access_token_expire_minutes