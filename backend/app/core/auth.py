"""JWT authentication utilities for FirmLock.

Security hardening:
- HS256 algorithm explicitly enforced (algorithm confusion prevention)
- Issuer and audience validation required
- Token expiry validated
- Strong secret required in production (validated in config)
- Sensitive token data never logged
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from app.core.config import settings
from app.models.models import User


_ALLOWED_ALGORITHMS = ("HS256",)


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

    Security checks:
    - Algorithm explicitly restricted to HS256 (prevents algorithm substitution)
    - Signature verified with configured secret
    - Expiry (exp) validated
    - Issuer (iss) validated
    - Audience (aud) validated
    - Issued-at (iat) validated (not in future)

    Returns the payload dict if valid.
    Raises JWTError if invalid.
    """
    # Explicitly specify allowed algorithm to prevent algorithm confusion attacks
    payload = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=list(_ALLOWED_ALGORITHMS),
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={
            "verify_exp": True,
            "verify_iat": True,
            "verify_iss": True,
            "verify_aud": True,
            "verify_signature": True,
        },
    )
    return payload


def get_token_expiry_minutes() -> int:
    """Return the configured access token expiry in minutes."""
    return settings.jwt_access_token_expire_minutes