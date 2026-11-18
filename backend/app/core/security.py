"""Password hashing and verification utilities for FirmLock.

Uses Argon2id via passlib for secure password storage.
"""

from __future__ import annotations

from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto", argon2__type="id")


def hash_password(password: str) -> str:
    """Return the Argon2id hash of ``password``."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify ``plain_password`` against ``hashed_password``."""
    return pwd_context.verify(plain_password, hashed_password)


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password meets minimum requirements.

    Returns (is_valid, error_message).
    """
    min_len = settings.password_min_length
    if len(password) < min_len:
        return False, f"Password must be at least {min_len} characters long."
    return True, ""