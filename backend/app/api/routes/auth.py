"""Authentication API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.api.rate_limit import login_rate_limit, register_rate_limit, _get_client_ip
from app.database.connection import get_db
from app.schemas.auth import Token, UserCreate, UserLogin, UserResponse
from app.services import auth_service
from app.core.auth import create_access_token, get_token_expiry_minutes

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    dependencies=[Depends(register_rate_limit)],
)
def register_user(payload: UserCreate, db: Session = Depends(get_db)) -> UserResponse:
    """Register a new user account.

    Email is normalized to lowercase.
    Password must be at least 12 characters.
    Returns the created user profile (no password hash).
    """
    try:
        user = auth_service.create_user(db, payload)
    except auth_service.DuplicateEmailError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return UserResponse.model_validate(user)


@router.post(
    "/login",
    response_model=Token,
    summary="Authenticate user and return access token",
    dependencies=[Depends(login_rate_limit)],
)
def login_user(payload: UserLogin, request: Request, db: Session = Depends(get_db)) -> Token:
    """Authenticate user with email and password.

    Returns a short-lived JWT access token (15 minutes by default).
    Uses generic error message to avoid email enumeration.
    Implements brute-force protection with temporary lockouts.
    """
    client_ip = _get_client_ip(request)
    try:
        user = auth_service.authenticate_user(db, payload, client_ip)
    except auth_service.InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except auth_service.AccountLockedError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    access_token = create_access_token(user)
    expires_in = get_token_expiry_minutes() * 60
    return Token(access_token=access_token, expires_in=expires_in)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
def get_current_user_profile(user: User = Depends(get_current_user)) -> UserResponse:
    """Return the authenticated user's profile."""
    return UserResponse.model_validate(user)