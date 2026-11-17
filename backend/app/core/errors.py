"""Error handling utilities for FirmLock.

Provides consistent error response models and exception handlers.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class ErrorResponse(BaseModel):
    """Standard error response model."""

    model_config = ConfigDict(from_attributes=True)

    detail: str
    error_code: Optional[str] = None
    error_type: Optional[str] = None


class ValidationErrorResponse(BaseModel):
    """Validation error response model."""

    model_config = ConfigDict(from_attributes=True)

    detail: str
    errors: list[dict[str, Any]]
    error_code: str = "VALIDATION_ERROR"


def _create_error_response(
    status_code: int,
    detail: str,
    error_code: Optional[str] = None,
    error_type: Optional[str] = None,
) -> JSONResponse:
    """Create a consistent error response."""
    content = {"detail": detail}
    if error_code:
        content["error_code"] = error_code
    if error_type and settings.environment != "production":
        content["error_type"] = error_type
    return JSONResponse(status_code=status_code, content=content)


def register_error_handlers(app: FastAPI) -> None:
    """Register consistent error handlers for the FastAPI application."""

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle Pydantic validation errors with consistent format."""
        logger.warning(
            "Validation error for %s %s: %s",
            request.method,
            request.url.path,
            exc.errors(),
        )
        return _create_error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request validation failed",
            error_code="VALIDATION_ERROR",
            error_type="RequestValidationError",
        )

    @app.exception_handler(status.HTTP_400_BAD_REQUEST)
    async def bad_request_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle 400 Bad Request errors."""
        return _create_error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
            error_code="BAD_REQUEST",
        )

    @app.exception_handler(status.HTTP_401_UNAUTHORIZED)
    async def unauthorized_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle 401 Unauthorized errors."""
        return _create_error_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            error_code="UNAUTHORIZED",
        )

    @app.exception_handler(status.HTTP_403_FORBIDDEN)
    async def forbidden_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle 403 Forbidden errors."""
        return _create_error_response(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
            error_code="FORBIDDEN",
        )

    @app.exception_handler(status.HTTP_404_NOT_FOUND)
    async def not_found_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle 404 Not Found errors."""
        return _create_error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found",
            error_code="NOT_FOUND",
        )

    @app.exception_handler(status.HTTP_409_CONFLICT)
    async def conflict_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle 409 Conflict errors."""
        return _create_error_response(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
            error_code="CONFLICT",
        )

    @app.exception_handler(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
    async def request_too_large_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle 413 Payload Too Large errors."""
        return _create_error_response(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Request body too large",
            error_code="PAYLOAD_TOO_LARGE",
        )

    @app.exception_handler(status.HTTP_429_TOO_MANY_REQUESTS)
    async def rate_limit_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle 429 Too Many Requests errors."""
        retry_after = getattr(exc, "headers", {}).get("Retry-After", "60")
        return _create_error_response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later.",
            error_code="RATE_LIMITED",
        )