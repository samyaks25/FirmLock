"""FastAPI application entry point for FirmLock.

Run locally with:
    uvicorn app.main:app --reload
"""

import logging
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.rate_limit import add_rate_limit_headers
from app.api.router import api_router
from app.core.config import settings
from app.core.errors import register_error_handlers
from app.core.logging import get_logger, setup_secure_logging
from app.core.request_size import RequestSizeLimitMiddleware, get_request_size_limit
from app.core.security_headers import SecurityHeadersMiddleware, get_hsts_config
from app.core.trusted_host import TrustedHostMiddleware, get_allowed_hosts
from app.database.connection import check_migration_version

# Configure secure logging with sensitive data redaction
setup_secure_logging(level=logging.INFO if settings.environment == "production" else logging.DEBUG)
logger = get_logger("firmlock")


@asynccontextmanager
async def lifespan(_application: FastAPI):
    """Application lifespan hook for startup/shutdown tasks.

    Checks database migration status on startup. Does NOT automatically run
    migrations - schema changes must be applied explicitly via 'alembic upgrade head'.
    Logs a warning if the database schema is outdated.
    """
    is_up_to_date, message = check_migration_version()
    if is_up_to_date:
        logger.info("Database migration check: %s", message)
    else:
        logger.warning("Database migration check: %s", message)
        logger.warning("Run 'alembic upgrade head' to apply pending migrations.")
    yield


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    application = FastAPI(
        title=settings.app_name,
        version=settings.api_version,
        description="Backend API for FirmLock cybersecurity monitoring.",
        lifespan=lifespan,
    )

    # Request size limiting (outermost - reject oversized requests early)
    application.add_middleware(
        RequestSizeLimitMiddleware,
        max_size_bytes=get_request_size_limit(),
    )

    # Trusted host validation (validate Host header early)
    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=get_allowed_hosts(),
    )

    # Security headers (add to all responses)
    hsts_enabled, hsts_max_age = get_hsts_config()
    application.add_middleware(
        SecurityHeadersMiddleware,
        hsts_enabled=hsts_enabled,
        hsts_max_age=hsts_max_age,
    )

    # CORS (must be after security headers to allow credentials with explicit origins)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["*"],
    )

    # Rate limit headers middleware (add headers to responses)
    @application.middleware("http")
    async def rate_limit_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        add_rate_limit_headers(request, response)
        return response

    # Register consistent error handlers
    register_error_handlers(application)

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Return a generic error response instead of leaking internals.

        In production: log full exception with traceback, return generic message.
        In development: include error details for debugging.
        """
        logger.exception(
            "Unhandled error for %s %s",
            request.method,
            request.url.path,
        )

        if settings.environment == "production":
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"},
            )
        else:
            # Development: include error type and message for debugging
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal server error",
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            )

    @application.get("/", tags=["General"], summary="Welcome message")
    def read_root() -> Dict[str, str]:
        """Return a welcome message identifying the FirmLock API."""
        return {
            "message": "Welcome to the FirmLock API",
            "service": "FirmLock",
            "version": settings.api_version,
        }

    @application.get("/api/health", tags=["Health"], summary="Backend health status")
    def health_check() -> Dict[str, Any]:
        """Return the backend health status, service name, API version, and migration status."""
        is_up_to_date, migration_message = check_migration_version()
        return {
            "status": "ok",
            "service": settings.app_name,
            "version": settings.api_version,
            "environment": settings.environment,
            "database_migration": {
                "up_to_date": is_up_to_date,
                "message": migration_message,
            },
        }

    application.include_router(api_router)
    return application


app = create_app()


def get_app_metadata() -> Dict[str, Any]:
    """Expose a small metadata helper (used by tests and tooling)."""
    return {
        "title": app.title,
        "version": app.version,
        "cors_origins": settings.cors_origins,
    }
