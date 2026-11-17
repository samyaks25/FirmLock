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

from app.api.router import api_router
from app.core.config import settings
from app.database.connection import check_migration_version

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("firmlock")


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

    # Explicitly allowed origins only. Credentials are allowed for these
    # known local frontend origins, so no wildcard origin is used.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["*"],
    )

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Return a generic error response instead of leaking internals."""
        logger.exception("Unhandled error for %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
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
