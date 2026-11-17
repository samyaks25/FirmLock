"""FastAPI application entry point for FirmLock.

Run locally with:
    uvicorn app.main:app --reload
"""

import logging
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("firmlock")


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    application = FastAPI(
        title=settings.app_name,
        version=settings.api_version,
        description="Backend API for FirmLock cybersecurity monitoring.",
    )

    # Explicitly allowed origins only. Credentials are allowed for these
    # known local frontend origins, so no wildcard origin is used.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET"],
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
    def health_check() -> Dict[str, str]:
        """Return the backend health status, service name and API version."""
        return {
            "status": "ok",
            "service": settings.app_name,
            "version": settings.api_version,
            "environment": settings.environment,
        }

    return application


app = create_app()


def get_app_metadata() -> Dict[str, Any]:
    """Expose a small metadata helper (used by tests and tooling)."""
    return {
        "title": app.title,
        "version": app.version,
        "cors_origins": settings.cors_origins,
    }