"""Security headers middleware for FirmLock."""

from __future__ import annotations

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    def __init__(self, app, hsts_enabled: bool = False, hsts_max_age: int = 31536000):
        super().__init__(app)
        self.hsts_enabled = hsts_enabled
        self.hsts_max_age = hsts_max_age

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # X-Content-Type-Options: Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-Frame-Options: Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Referrer-Policy: No referrer sent
        response.headers["Referrer-Policy"] = "no-referrer"

        # Permissions-Policy: Restrict powerful browser features
        # Disables all powerful features by default
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=(), "
            "interest-cohort=()"
        )

        # Cache-Control for sensitive responses
        # Apply no-store for authenticated API responses
        if request.url.path.startswith("/api/") and request.method != "GET":
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        elif request.url.path.startswith("/api/auth/") or "/report.csv" in request.url.path:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        elif request.url.path.startswith("/api/"):
            # For other API GET responses, allow brief caching but require revalidation
            response.headers["Cache-Control"] = "private, max-age=0, must-revalidate"

        # HSTS: Only enable when behind HTTPS
        if self.hsts_enabled and request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = f"max-age={self.hsts_max_age}; includeSubDomains"

        return response


def get_hsts_config() -> tuple[bool, int]:
    """Get HSTS configuration from environment.

    Returns:
        tuple: (enabled, max_age_seconds)
    """
    enabled = os.getenv("FIRMLOCK_HSTS_ENABLED", "false").lower() in ("true", "1", "yes")
    max_age = int(os.getenv("FIRMLOCK_HSTS_MAX_AGE", "31536000"))  # 1 year default
    return enabled, max_age


import os