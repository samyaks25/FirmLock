"""Trusted host middleware for FirmLock."""

from __future__ import annotations

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse

from app.core.config import settings


class TrustedHostMiddleware(BaseHTTPMiddleware):
    """Validate Host header against allowed hosts.

    Rejects requests with unexpected Host headers to prevent Host header injection attacks.
    """

    def __init__(
        self,
        app,
        allowed_hosts: list[str] | None = None,
        www_redirect: bool = False,
    ):
        super().__init__(app)
        self.allowed_hosts = set(allowed_hosts or [])
        self.www_redirect = www_redirect

        # Always allow localhost in development
        if settings.environment == "development":
            self.allowed_hosts.update([
                "localhost",
                "127.0.0.1",
                "localhost:8000",
                "127.0.0.1:8000",
                "localhost:5173",
                "127.0.0.1:5173",
            ])

    def _is_allowed_host(self, host: str) -> bool:
        """Check if host is in allowed list (supports wildcards for subdomains)."""
        host = host.lower().strip()

        # Remove port if present for comparison
        host_no_port = host.split(":")[0]

        for allowed in self.allowed_hosts:
            allowed = allowed.lower().strip()
            allowed_no_port = allowed.split(":")[0]

            if host == allowed:
                return True

            # Support wildcard subdomain matching (e.g., *.example.com)
            if allowed_no_port.startswith("*."):
                domain = allowed_no_port[2:]
                if host_no_port == domain or host_no_port.endswith("." + domain):
                    return True

        return False

    async def dispatch(self, request: Request, call_next):
        host = request.headers.get("host", "").split(":")[0]

        # Skip validation for test client and internal requests
        if not host or host in ("testserver", "localhost", "127.0.0.1"):
            if settings.environment == "development":
                return await call_next(request)

        if not self._is_allowed_host(host):
            return PlainTextResponse(
                "Invalid Host header",
                status_code=400,
            )

        return await call_next(request)


def get_allowed_hosts() -> list[str]:
    """Get allowed hosts from environment variable.

    Format: comma-separated list of hostnames (e.g., "api.example.com,*.example.com")
    """
    raw = os.getenv("FIRMLOCK_ALLOWED_HOSTS", "")
    return [host.strip() for host in raw.split(",") if host.strip()]


import os