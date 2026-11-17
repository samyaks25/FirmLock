"""Rate limiting middleware and dependencies for FirmLock."""

from __future__ import annotations

from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.rate_limit import (
    InMemoryRateLimiter,
    RateLimitConfig,
    RateLimitInfo,
    get_authenticated_rate_limit_config,
    get_general_rate_limit_config,
    get_login_rate_limit_config,
    get_rate_limiter,
    get_register_rate_limit_config,
    get_scan_rate_limit_config,
)
from app.models.models import User
from app.services import auth_service

bearer_scheme = HTTPBearer(auto_error=False)


def _get_client_ip(request: Request) -> str:
    """Extract client IP address from request.

    Handles X-Forwarded-For header when behind trusted proxies.
    The direct connection must come from a trusted proxy for forwarded
    headers to be honored; otherwise the request is treated as a direct
    connection and X-Forwarded-For is ignored to prevent spoofing.
    """
    trusted_proxies = _get_trusted_proxies()
    direct_client_ip = request.client.host if request.client else None

    # Only trust forwarded headers if the direct connection is from a trusted proxy
    if trusted_proxies and direct_client_ip and direct_client_ip in trusted_proxies:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            ips = [ip.strip() for ip in forwarded_for.split(",")]
            # Iterate from right to left (closest proxy first)
            # Skip IPs that are trusted proxies to find the original client
            for ip in reversed(ips):
                if ip not in trusted_proxies:
                    return ip
            # All proxies in the chain are trusted; use the leftmost (original client)
            return ips[0] if ips else direct_client_ip

    # Check X-Real-IP header (commonly set by nginx) - only trust if from a trusted proxy
    if trusted_proxies and direct_client_ip and direct_client_ip in trusted_proxies:
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

    return direct_client_ip if direct_client_ip else "unknown"


def _get_trusted_proxies() -> set[str]:
    """Get set of trusted proxy IPs from configuration."""
    raw = os.getenv("FIRMLOCK_TRUSTED_PROXIES", "")
    return {ip.strip() for ip in raw.split(",") if ip.strip()}


import os


def _get_user_id_from_token(request: Request) -> Optional[int]:
    """Extract user ID from Authorization header if present."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:]  # Remove "Bearer "
    try:
        from app.core.auth import decode_access_token
        payload = decode_access_token(token)
        return int(payload.get("sub", 0))
    except Exception:
        return None


class RateLimitDependency:
    """FastAPI dependency for rate limiting."""

    def __init__(
        self,
        config_getter: Callable[[], RateLimitConfig],
        key_func: Callable[[Request], str],
        prefix: str = "ratelimit",
    ):
        self.config_getter = config_getter
        self.key_func = key_func
        self.prefix = prefix
        self.limiter = get_rate_limiter()

    def __call__(self, request: Request) -> RateLimitInfo:
        identifier = self.key_func(request)
        config = self.config_getter()
        info = self.limiter.check_rate_limit(identifier, config)

        # Add rate limit headers to response (will be added by middleware)
        request.state.rate_limit_info = info

        if not info.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later.",
                headers={"Retry-After": str(info.retry_after or config.window_seconds)},
            )

        return info


def _login_key_func(request: Request) -> str:
    """Key function for login endpoint - uses IP only to avoid enumeration."""
    return f"login:{_get_client_ip(request)}"


def _register_key_func(request: Request) -> str:
    """Key function for register endpoint - uses IP only."""
    return f"register:{_get_client_ip(request)}"


def _scan_key_func(request: Request) -> str:
    """Key function for scan endpoint - uses user ID if authenticated, else IP."""
    user_id = _get_user_id_from_token(request)
    if user_id:
        return f"scan:user:{user_id}"
    return f"scan:ip:{_get_client_ip(request)}"


def _general_key_func(request: Request) -> str:
    """Key function for general API - uses IP."""
    return f"general:{_get_client_ip(request)}"


def _authenticated_key_func(request: Request) -> str:
    """Key function for authenticated endpoints - uses user ID."""
    user_id = _get_user_id_from_token(request)
    if user_id:
        return f"auth:user:{user_id}"
    return f"auth:ip:{_get_client_ip(request)}"


# Rate limit dependencies for specific endpoints
login_rate_limit = RateLimitDependency(
    config_getter=get_login_rate_limit_config,
    key_func=_login_key_func,
    prefix="login",
)

register_rate_limit = RateLimitDependency(
    config_getter=get_register_rate_limit_config,
    key_func=_register_key_func,
    prefix="register",
)

scan_rate_limit = RateLimitDependency(
    config_getter=get_scan_rate_limit_config,
    key_func=_scan_key_func,
    prefix="scan",
)

general_rate_limit = RateLimitDependency(
    config_getter=get_general_rate_limit_config,
    key_func=_general_key_func,
    prefix="general",
)

authenticated_rate_limit = RateLimitDependency(
    config_getter=get_authenticated_rate_limit_config,
    key_func=_authenticated_key_func,
    prefix="auth",
)


def add_rate_limit_headers(request: Request, response) -> None:
    """Add rate limit headers to response."""
    info: Optional[RateLimitInfo] = getattr(request.state, "rate_limit_info", None)
    if info:
        response.headers["X-RateLimit-Limit"] = str(info.limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, info.limit - info.current_count))
        response.headers["X-RateLimit-Reset"] = str(int(time.time() + info.window_seconds))
        if info.retry_after:
            response.headers["Retry-After"] = str(info.retry_after)


import time