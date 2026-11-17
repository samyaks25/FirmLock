"""Rate limiting utilities for FirmLock.

This module provides configurable rate limiting for API endpoints.
Uses an in-memory implementation suitable for local development and single-process deployments.

MULTI-PROCESS LIMITATIONS:
- In-memory storage is NOT shared across processes.
- In multi-worker deployments (e.g., gunicorn with multiple workers), each worker
  maintains its own rate limit counters, effectively multiplying the limits.
- For production multi-process deployments, replace with a shared backend
  (Redis, Memcached, or database-backed implementation).
- The interface is designed to allow swapping the storage backend without
  changing the rate limiter API.
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from app.core.config import settings


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit rule."""
    requests: int
    window_seconds: int
    key_prefix: str = "ratelimit"


@dataclass
class RateLimitInfo:
    """Result of a rate limit check."""
    allowed: bool
    current_count: int
    limit: int
    window_seconds: int
    retry_after: Optional[int] = None


class InMemoryRateLimiter:
    """Thread-safe in-memory rate limiter using sliding window.

    NOTE: This implementation is suitable for local development and single-process
    deployments only. For multi-process production deployments, use a shared
    backend like Redis.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._windows: Dict[str, list[float]] = {}

    def _get_window_key(self, prefix: str, identifier: str) -> str:
        return f"{prefix}:{identifier}"

    def _cleanup_expired(self, key: str, window_seconds: int, now: float) -> None:
        """Remove timestamps older than the window."""
        cutoff = now - window_seconds
        timestamps = self._windows.get(key, [])
        # Keep only timestamps within the window
        self._windows[key] = [ts for ts in timestamps if ts > cutoff]
        if not self._windows[key]:
            self._windows.pop(key, None)

    def check_rate_limit(
        self,
        identifier: str,
        config: RateLimitConfig,
    ) -> RateLimitInfo:
        """Check if the request is within rate limits.

        Args:
            identifier: Unique identifier for the client (IP, user ID, etc.)
            config: Rate limit configuration

        Returns:
            RateLimitInfo with allowed status and metadata
        """
        key = self._get_window_key(config.key_prefix, identifier)
        now = time.time()

        with self._lock:
            self._cleanup_expired(key, config.window_seconds, now)
            timestamps = self._windows.get(key, [])
            current_count = len(timestamps)

            if current_count >= config.requests:
                # Rate limited - calculate retry-after
                oldest = min(timestamps) if timestamps else now
                retry_after = int(oldest + config.window_seconds - now) + 1
                return RateLimitInfo(
                    allowed=False,
                    current_count=current_count,
                    limit=config.requests,
                    window_seconds=config.window_seconds,
                    retry_after=max(1, retry_after),
                )

            # Allow request - add timestamp
            timestamps.append(now)
            self._windows[key] = timestamps

            return RateLimitInfo(
                allowed=True,
                current_count=current_count + 1,
                limit=config.requests,
                window_seconds=config.window_seconds,
                retry_after=None,
            )

    def reset(self, identifier: str, prefix: str = "ratelimit") -> None:
        """Reset rate limit for an identifier (useful for testing)."""
        key = self._get_window_key(prefix, identifier)
        with self._lock:
            self._windows.pop(key, None)


# Global rate limiter instance
_rate_limiter = InMemoryRateLimiter()


def get_rate_limiter() -> InMemoryRateLimiter:
    """Get the global rate limiter instance."""
    return _rate_limiter


def _parse_rate_limit_env(var_name: str, default: str) -> RateLimitConfig:
    """Parse rate limit configuration from environment variable.

    Format: "requests:window_seconds" (e.g., "10:60" = 10 requests per 60 seconds)
    """
    raw = os.getenv(var_name, default)
    try:
        parts = raw.split(":")
        requests = int(parts[0])
        window_seconds = int(parts[1]) if len(parts) > 1 else 60
        return RateLimitConfig(requests=requests, window_seconds=window_seconds)
    except (ValueError, IndexError):
        # Fall back to a sensible default
        return RateLimitConfig(requests=100, window_seconds=60)


import os


def get_login_rate_limit_config() -> RateLimitConfig:
    """Get rate limit config for login endpoint."""
    return _parse_rate_limit_env(
        "FIRMLOCK_RATE_LIMIT_LOGIN",
        "5:300",  # 5 requests per 5 minutes by default
    )


def get_register_rate_limit_config() -> RateLimitConfig:
    """Get rate limit config for registration endpoint."""
    return _parse_rate_limit_env(
        "FIRMLOCK_RATE_LIMIT_REGISTER",
        "3:3600",  # 3 requests per hour by default
    )


def get_scan_rate_limit_config() -> RateLimitConfig:
    """Get rate limit config for scan initiation endpoint."""
    return _parse_rate_limit_env(
        "FIRMLOCK_RATE_LIMIT_SCAN",
        "10:3600",  # 10 requests per hour by default
    )


def get_general_rate_limit_config() -> RateLimitConfig:
    """Get rate limit config for general API endpoints."""
    return _parse_rate_limit_env(
        "FIRMLOCK_RATE_LIMIT_GENERAL",
        "100:60",  # 100 requests per minute by default
    )


def get_authenticated_rate_limit_config() -> RateLimitConfig:
    """Get rate limit config for authenticated API endpoints (per user)."""
    return _parse_rate_limit_env(
        "FIRMLOCK_RATE_LIMIT_AUTHENTICATED",
        "200:60",  # 200 requests per minute by default
    )