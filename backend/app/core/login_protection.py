"""Login brute-force protection for FirmLock.

This module tracks failed login attempts and applies temporary throttling
to protect against brute-force attacks while avoiding account enumeration
and permanent lockouts.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

from app.core.config import settings


@dataclass
class LoginAttemptInfo:
    """Information about login attempts for a key."""
    failures: int = 0
    first_failure: float = 0.0
    last_failure: float = 0.0
    locked_until: float = 0.0


@dataclass
class LoginProtectionConfig:
    """Configuration for login brute-force protection."""
    max_failures: int = 5
    lockout_duration_seconds: int = 300  # 5 minutes
    window_seconds: int = 900  # 15 minutes - track failures within this window
    # Never permanently lock - max lockout duration
    max_lockout_duration_seconds: int = 3600  # 1 hour


class LoginBruteForceProtection:
    """Thread-safe login brute-force protection with temporary throttling.

    Key design principles:
    - Tracks failures by IP + email combination (not email alone) to prevent
      one attacker from locking out a legitimate user
    - Uses generic error messages to avoid email enumeration
    - Applies temporary lockouts only (never permanent)
    - Lockout duration increases with repeated attacks but caps at max
    - Does NOT log passwords or tokens
    """

    def __init__(self, config: Optional[LoginProtectionConfig] = None):
        self.config = config or LoginProtectionConfig()
        self._lock = threading.RLock()
        self._attempts: Dict[str, LoginAttemptInfo] = {}

    def _get_key(self, ip: str, email: str) -> str:
        """Generate tracking key from IP and normalized email."""
        # Normalize email to lowercase for consistent tracking
        email_normalized = email.strip().lower() if email else "unknown"
        return f"{ip}:{email_normalized}"

    def _cleanup_expired(self, now: float) -> None:
        """Remove expired entries."""
        expired_keys = [
            key for key, info in self._attempts.items()
            if now - info.last_failure > self.config.window_seconds
            and info.locked_until <= now
        ]
        for key in expired_keys:
            self._attempts.pop(key, None)

    def record_failure(self, ip: str, email: str) -> None:
        """Record a failed login attempt."""
        key = self._get_key(ip, email)
        now = time.time()

        with self._lock:
            self._cleanup_expired(now)
            info = self._attempts.get(key)

            if info is None:
                info = LoginAttemptInfo()
                info.first_failure = now
                self._attempts[key] = info

            info.failures += 1
            info.last_failure = now

            # Calculate lockout - progressive but capped
            if info.failures >= self.config.max_failures:
                # Progressive lockout: base * (failures - max_failures + 1), capped
                excess = info.failures - self.config.max_failures + 1
                lockout = min(
                    self.config.lockout_duration_seconds * excess,
                    self.config.max_lockout_duration_seconds,
                )
                info.locked_until = now + lockout

    def record_success(self, ip: str, email: str) -> None:
        """Record a successful login - resets failure tracking for this key."""
        key = self._get_key(ip, email)
        with self._lock:
            self._attempts.pop(key, None)

    def is_locked(self, ip: str, email: str) -> tuple[bool, Optional[int]]:
        """Check if the given IP/email combination is currently locked out.

        Returns:
            tuple: (is_locked, retry_after_seconds)
        """
        key = self._get_key(ip, email)
        now = time.time()

        with self._lock:
            self._cleanup_expired(now)
            info = self._attempts.get(key)

            if info is None:
                return False, None

            if info.locked_until > now:
                retry_after = int(info.locked_until - now) + 1
                return True, retry_after

            return False, None

    def get_failure_count(self, ip: str, email: str) -> int:
        """Get current failure count for a key (for monitoring/debugging)."""
        key = self._get_key(ip, email)
        now = time.time()

        with self._lock:
            self._cleanup_expired(now)
            info = self._attempts.get(key)
            return info.failures if info else 0

    def reset(self, ip: str, email: str) -> None:
        """Reset tracking for a specific key (useful for testing/admin)."""
        key = self._get_key(ip, email)
        with self._lock:
            self._attempts.pop(key, None)

    def get_stats(self) -> dict:
        """Get protection statistics (for monitoring)."""
        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            locked = sum(1 for info in self._attempts.values() if info.locked_until > now)
            return {
                "tracked_keys": len(self._attempts),
                "currently_locked": locked,
            }


# Global instance
_login_protection = LoginBruteForceProtection()


def get_login_protection() -> LoginBruteForceProtection:
    """Get the global login brute-force protection instance."""
    return _login_protection


def get_login_protection_config() -> LoginProtectionConfig:
    """Get login protection configuration from environment variables."""
    return LoginProtectionConfig(
        max_failures=int(os.getenv("FIRMLOCK_LOGIN_MAX_FAILURES", "5")),
        lockout_duration_seconds=int(os.getenv("FIRMLOCK_LOGIN_LOCKOUT_SECONDS", "300")),
        window_seconds=int(os.getenv("FIRMLOCK_LOGIN_WINDOW_SECONDS", "900")),
        max_lockout_duration_seconds=int(os.getenv("FIRMLOCK_LOGIN_MAX_LOCKOUT_SECONDS", "3600")),
    )


import os