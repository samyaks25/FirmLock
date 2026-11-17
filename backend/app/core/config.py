"""Application configuration for FirmLock.

Configuration values are kept here, separate from the application logic, so
that they can be changed in one place. Only non-sensitive, public settings
live in this module. No secrets or credentials are stored in source code.
"""

import os
from typing import List


def _parse_origins(raw_value: str) -> List[str]:
    """Split a comma separated string of origins into a clean list."""
    return [origin.strip() for origin in raw_value.split(",") if origin.strip()]


class Settings:
    """Runtime settings for the FirmLock API.

    Every value can be overridden with an environment variable, which keeps
    the code free of hardcoded, environment-specific configuration.
    """

    def __init__(self) -> None:
        self.app_name: str = os.getenv("FIRMLOCK_APP_NAME", "FirmLock API")
        self.api_version: str = os.getenv("FIRMLOCK_API_VERSION", "0.1.0")
        self.environment: str = os.getenv("FIRMLOCK_ENV", "development")

        # Local frontend development origins (Vite dev server defaults).
        default_origins = "http://localhost:5173,http://127.0.0.1:5173"
        self.cors_origins: List[str] = _parse_origins(
            os.getenv("FIRMLOCK_CORS_ORIGINS", default_origins)
        )


settings = Settings()