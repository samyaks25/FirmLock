"""Application configuration for FirmLock.

Configuration values are kept here, separate from the application logic, so
that they can be changed in one place. Only non-sensitive, public settings
live in this module. No secrets or credentials are stored in source code.
"""

import os
import warnings
from pathlib import Path
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

        backend_dir = Path(__file__).resolve().parents[2]
        self.data_dir: Path = Path(
            os.getenv("FIRMLOCK_DATA_DIR", str(backend_dir / "data"))
        )
        self.data_dir.mkdir(parents=True, exist_ok=True)

        default_db_path = self.data_dir / "firmlock.db"
        # The URL is configurable via env var; no credentials are embedded.
        self.database_url: str = os.getenv(
            "FIRMLOCK_DATABASE_URL", f"sqlite:///{default_db_path.as_posix()}"
        )

        # --- JWT Authentication configuration -----------------------------
        # The JWT signing secret MUST be set via FIRMLOCK_JWT_SECRET in
        # production. A default is provided only for local development.
        # Production deployments MUST use a strong secret (at least 32 bytes).
        self.jwt_secret: str = os.getenv("FIRMLOCK_JWT_SECRET", "dev-secret-change-in-production")

        # Validate JWT secret strength
        if self.environment == "production":
            if not os.getenv("FIRMLOCK_JWT_SECRET"):
                raise ValueError(
                    "FIRMLOCK_JWT_SECRET must be set in production. "
                    "Generate a strong secret with at least 32 characters."
                )
            if len(self.jwt_secret) < 32:
                raise ValueError(
                    "FIRMLOCK_JWT_SECRET must be at least 32 characters in production. "
                    f"Current length: {len(self.jwt_secret)}."
                )
        elif len(self.jwt_secret) < 32:
            # Development: warn but don't block startup
            warnings.warn(
                "FIRMLOCK_JWT_SECRET is less than 32 characters. "
                "Use a strong secret (at least 32 bytes) in production.",
                RuntimeWarning,
                stacklevel=2,
            )
        
        # JWT algorithm - restricted to HS256 for security
        # Algorithm substitution attacks are prevented by explicit validation
        self.jwt_algorithm: str = "HS256"
        
        # Access token lifetime in minutes (default: 15 minutes).
        self.jwt_access_token_expire_minutes: int = int(
            os.getenv("FIRMLOCK_JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "15")
        )
        # JWT issuer and audience for validation.
        self.jwt_issuer: str = os.getenv("FIRMLOCK_JWT_ISSUER", "firmlock")
        self.jwt_audience: str = os.getenv("FIRMLOCK_JWT_AUDIENCE", "firmlock-api")

        # --- Password policy ----------------------------------------------
        self.password_min_length: int = int(
            os.getenv("FIRMLOCK_PASSWORD_MIN_LENGTH", "12")
        )

        # --- Risk scoring configuration ---------------------------------
        # Penalty weights are configurable so that the scoring model can be
        # tuned without code changes. Values are clamped to non-negative
        # integers by the risk configuration dataclass.
        self.score_penalty_critical: int = int(
            os.getenv("FIRMLOCK_SCORE_PENALTY_CRITICAL", "25")
        )
        self.score_penalty_high: int = int(
            os.getenv("FIRMLOCK_SCORE_PENALTY_HIGH", "15")
        )
        self.score_penalty_medium: int = int(
            os.getenv("FIRMLOCK_SCORE_PENALTY_MEDIUM", "8")
        )
        self.score_penalty_low: int = int(
            os.getenv("FIRMLOCK_SCORE_PENALTY_LOW", "3")
        )
        self.score_penalty_info: int = int(
            os.getenv("FIRMLOCK_SCORE_PENALTY_INFO", "0")
        )
        # Minimum percentage of checks that must be conclusively evaluated
        # before a numerical security score is displayed.
        self.risk_min_coverage_percent: float = float(
            os.getenv("FIRMLOCK_RISK_MIN_COVERAGE_PERCENT", "80")
        )


settings = Settings()