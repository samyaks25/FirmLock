"""Risk scoring configuration.

The scoring model is deliberately simple and auditable: a scan starts at 100
and each confirmed finding deducts a fixed, per-severity penalty. All weights
and the coverage threshold are configurable so the model can be tuned without
changing business logic.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import settings


@dataclass(frozen=True)
class RiskConfig:
    """Weights and thresholds used by the risk assessment engine.

    Attributes:
        penalty_critical: Points deducted per critical finding.
        penalty_high: Points deducted per high finding.
        penalty_medium: Points deducted per medium finding.
        penalty_low: Points deducted per low finding.
        penalty_info: Points deducted per informational finding (normally 0).
        minimum_score: Lowest score the engine will report.
        maximum_score: Score a scan starts with before deductions.
        minimum_coverage_percent: Minimum conclusive scan coverage required
            before a numerical score is displayed.
    """

    penalty_critical: int = 25
    penalty_high: int = 15
    penalty_medium: int = 8
    penalty_low: int = 3
    penalty_info: int = 0
    minimum_score: int = 0
    maximum_score: int = 100
    minimum_coverage_percent: float = 80.0

    def __post_init__(self) -> None:
        # Clamp configured values so a bad environment variable cannot create
        # negative penalties or an impossible score range.
        object.__setattr__(self, "penalty_critical", max(0, int(self.penalty_critical)))
        object.__setattr__(self, "penalty_high", max(0, int(self.penalty_high)))
        object.__setattr__(self, "penalty_medium", max(0, int(self.penalty_medium)))
        object.__setattr__(self, "penalty_low", max(0, int(self.penalty_low)))
        object.__setattr__(self, "penalty_info", max(0, int(self.penalty_info)))
        object.__setattr__(self, "minimum_score", max(0, int(self.minimum_score)))
        object.__setattr__(
            self, "maximum_score", min(100, max(0, int(self.maximum_score)))
        )
        object.__setattr__(
            self,
            "minimum_coverage_percent",
            min(100.0, max(0.0, float(self.minimum_coverage_percent))),
        )
        if self.minimum_score > self.maximum_score:
            object.__setattr__(self, "minimum_score", self.maximum_score)

    def penalty_for(self, severity: str) -> int:
        """Return the penalty for ``severity`` (0 for unknown severities)."""
        normalized = (severity or "").strip().lower()
        if normalized == "critical":
            return self.penalty_critical
        if normalized == "high":
            return self.penalty_high
        if normalized == "medium":
            return self.penalty_medium
        if normalized == "low":
            return self.penalty_low
        if normalized == "info":
            return self.penalty_info
        # Unknown severities are never penalised.
        return 0

    def as_dict(self) -> dict[str, int | float]:
        """Return the weights as a JSON-friendly dictionary."""
        return {
            "critical": self.penalty_critical,
            "high": self.penalty_high,
            "medium": self.penalty_medium,
            "low": self.penalty_low,
            "info": self.penalty_info,
            "minimum_score": self.minimum_score,
            "maximum_score": self.maximum_score,
            "minimum_coverage_percent": self.minimum_coverage_percent,
        }


def load_risk_config() -> RiskConfig:
    """Build a :class:`RiskConfig` from application settings."""
    return RiskConfig(
        penalty_critical=settings.score_penalty_critical,
        penalty_high=settings.score_penalty_high,
        penalty_medium=settings.score_penalty_medium,
        penalty_low=settings.score_penalty_low,
        penalty_info=settings.score_penalty_info,
        minimum_coverage_percent=settings.risk_min_coverage_percent,
    )


DEFAULT_RISK_CONFIG = load_risk_config()