"""Pydantic schemas for risk assessments."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class SeverityCounts(BaseModel):
    """Number of findings at each severity, including informational ones."""

    model_config = ConfigDict(from_attributes=True)

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class CoverageInfo(BaseModel):
    """How much of the scan was conclusively evaluated."""

    model_config = ConfigDict(from_attributes=True)

    percentage: float
    evaluated: int
    total: int
    unknown: int
    not_applicable: int
    threshold_percent: float
    sufficient: bool
    unknown_checks: List[str] = Field(default_factory=list)


class ScoreWeights(BaseModel):
    """Scoring weights used for this assessment."""

    model_config = ConfigDict(from_attributes=True)

    critical: int
    high: int
    medium: int
    low: int
    info: int
    minimum_score: int
    maximum_score: int


class ScoreDeduction(BaseModel):
    """A single, explained score deduction."""

    model_config = ConfigDict(from_attributes=True)

    check_code: str
    title: str
    severity: str
    penalty: int
    applied_penalty: int
    score_before: int
    score_after: int
    reason: str
    recommendation: str


class PriorityIssue(BaseModel):
    """A high-priority finding requiring attention."""

    model_config = ConfigDict(from_attributes=True)

    rank: int
    check_code: str
    title: str
    severity: str
    penalty: int
    recommendation: str


class RiskAssessmentResponse(BaseModel):
    """Risk assessment for a single scan."""

    model_config = ConfigDict(from_attributes=True)

    scan_id: int
    asset_id: int
    scan_status: str
    scan_started_at: Optional[datetime] = None
    scan_completed_at: Optional[datetime] = None
    security_score: Optional[int] = None
    score_available: bool = False
    unavailable_reason: Optional[str] = None
    base_score: int = 100
    total_penalty: int = 0
    risk_level: Optional[str] = None
    grade: Optional[str] = None
    coverage: CoverageInfo
    findings_by_severity: SeverityCounts
    findings_total: int = 0
    deductions: List[ScoreDeduction] = Field(default_factory=list)
    highest_priority_issues: List[PriorityIssue] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    score_weights: ScoreWeights
    score_source: str = "calculated"
    generated_at: datetime


class RiskHistoryEntry(BaseModel):
    """Compact assessment summary used for historical comparison."""

    model_config = ConfigDict(from_attributes=True)

    scan_id: int
    completed_at: Optional[datetime] = None
    security_score: Optional[int] = None
    score_available: bool = False
    risk_level: Optional[str] = None
    grade: Optional[str] = None
    coverage_percent: float = 0.0
    findings_total: int = 0
    severity_counts: SeverityCounts
    unavailable_reason: Optional[str] = None
    score_source: str = "calculated"


class AssetRiskResponse(RiskAssessmentResponse):
    """Latest completed scan's risk assessment for an asset."""

    asset_domain: str
    previous_assessment: Optional[RiskHistoryEntry] = None
    score_change: Optional[int] = None