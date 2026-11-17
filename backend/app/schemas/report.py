"""Pydantic schemas for security reports."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ReportFinding(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    check_code: str
    title: str
    description: str
    severity: str
    evidence: Optional[str] = None
    recommendation: str
    created_at: datetime


class ReportRiskAssessment(BaseModel):
    security_score: Optional[int] = None
    score_available: bool = False
    unavailable_reason: Optional[str] = None
    risk_level: Optional[str] = None
    grade: Optional[str] = None
    coverage_percent: Optional[float] = None
    checks_total: Optional[int] = None
    checks_evaluated: Optional[int] = None
    checks_unknown: Optional[int] = None
    checks_not_applicable: Optional[int] = None
    coverage_sufficient: Optional[bool] = None
    coverage_unknown_checks: List[str] = Field(default_factory=list)
    findings_by_severity: Dict[str, Any] = Field(default_factory=dict)
    findings_total: int = 0
    highest_priority_issues: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    score_source: Optional[str] = None


class ScanReportResponse(BaseModel):
    scan_id: int
    scan_status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    business_id: int
    business_name: str
    asset_id: int
    asset_domain: str
    security_score: Optional[int] = None
    score_available: bool = False
    unavailable_reason: Optional[str] = None
    risk_assessment: Optional[ReportRiskAssessment] = None
    scan_coverage: Optional[Dict[str, Any]] = None
    findings_total: int = 0
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings: List[ReportFinding] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class AssetReportHistoryEntry(BaseModel):
    scan_id: int
    scan_status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    security_score: Optional[int] = None
    score_available: bool = False
    unavailable_reason: Optional[str] = None
    risk_level: Optional[str] = None
    grade: Optional[str] = None
    coverage_percent: Optional[float] = None
    findings_total: int = 0
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)


class AssetReportsResponse(BaseModel):
    asset_id: int
    asset_domain: str
    business_id: int
    business_name: str
    scans: List[AssetReportHistoryEntry] = Field(default_factory=list)
