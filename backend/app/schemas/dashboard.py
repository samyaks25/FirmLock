"""Pydantic schemas for the business dashboard API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class DashboardScanSummary(BaseModel):
    scan_id: int
    asset_id: int
    asset_domain: str
    status: str
    security_score: Optional[int] = None
    score_available: bool = False
    unavailable_reason: Optional[str] = None
    risk_level: Optional[str] = None
    grade: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime


class DashboardAlertCounts(BaseModel):
    total_unread: int = 0
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    resolved: int = 0


class CriticalFindingSummary(BaseModel):
    scan_id: int
    asset_id: int
    asset_domain: str
    finding_id: int
    check_code: str
    title: str
    severity: str
    recommendation: str
    detected_at: Optional[datetime] = None


class RecentActivityItem(BaseModel):
    type: str
    occurred_at: Optional[datetime] = None
    title: str
    severity: Optional[str] = None
    asset_id: Optional[int] = None
    asset_domain: Optional[str] = None
    scan_id: Optional[int] = None
    alert_id: Optional[int] = None
    status: Optional[str] = None


class DashboardSecurityOverview(BaseModel):
    average_security_score: Optional[float] = None
    scored_assets: int = 0
    overall_risk_level: str = "unknown"
    latest_completed_scans: int = 0


class DashboardResponse(BaseModel):
    business_id: int
    business_name: str
    total_monitored_websites: int = 0
    active_websites: int = 0
    paused_websites: int = 0
    latest_scan: Optional[DashboardScanSummary] = None
    latest_security_scores: Dict[str, Any] = Field(default_factory=dict)
    critical_security_findings: List[CriticalFindingSummary] = Field(default_factory=list)
    alert_counts: DashboardAlertCounts = Field(default_factory=DashboardAlertCounts)
    recent_security_activity: List[RecentActivityItem] = Field(default_factory=list)
    security_overview: DashboardSecurityOverview = Field(
        default_factory=DashboardSecurityOverview
    )
