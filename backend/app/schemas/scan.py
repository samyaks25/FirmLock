"""Pydantic schemas for scan resources."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class FindingResponse(BaseModel):
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


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    status: str
    security_score: Optional[int] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    celery_task_id: Optional[str] = None
    queue_timestamp: Optional[datetime] = None
    attempt_count: int = 0
    worker_metadata: Optional[dict] = None
    findings: List[FindingResponse] = Field(default_factory=list)


class ScanAcceptedResponse(BaseModel):
    """Response returned when a scan is queued for background execution."""

    scan_id: int
    asset_id: int
    status: str


class SeveritySummary(BaseModel):
    """Counts of findings by severity for a scan."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0