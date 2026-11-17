"""Pydantic schemas for security alerts."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class AlertResponse(BaseModel):
    """A single in-app security alert."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    business_id: int
    asset_id: int
    finding_id: Optional[int] = None
    title: str
    message: str
    severity: str
    status: str
    created_at: datetime
    read_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None


class AlertUpdate(BaseModel):
    """Patch payload for an alert.

    Exactly one of ``read`` or ``resolved`` should be supplied. Setting
    ``resolved: true`` also marks the alert as read.
    """

    read: Optional[bool] = Field(
        default=None,
        description="Mark the alert as read. Ignored when `resolved` is true.",
    )
    resolved: Optional[bool] = Field(
        default=None,
        description="Mark the alert as resolved. Also marks it as read.",
    )


class AlertSummary(BaseModel):
    """Aggregate counts for business alerts."""

    model_config = ConfigDict(from_attributes=True)

    total: int = 0
    unread: int = 0
    read: int = 0
    resolved: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class AlertListResponse(BaseModel):
    """Paginated alert listing."""

    items: List[AlertResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 20
    pages: int = 0


class AlertCountsBySeverity(BaseModel):
    """Counts of alerts grouped by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0