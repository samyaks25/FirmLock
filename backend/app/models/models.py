"""SQLAlchemy ORM models for FirmLock."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.connection import Base


def utcnow() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


class BusinessMembership(Base):
    __tablename__ = "business_memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "business_id", name="uq_membership_user_business"),
        CheckConstraint(
            "role IN ('owner', 'admin', 'member')",
            name="ck_membership_role",
        ),
        Index("ix_memberships_user_id", "user_id"),
        Index("ix_memberships_business_id", "business_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    business_id: Mapped[int] = mapped_column(
        ForeignKey("businesses.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="member")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    user: Mapped["User"] = relationship("User", back_populates="memberships")
    business: Mapped["Business"] = relationship("Business", back_populates="memberships")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    memberships: Mapped[List["BusinessMembership"]] = relationship(
        "BusinessMembership", back_populates="user", passive_deletes=True
    )


class Business(Base):
    __tablename__ = "businesses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    industry: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    assets: Mapped[List["Asset"]] = relationship(
        "Asset", back_populates="business", passive_deletes=True
    )
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert", back_populates="business", passive_deletes=True
    )
    memberships: Mapped[List["BusinessMembership"]] = relationship(
        "BusinessMembership", back_populates="business", passive_deletes=True
    )


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("business_id", "domain", name="uq_asset_business_domain"),
        CheckConstraint("status IN ('active', 'paused')", name="ck_asset_status"),
        Index("ix_assets_business_id", "business_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    business_id: Mapped[int] = mapped_column(
        ForeignKey("businesses.id", ondelete="RESTRICT"), nullable=False
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    authorization_confirmed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    business: Mapped["Business"] = relationship("Business", back_populates="assets")
    scans: Mapped[List["Scan"]] = relationship(
        "Scan", back_populates="asset", passive_deletes=True
    )
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert", back_populates="asset", passive_deletes=True
    )


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_scan_status",
        ),
        CheckConstraint(
            "security_score IS NULL OR (security_score >= 0 AND security_score <= 100)",
            name="ck_scan_score_range",
        ),
        Index("ix_scans_asset_id", "asset_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    security_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    # Celery task tracking fields
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    queue_timestamp: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    worker_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="scan", passive_deletes=True
    )
    check_results: Mapped[List["CheckResult"]] = relationship(
        "CheckResult", back_populates="scan", passive_deletes=True
    )
    risk_assessment: Mapped[Optional["RiskAssessment"]] = relationship(
        "RiskAssessment", back_populates="scan", uselist=False, passive_deletes=True
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "check_code", name="uq_finding_scan_check_code"),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_finding_severity",
        ),
        Index("ix_findings_scan_id", "scan_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False
    )
    check_code: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert", back_populates="finding", passive_deletes=True
    )
    check_results: Mapped[List["CheckResult"]] = relationship(
        "CheckResult", back_populates="finding", passive_deletes=True
    )


class CheckResult(Base):
    """Explicit outcome of one scanner check for one scan.

    Findings describe *problems*. A check result records the outcome of every
    expected check, including checks that passed and checks that could not be
    evaluated (``unknown``). This is what lets the risk engine calculate
    coverage and distinguish a security finding from a technical scanning
    failure.
    """

    __tablename__ = "check_results"
    __table_args__ = (
        UniqueConstraint("scan_id", "check_id", name="uq_check_result_scan_check"),
        CheckConstraint(
            "outcome IN ('passed', 'failed', 'unknown', 'not_applicable')",
            name="ck_check_result_outcome",
        ),
        Index("ix_check_results_scan_id", "scan_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False
    )
    check_id: Mapped[str] = mapped_column(String(100), nullable=False)
    module: Mapped[str] = mapped_column(String(30), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    check_code: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    finding_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="check_results")
    finding: Mapped[Optional["Finding"]] = relationship(
        "Finding", back_populates="check_results"
    )


class RiskAssessment(Base):
    """Persisted risk assessment snapshot for a completed scan.

    A snapshot is written once and never overwritten, so historical security
    scores and their explanations remain stable even if the scoring
    configuration changes later.
    """

    __tablename__ = "risk_assessments"
    __table_args__ = (
        UniqueConstraint("scan_id", name="uq_risk_assessment_scan"),
        CheckConstraint(
            "security_score IS NULL OR (security_score >= 0 AND security_score <= 100)",
            name="ck_risk_assessment_score_range",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False
    )
    security_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    grade: Mapped[Optional[str]] = mapped_column(String(2), nullable=True)
    coverage_percent: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    checks_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_evaluated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_unknown: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_not_applicable: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    coverage_sufficient: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    coverage_unknown_checks: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )
    findings_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity_counts: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    deductions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    highest_priority: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    recommendations: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    score_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    unavailable_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    score_source: Mapped[str] = mapped_column(String(20), nullable=False, default="calculated")
    risk_config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="risk_assessment")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_alert_severity",
        ),
        CheckConstraint(
            "status IN ('unread', 'read', 'resolved')",
            name="ck_alert_status",
        ),
        Index("ix_alerts_business_id", "business_id"),
        Index("ix_alerts_asset_id", "asset_id"),
        Index("ix_alerts_finding_id", "finding_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    business_id: Mapped[int] = mapped_column(
        ForeignKey("businesses.id", ondelete="RESTRICT"), nullable=False
    )
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False
    )
    finding_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="unread")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    read_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    business: Mapped["Business"] = relationship("Business", back_populates="alerts")
    asset: Mapped["Asset"] = relationship("Asset", back_populates="alerts")
    finding: Mapped[Optional["Finding"]] = relationship("Finding", back_populates="alerts")
