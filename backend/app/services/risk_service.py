"""Risk assessment and security scoring engine.

The engine turns persisted scan findings into an explainable risk assessment:

* every confirmed finding is classified by severity;
* a numerical score starts at 100 and deducts configurable per-severity
  penalties, with a hard floor;
* duplicate findings never deduct twice;
* informational findings never deduct;
* unknown check outcomes never deduct and are never treated as secure;
* a numerical score is only produced when the scan completed and enough checks
  were conclusively evaluated (coverage threshold);
* each assessment is persisted as an immutable snapshot so historical scores
  are preserved.

The public entry points are :func:`get_scan_risk`, :func:`get_asset_risk` and
:func:`list_asset_risk_history`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.models import CheckResult, Finding, RiskAssessment, Scan
from app.schemas.risk import (
    AssetRiskResponse,
    CoverageInfo,
    PriorityIssue,
    RiskAssessmentResponse,
    RiskHistoryEntry,
    ScoreDeduction,
    ScoreWeights,
    SeverityCounts,
)
from app.services.risk_config import DEFAULT_RISK_CONFIG, RiskConfig
from app.services.scanner.check_catalog import (
    ALL_GROUPS,
    MODULE_NAMES,
    OUTCOME_FAILED,
    OUTCOME_NOT_APPLICABLE,
    OUTCOME_PASSED,
    UNKNOWN_CHECK_CODES,
    derive_outcomes,
    module_for_code,
    severity_rank,
)
from app.services.scanner.config import CheckCodes

logger = logging.getLogger("firmlock.risk")

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

_RISK_LEVELS = (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW)

# Target-validation findings mean the scanner modules never ran. Legacy scans
# that only persisted such a finding must not be treated as fully covered.
_TARGET_FAILURE_CODES = frozenset(
    {
        CheckCodes.TARGET_INVALID,
        CheckCodes.TARGET_SSRF_REJECTED,
        CheckCodes.TARGET_DNS_FAILED,
    }
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------
@dataclass
class Coverage:
    """Conclusive coverage of the scan's expected checks."""

    percentage: float
    evaluated: int
    total: int
    unknown: int
    not_applicable: int
    threshold_percent: float
    sufficient: bool
    unknown_checks: List[str] = field(default_factory=list)


@dataclass
class Deduction:
    """One explained deduction from the starting score."""

    check_code: str
    title: str
    severity: str
    penalty: int
    applied_penalty: int
    score_before: int
    score_after: int
    reason: str
    recommendation: str

    def as_dict(self) -> dict:
        return {
            "check_code": self.check_code,
            "title": self.title,
            "severity": self.severity,
            "penalty": self.penalty,
            "applied_penalty": self.applied_penalty,
            "score_before": self.score_before,
            "score_after": self.score_after,
            "reason": self.reason,
            "recommendation": self.recommendation,
        }


@dataclass
class Snapshot:
    """A complete, persistable risk assessment snapshot."""

    security_score: Optional[int]
    score_available: bool
    unavailable_reason: Optional[str]
    risk_level: str
    grade: Optional[str]
    coverage: Coverage
    findings_total: int
    severity_counts: dict
    deductions: List[Deduction]
    highest_priority: List[dict]
    recommendations: List[str]
    score_source: str = "calculated"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _severity_counts(findings: Sequence[Finding]) -> dict:
    counts = {
        SEVERITY_CRITICAL: 0,
        SEVERITY_HIGH: 0,
        SEVERITY_MEDIUM: 0,
        SEVERITY_LOW: 0,
        SEVERITY_INFO: 0,
    }
    for finding in findings:
        severity = (finding.severity or "").strip().lower()
        if severity in counts:
            counts[severity] += 1
    counts["total"] = len(findings)
    return counts


def _dedupe_findings(findings: Sequence[Finding]) -> List[Finding]:
    """Keep one finding per check code, preferring the most severe.

    The database enforces uniqueness on ``(scan_id, check_code)`` for new
    scans, but older or externally-created data may contain duplicates. This
    function guarantees that a check code can never be penalised twice.
    """
    best: Dict[str, Finding] = {}
    order: List[str] = []
    for finding in findings:
        code = finding.check_code
        if code not in best:
            best[code] = finding
            order.append(code)
        elif severity_rank(finding.severity) > severity_rank(best[code].severity):
            best[code] = finding
    return [best[code] for code in order]


def _assessable_findings(findings: Sequence[Finding]) -> List[Finding]:
    """Return security findings, excluding technical-failure markers.

    Findings such as ``DNS_TIMEOUT`` or ``HEADERS_UNAVAILABLE`` are recorded so
    the scan can report unknown coverage, but they are not security findings
    and must never be penalised.
    """
    return [
        finding
        for finding in findings
        if finding.check_code not in UNKNOWN_CHECK_CODES
    ]


def _grade(score: Optional[int]) -> Optional[str]:
    if score is None:
        return None
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _risk_level(findings: Sequence[Finding]) -> str:
    severities = {
        (finding.severity or "").strip().lower()
        for finding in findings
        if severity_rank(finding.severity) > severity_rank(SEVERITY_INFO)
    }
    for level in _RISK_LEVELS:
        if level in severities:
            return level
    return "minimal"


def _calculate_deductions(
    findings: Sequence[Finding], config: RiskConfig
) -> tuple[List[Deduction], int]:
    """Apply penalties in severity order, explaining each deduction."""
    running = config.maximum_score
    deductions: List[Deduction] = []
    ordered = sorted(
        findings,
        key=lambda finding: (
            -severity_rank(finding.severity),
            -config.penalty_for(finding.severity),
            finding.check_code,
        ),
    )

    for finding in ordered:
        penalty = config.penalty_for(finding.severity)
        if penalty <= 0:
            continue

        before = running
        applied = min(penalty, max(0, before - config.minimum_score))
        after = before - applied
        running = after

        if applied == penalty:
            reason = (
                f"{finding.severity.capitalize()} finding '{finding.title}' "
                f"deducts {penalty} points."
            )
        elif applied > 0:
            reason = (
                f"{finding.severity.capitalize()} finding '{finding.title}' "
                f"deducts {applied} of its {penalty}-point weight before reaching "
                f"the minimum score of {config.minimum_score}."
            )
        else:
            reason = (
                f"{finding.severity.capitalize()} finding '{finding.title}' has a "
                f"{penalty}-point weight, but the score is already at the minimum "
                f"of {config.minimum_score}."
            )

        deductions.append(
            Deduction(
                check_code=finding.check_code,
                title=finding.title,
                severity=(finding.severity or "").strip().lower(),
                penalty=penalty,
                applied_penalty=applied,
                score_before=before,
                score_after=after,
                reason=reason,
                recommendation=finding.recommendation,
            )
        )

    return deductions, running


def _highest_priority(findings: Sequence[Finding], config: RiskConfig) -> List[dict]:
    failed = [finding for finding in findings if severity_rank(finding.severity) > 0]
    failed.sort(
        key=lambda finding: (
            -severity_rank(finding.severity),
            -config.penalty_for(finding.severity),
            finding.check_code,
        )
    )
    return [
        {
            "rank": index,
            "check_code": finding.check_code,
            "title": finding.title,
            "severity": (finding.severity or "").strip().lower(),
            "penalty": config.penalty_for(finding.severity),
            "recommendation": finding.recommendation,
        }
        for index, finding in enumerate(failed[:5], start=1)
    ]


def _recommendations(findings: Sequence[Finding], config: RiskConfig) -> List[str]:
    ordered = sorted(
        findings,
        key=lambda finding: (
            -severity_rank(finding.severity),
            -config.penalty_for(finding.severity),
            finding.check_code,
        ),
    )
    recommendations: List[str] = []
    seen = set()
    for finding in ordered:
        if severity_rank(finding.severity) <= 0:
            continue
        recommendation = (finding.recommendation or "").strip()
        if not recommendation or recommendation in seen:
            continue
        seen.add(recommendation)
        recommendations.append(recommendation)
        if len(recommendations) >= 10:
            break
    return recommendations


def _compute_coverage(
    check_results: Sequence[CheckResult], config: RiskConfig
) -> Coverage:
    """Calculate conclusive coverage across all expected check groups.

    Unknown and not-applicable checks are excluded from the numerator but
    remain in the denominator, so a scan with technical failures cannot
    silently report full coverage.
    """
    by_id = {result.check_id: result for result in check_results}
    total = len(ALL_GROUPS)
    evaluated = 0
    unknown = 0
    not_applicable = 0
    unknown_checks: List[str] = []

    for group in ALL_GROUPS:
        result = by_id.get(group.check_id)
        if result is None:
            unknown += 1
            unknown_checks.append(group.check_id)
            continue
        if result.outcome in (OUTCOME_PASSED, OUTCOME_FAILED):
            evaluated += 1
        elif result.outcome == OUTCOME_NOT_APPLICABLE:
            not_applicable += 1
        else:
            unknown += 1
            unknown_checks.append(group.check_id)

    denominator = total - not_applicable
    percentage = round((evaluated / denominator) * 100, 1) if denominator > 0 else 0.0
    sufficient = denominator > 0 and percentage >= config.minimum_coverage_percent

    return Coverage(
        percentage=percentage,
        evaluated=evaluated,
        total=total,
        unknown=unknown,
        not_applicable=not_applicable,
        threshold_percent=config.minimum_coverage_percent,
        sufficient=sufficient,
        unknown_checks=unknown_checks,
    )


def _ensure_check_results(
    db: Session, scan: Scan, persist: bool = True
) -> List[CheckResult]:
    """Return persisted check results, backfilling them for legacy scans.

    Scans created before check-result persistence still have findings. For a
    completed legacy scan, outcomes are derived from those findings so the
    historical scan can still be assessed. New scans always have explicit
    results written by the scan manager.
    """
    existing = list(
        db.scalars(select(CheckResult).where(CheckResult.scan_id == scan.id)).all()
    )
    if existing:
        return existing

    if scan.status != "completed":
        return []

    findings_by_module: Dict[str, List[Finding]] = {name: [] for name in MODULE_NAMES}
    findings_by_code: Dict[str, Finding] = {}
    for finding in scan.findings:
        findings_by_code[finding.check_code] = finding
        module = module_for_code(finding.check_code)
        if module is not None:
            findings_by_module[module].append(finding)

    target_failure = any(
        finding.check_code in _TARGET_FAILURE_CODES for finding in scan.findings
    )
    modules_ran = any(findings_by_module.values())

    created: List[CheckResult] = []
    for module in MODULE_NAMES:
        if target_failure and not modules_ran:
            outcomes = derive_outcomes(
                module,
                [],
                error="Target validation failed; scanner modules were not executed.",
            )
        else:
            outcomes = derive_outcomes(module, findings_by_module[module])
        for outcome in outcomes:
            linked = (
                findings_by_code.get(outcome.check_code)
                if outcome.check_code is not None
                else None
            )
            result = CheckResult(
                scan_id=scan.id,
                check_id=outcome.check_id,
                module=outcome.module,
                outcome=outcome.outcome,
                severity=outcome.severity,
                check_code=outcome.check_code,
                detail=outcome.detail,
                finding_id=linked.id if linked is not None else None,
            )
            if persist:
                db.add(result)
            created.append(result)

    if persist and created:
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return list(
                db.scalars(select(CheckResult).where(CheckResult.scan_id == scan.id)).all()
            )

    return created


def _build_snapshot(
    db: Session, scan: Scan, config: RiskConfig
) -> Snapshot:
    findings = _dedupe_findings(_assessable_findings(list(scan.findings)))
    check_results = _ensure_check_results(db, scan)
    coverage = _compute_coverage(check_results, config)
    counts = _severity_counts(findings)
    deductions, final_score = _calculate_deductions(findings, config)

    score_available = scan.status == "completed" and coverage.sufficient
    security_score = final_score if score_available else None

    if scan.status != "completed":
        unavailable_reason = (
            f"Scan status is '{scan.status}'. A risk assessment is only "
            "available for completed scans."
        )
    elif not coverage.sufficient:
        unavailable_reason = (
            f"Scan coverage {coverage.percentage:.1f}% is below the required "
            f"{config.minimum_coverage_percent:.1f}%."
        )
    else:
        unavailable_reason = None

    return Snapshot(
        security_score=security_score,
        score_available=score_available,
        unavailable_reason=unavailable_reason,
        risk_level=_risk_level(findings),
        grade=_grade(security_score),
        coverage=coverage,
        findings_total=len(findings),
        severity_counts=counts,
        deductions=deductions,
        highest_priority=_highest_priority(findings, config),
        recommendations=_recommendations(findings, config),
    )


def _snapshot_to_assessment(
    scan: Scan, snapshot: Snapshot, config: RiskConfig, *, score: Optional[int], source: str
) -> RiskAssessment:
    return RiskAssessment(
        scan_id=scan.id,
        security_score=score,
        risk_level=snapshot.risk_level,
        grade=_grade(score) if score is not None else snapshot.grade,
        coverage_percent=snapshot.coverage.percentage,
        checks_total=snapshot.coverage.total,
        checks_evaluated=snapshot.coverage.evaluated,
        checks_unknown=snapshot.coverage.unknown,
        checks_not_applicable=snapshot.coverage.not_applicable,
        coverage_sufficient=snapshot.coverage.sufficient,
        coverage_unknown_checks=list(snapshot.coverage.unknown_checks),
        findings_total=snapshot.findings_total,
        severity_counts=snapshot.severity_counts,
        deductions=[deduction.as_dict() for deduction in snapshot.deductions],
        highest_priority=snapshot.highest_priority,
        recommendations=snapshot.recommendations,
        score_available=snapshot.score_available,
        unavailable_reason=snapshot.unavailable_reason,
        score_source=source,
        risk_config=config.as_dict(),
        created_at=utcnow(),
    )


def get_or_create_assessment(
    db: Session, scan: Scan, config: RiskConfig = DEFAULT_RISK_CONFIG
) -> RiskAssessment:
    """Return the persisted assessment for ``scan``, creating it once.

    Existing assessments are never recomputed or overwritten. This is what
    preserves historical security scores when the scoring configuration or the
    underlying findings change later.
    """
    existing = db.scalar(
        select(RiskAssessment).where(RiskAssessment.scan_id == scan.id).limit(1)
    )
    if existing is not None:
        return existing

    snapshot = _build_snapshot(db, scan, config)

    # Non-completed scans are assessed on demand but never persisted: their
    # result is explicitly marked unavailable.
    if scan.status != "completed":
        return _snapshot_to_assessment(
            scan,
            snapshot,
            config,
            score=snapshot.security_score,
            source=snapshot.score_source,
        )

    stored_score = scan.security_score
    if stored_score is not None:
        # A previously persisted score is historical data and must not be
        # overwritten, even if the current configuration would produce a
        # different number.
        assessment = _snapshot_to_assessment(
            scan,
            snapshot,
            config,
            score=stored_score,
            source="stored",
        )
        assessment.score_available = True
        assessment.unavailable_reason = None
    else:
        assessment = _snapshot_to_assessment(
            scan,
            snapshot,
            config,
            score=snapshot.security_score,
            source=snapshot.score_source,
        )
        if snapshot.security_score is not None:
            scan.security_score = snapshot.security_score

    db.add(assessment)
    try:
        db.commit()
    except IntegrityError:
        # Another request created the snapshot concurrently.
        db.rollback()
        existing = db.scalar(
            select(RiskAssessment).where(RiskAssessment.scan_id == scan.id).limit(1)
        )
        if existing is not None:
            return existing
        raise
    db.refresh(assessment)
    return assessment


def assess_and_store(
    db: Session, scan: Scan, config: RiskConfig = DEFAULT_RISK_CONFIG
) -> Optional[RiskAssessment]:
    """Assess a just-completed scan, logging (not raising) on failure."""
    try:
        return get_or_create_assessment(db, scan, config)
    except Exception:  # pragma: no cover - defensive
        logger.exception("Could not assess scan %s.", scan.id)
        try:
            db.rollback()
        except Exception:
            logger.exception("Could not roll back after assessment failure.")
        return None


def _severity_counts_model(counts: dict) -> SeverityCounts:
    return SeverityCounts(
        critical=int(counts.get(SEVERITY_CRITICAL, 0)),
        high=int(counts.get(SEVERITY_HIGH, 0)),
        medium=int(counts.get(SEVERITY_MEDIUM, 0)),
        low=int(counts.get(SEVERITY_LOW, 0)),
        info=int(counts.get(SEVERITY_INFO, 0)),
        total=int(counts.get("total", 0)),
    )


def _config_from_assessment(
    assessment: RiskAssessment, fallback: RiskConfig
) -> RiskConfig:
    """Return the scoring configuration captured with an assessment.

    Historical assessments must report the weights and threshold that were in
    effect when they were created, not whatever the process is configured with
    today.
    """
    stored = assessment.risk_config or {}
    if not stored:
        return fallback
    try:
        return RiskConfig(
            penalty_critical=int(stored.get("critical", fallback.penalty_critical)),
            penalty_high=int(stored.get("high", fallback.penalty_high)),
            penalty_medium=int(stored.get("medium", fallback.penalty_medium)),
            penalty_low=int(stored.get("low", fallback.penalty_low)),
            penalty_info=int(stored.get("info", fallback.penalty_info)),
            minimum_score=int(stored.get("minimum_score", fallback.minimum_score)),
            maximum_score=int(stored.get("maximum_score", fallback.maximum_score)),
            minimum_coverage_percent=float(
                stored.get(
                    "minimum_coverage_percent", fallback.minimum_coverage_percent
                )
            ),
        )
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return fallback


def _response_from_assessment(
    scan: Scan, assessment: RiskAssessment, config: RiskConfig
) -> RiskAssessmentResponse:
    config = _config_from_assessment(assessment, config)
    counts = assessment.severity_counts or {}
    deductions = [ScoreDeduction(**item) for item in (assessment.deductions or [])]
    total_penalty = sum(item.applied_penalty for item in deductions)
    weights = config.as_dict()

    return RiskAssessmentResponse(
        scan_id=scan.id,
        asset_id=scan.asset_id,
        scan_status=scan.status,
        scan_started_at=scan.started_at,
        scan_completed_at=scan.completed_at,
        security_score=assessment.security_score,
        score_available=assessment.score_available,
        unavailable_reason=assessment.unavailable_reason,
        base_score=config.maximum_score,
        total_penalty=total_penalty,
        risk_level=assessment.risk_level,
        grade=assessment.grade,
        coverage=CoverageInfo(
            percentage=assessment.coverage_percent,
            evaluated=assessment.checks_evaluated,
            total=assessment.checks_total,
            unknown=assessment.checks_unknown,
            not_applicable=assessment.checks_not_applicable,
            threshold_percent=config.minimum_coverage_percent,
            sufficient=assessment.coverage_sufficient,
            unknown_checks=list(assessment.coverage_unknown_checks or []),
        ),
        findings_by_severity=_severity_counts_model(counts),
        findings_total=assessment.findings_total,
        deductions=deductions,
        highest_priority_issues=[
            PriorityIssue(**item) for item in (assessment.highest_priority or [])
        ],
        recommended_actions=list(assessment.recommendations or []),
        score_weights=ScoreWeights(
            critical=int(weights["critical"]),
            high=int(weights["high"]),
            medium=int(weights["medium"]),
            low=int(weights["low"]),
            info=int(weights["info"]),
            minimum_score=int(weights["minimum_score"]),
            maximum_score=int(weights["maximum_score"]),
        ),
        score_source=assessment.score_source,
        generated_at=assessment.created_at or utcnow(),
    )


def get_scan_risk(
    db: Session, scan: Scan, config: RiskConfig = DEFAULT_RISK_CONFIG
) -> RiskAssessmentResponse:
    """Return the risk assessment for ``scan``."""
    assessment = get_or_create_assessment(db, scan, config)
    return _response_from_assessment(scan, assessment, config)


def _history_entry(scan: Scan, assessment: RiskAssessment) -> RiskHistoryEntry:
    return RiskHistoryEntry(
        scan_id=scan.id,
        completed_at=scan.completed_at,
        security_score=assessment.security_score,
        score_available=assessment.score_available,
        risk_level=assessment.risk_level,
        grade=assessment.grade,
        coverage_percent=assessment.coverage_percent,
        findings_total=assessment.findings_total,
        severity_counts=_severity_counts_model(assessment.severity_counts or {}),
        unavailable_reason=assessment.unavailable_reason,
        score_source=assessment.score_source,
    )


def _latest_completed_scan(db: Session, asset_id: int, *, exclude_scan_id: Optional[int] = None):
    stmt = (
        select(Scan)
        .where(Scan.asset_id == asset_id, Scan.status == "completed")
        .order_by(Scan.completed_at.desc(), Scan.id.desc())
    )
    if exclude_scan_id is not None:
        stmt = stmt.where(Scan.id != exclude_scan_id)
    return db.scalars(stmt.limit(1)).first()


def get_asset_risk(
    db: Session, asset, config: RiskConfig = DEFAULT_RISK_CONFIG
) -> Optional[AssetRiskResponse]:
    """Return the latest completed scan's assessment for ``asset``.

    Returns ``None`` when the asset has no completed scan.
    """
    latest = _latest_completed_scan(db, asset.id)
    if latest is None:
        return None

    response = get_scan_risk(db, latest, config)
    previous_scan = _latest_completed_scan(db, asset.id, exclude_scan_id=latest.id)
    previous_entry: Optional[RiskHistoryEntry] = None
    score_change: Optional[int] = None

    if previous_scan is not None:
        previous_assessment = get_or_create_assessment(db, previous_scan, config)
        previous_entry = _history_entry(previous_scan, previous_assessment)
        if (
            response.security_score is not None
            and previous_assessment.security_score is not None
        ):
            score_change = response.security_score - previous_assessment.security_score

    data = response.model_dump()
    data.update(
        {
            "asset_domain": asset.domain,
            "previous_assessment": previous_entry,
            "score_change": score_change,
        }
    )
    return AssetRiskResponse(**data)


def list_asset_risk_history(
    db: Session, asset, config: RiskConfig = DEFAULT_RISK_CONFIG
) -> List[RiskHistoryEntry]:
    """Return completed-scan assessments for ``asset``, newest first."""
    stmt = (
        select(Scan)
        .where(Scan.asset_id == asset.id, Scan.status == "completed")
        .order_by(Scan.completed_at.desc(), Scan.id.desc())
    )
    entries: List[RiskHistoryEntry] = []
    for scan in db.scalars(stmt).all():
        assessment = get_or_create_assessment(db, scan, config)
        entries.append(_history_entry(scan, assessment))
    return entries