"""Central scanning workflow.

Responsibilities:
    * Load a scan and its asset.
    * Re-verify authorization and monitoring state (defence in depth).
    * Validate and pin the target hostname safely (SSRF protection).
    * Execute the scanner modules in sequence with bounded timeouts.
    * Persist de-duplicated findings.
    * Transition the scan through ``running`` -> ``completed``/``failed`` and
      always record ``started_at`` / ``completed_at``.

A background scan uses its own database session (never the request session) and
is serialised through a small semaphore so the process never performs
aggressive parallel scanning.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Callable, List, Optional

from sqlalchemy.orm import Session, sessionmaker

from app.database.connection import SessionLocal
from app.models.models import Asset, CheckResult, Finding as FindingModel, Scan
from app.services.risk_config import DEFAULT_RISK_CONFIG, RiskConfig
from app.services.risk_service import assess_and_store
from app.services.scanner.check_catalog import MODULE_NAMES, derive_outcomes
from app.services.scanner.config import DEFAULT_CONFIG, SEVERITY_HIGH, CheckCodes, ScannerConfig
from app.services.scanner.dns_inspector import inspect_dns
from app.services.scanner.findings import Finding
from app.services.scanner.header_inspector import inspect_headers
from app.services.scanner.https_inspector import inspect_https
from app.services.scanner.target_validator import (
    InvalidTargetError,
    TargetDNSResolutionError,
    TargetValidationError,
    UnsafeTargetError,
    ValidatedTarget,
    resolve_and_validate,
)
from app.services.scanner.tls_inspector import inspect_tls

logger = logging.getLogger("firmlock.scanner")

# Bounded concurrency: never run aggressive parallel scans.
_scan_slots = threading.BoundedSemaphore(DEFAULT_CONFIG.max_concurrent_scans)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _dedupe(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate check codes within a scan, keeping the first."""
    seen = set()
    unique: List[Finding] = []
    for finding in findings:
        if finding.check_code in seen:
            continue
        seen.add(finding.check_code)
        unique.append(finding)
    return unique


def _persist_findings(
    db: Session, scan_id: int, findings: List[Finding]
) -> dict[str, FindingModel]:
    """Persist findings and return a ``check_code -> model`` lookup."""
    mapping: dict[str, FindingModel] = {}
    for finding in findings:
        model = FindingModel(
            scan_id=scan_id,
            check_code=finding.check_code,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            evidence=finding.evidence,
            recommendation=finding.recommendation,
        )
        db.add(model)
        mapping[finding.check_code] = model
    db.commit()
    return mapping


def _persist_check_results(
    db: Session,
    scan_id: int,
    module_findings: dict[str, List[Finding]],
    module_errors: dict[str, Optional[str]],
    finding_map: dict[str, FindingModel],
) -> None:
    """Persist one explicit outcome for every expected check group."""
    for module in MODULE_NAMES:
        outcomes = derive_outcomes(
            module,
            module_findings.get(module, []),
            module_errors.get(module),
        )
        for outcome in outcomes:
            linked = (
                finding_map.get(outcome.check_code)
                if outcome.check_code is not None
                else None
            )
            db.add(
                CheckResult(
                    scan_id=scan_id,
                    check_id=outcome.check_id,
                    module=outcome.module,
                    outcome=outcome.outcome,
                    severity=outcome.severity,
                    check_code=outcome.check_code,
                    detail=outcome.detail,
                    finding_id=linked.id if linked is not None else None,
                )
            )
    db.commit()


def _mark_completed(db: Session, scan: Scan, asset: Optional[Asset]) -> None:
    completed_at = _utcnow()
    scan.status = "completed"
    scan.completed_at = completed_at
    if asset is not None:
        asset.last_scanned_at = completed_at
    db.commit()


def _finalize_scan(
    db: Session,
    scan: Scan,
    asset: Optional[Asset],
    findings: List[Finding],
    module_findings: dict[str, List[Finding]],
    module_errors: dict[str, Optional[str]],
    risk_config: RiskConfig,
) -> None:
    """Persist findings, check outcomes, complete the scan and assess risk."""
    unique = _dedupe(findings)
    finding_map = _persist_findings(db, scan.id, unique)
    _persist_check_results(db, scan.id, module_findings, module_errors, finding_map)
    _mark_completed(db, scan, asset)
    assess_and_store(db, scan, risk_config)


def _mark_failed(db: Session, scan: Scan, reason: str) -> None:
    logger.error("Scan %s failed: %s", scan.id, reason)
    scan.status = "failed"
    scan.completed_at = _utcnow()
    db.commit()


def _safe_run(
    func: Callable, *args, config: ScannerConfig, label: str
) -> tuple[List[Finding], Optional[str]]:
    """Run a scanner module, isolating failures so one module cannot abort a scan.

    Returns ``(findings, error)``. A non-``None`` error marks checks in that
    module without a concrete result as unknown rather than passed.
    """
    try:
        return list(func(*args, config)), None
    except Exception as exc:
        logger.exception("Scanner module %s raised an error during a scan.", label)
        return [], f"{type(exc).__name__}: {exc}"


def _all_modules_errored(reason: str) -> dict[str, Optional[str]]:
    """Mark every module as not executed (used when validation stops a scan)."""
    return {name: reason for name in MODULE_NAMES}


def run_scan(
    scan_id: int,
    config: ScannerConfig = DEFAULT_CONFIG,
    session_factory: Optional[sessionmaker] = None,
    resolver: Optional[Callable] = None,
    tls_inspector: Callable = inspect_tls,
    https_inspector: Callable = inspect_https,
    header_inspector: Callable = inspect_headers,
    dns_inspector: Callable = inspect_dns,
    risk_config: RiskConfig = DEFAULT_RISK_CONFIG,
) -> None:
    """Execute a scan end-to-end.

    The parameters exist primarily for testing; the FastAPI background task
    calls this with defaults.
    """
    factory = session_factory or SessionLocal
    db = factory()
    acquired = False
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s not found; nothing to run.", scan_id)
            return

        if not _scan_slots.acquire(timeout=config.scan_acquire_timeout):
            _mark_failed(db, scan, "Timed out waiting for a scan concurrency slot.")
            return
        acquired = True

        scan.status = "running"
        scan.started_at = _utcnow()
        db.commit()

        asset = db.get(Asset, scan.asset_id)
        if asset is None:
            _mark_failed(db, scan, "The asset no longer exists.")
            return
        if not asset.authorization_confirmed:
            _mark_failed(db, scan, "Asset authorization is not confirmed.")
            return
        if not asset.monitoring_enabled or asset.status != "active":
            _mark_failed(db, scan, "Asset monitoring is disabled or the asset is inactive.")
            return

        try:
            target: ValidatedTarget = resolve_and_validate(asset.domain, config, resolver)
        except InvalidTargetError as exc:
            finding = Finding(
                check_code=CheckCodes.TARGET_INVALID,
                title="Target failed validation",
                description=(
                    "The asset domain is not a valid, hostname-based target and "
                    f"was not scanned: {exc}"
                ),
                severity=SEVERITY_HIGH,
                recommendation=(
                    "Register a valid public hostname and confirm authorization."
                ),
                evidence=str(exc),
            )
            _finalize_scan(
                db,
                scan,
                asset,
                [finding],
                {},
                _all_modules_errored("Target validation failed; modules were not executed."),
                risk_config,
            )
            return
        except UnsafeTargetError as exc:
            finding = Finding(
                check_code=CheckCodes.TARGET_SSRF_REJECTED,
                title="Target resolved to a non-public address",
                description=(
                    "The domain resolved to non-public address(es) and was blocked "
                    f"to prevent SSRF: {exc}"
                ),
                severity=SEVERITY_HIGH,
                recommendation=(
                    "Ensure the domain resolves only to public IP addresses."
                ),
                evidence=str(exc),
            )
            _finalize_scan(
                db,
                scan,
                asset,
                [finding],
                {},
                _all_modules_errored("Target rejected by SSRF validation; modules were not executed."),
                risk_config,
            )
            return
        except TargetDNSResolutionError as exc:
            _mark_failed(db, scan, f"DNS resolution failed: {exc}")
            return
        except TargetValidationError as exc:
            _mark_failed(db, scan, f"Target validation failed: {exc}")
            return

        findings: List[Finding] = []
        module_findings: dict[str, List[Finding]] = {}
        module_errors: dict[str, Optional[str]] = {}

        module_findings["tls"], module_errors["tls"] = _safe_run(
            tls_inspector, target, config=config, label="TLS"
        )
        module_findings["https"], module_errors["https"] = _safe_run(
            https_inspector, target, config=config, label="HTTPS"
        )
        module_findings["headers"], module_errors["headers"] = _safe_run(
            header_inspector, target, config=config, label="Headers"
        )
        module_findings["dns"], module_errors["dns"] = _safe_run(
            dns_inspector, asset.domain, config=config, label="DNS"
        )
        for module in MODULE_NAMES:
            findings.extend(module_findings[module])

        _finalize_scan(
            db,
            scan,
            asset,
            findings,
            module_findings,
            module_errors,
            risk_config,
        )

        # Generate in-app alerts from actionable findings. Alert generation is
        # isolated from scan completion so a failure here does not invalidate the
        # scan or its risk assessment.
        try:
            from app.services.alert_service import generate_alerts_for_scan

            generate_alerts_for_scan(db, scan.id)
        except Exception:  # pragma: no cover - defensive
            logger.exception("Could not generate alerts for scan %s.", scan.id)
            try:
                db.rollback()
            except Exception:
                logger.exception("Could not roll back after alert generation failure.")

    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Unexpected error while running scan %s: %s", scan_id, exc)
        try:
            db.rollback()
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.completed_at = _utcnow()
                db.commit()
        except Exception:
            logger.exception("Could not mark scan %s as failed.", scan_id)
            db.rollback()
    finally:
        if acquired:
            _scan_slots.release()
        db.close()