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
from app.models.models import Asset, Finding as FindingModel, Scan
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


def _persist_findings(db: Session, scan_id: int, findings: List[Finding]) -> None:
    for finding in findings:
        db.add(
            FindingModel(
                scan_id=scan_id,
                check_code=finding.check_code,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                evidence=finding.evidence,
                recommendation=finding.recommendation,
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


def _mark_failed(db: Session, scan: Scan, reason: str) -> None:
    logger.error("Scan %s failed: %s", scan.id, reason)
    scan.status = "failed"
    scan.completed_at = _utcnow()
    db.commit()


def _safe_run(func: Callable, *args, config: ScannerConfig, label: str) -> List[Finding]:
    """Run a scanner module, isolating failures so one module cannot abort a scan."""
    try:
        return list(func(*args, config))
    except Exception:
        logger.exception("Scanner module %s raised an error during a scan.", label)
        return []


def run_scan(
    scan_id: int,
    config: ScannerConfig = DEFAULT_CONFIG,
    session_factory: Optional[sessionmaker] = None,
    resolver: Optional[Callable] = None,
    tls_inspector: Callable = inspect_tls,
    https_inspector: Callable = inspect_https,
    header_inspector: Callable = inspect_headers,
    dns_inspector: Callable = inspect_dns,
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
            _persist_findings(
                db,
                scan.id,
                [
                    Finding(
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
                ],
            )
            _mark_completed(db, scan, asset)
            return
        except UnsafeTargetError as exc:
            _persist_findings(
                db,
                scan.id,
                [
                    Finding(
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
                ],
            )
            _mark_completed(db, scan, asset)
            return
        except TargetDNSResolutionError as exc:
            _mark_failed(db, scan, f"DNS resolution failed: {exc}")
            return
        except TargetValidationError as exc:
            _mark_failed(db, scan, f"Target validation failed: {exc}")
            return

        findings: List[Finding] = []
        findings.extend(_safe_run(tls_inspector, target, config=config, label="TLS"))
        findings.extend(_safe_run(https_inspector, target, config=config, label="HTTPS"))
        findings.extend(_safe_run(header_inspector, target, config=config, label="Headers"))
        findings.extend(_safe_run(dns_inspector, asset.domain, config=config, label="DNS"))

        unique = _dedupe(findings)
        _persist_findings(db, scan.id, unique)
        _mark_completed(db, scan, asset)

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