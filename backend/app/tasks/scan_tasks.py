"""Celery tasks for scan execution.

This module contains the background tasks that execute security scans.
Tasks receive only the scan ID and use their own database sessions.

Import-safe when Celery is not installed so inline scan execution mode can run
without Redis/Celery dependencies.
"""

from __future__ import annotations

import logging
import signal
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable

from app.core.config import settings
from app.database.connection import SessionLocal
from app.models.models import Scan
from app.services.scanner.scan_manager import run_scan

try:
    from celery import Task
    from celery.exceptions import SoftTimeLimitExceeded
    _CELERY_AVAILABLE = True
except Exception:  # pragma: no cover
    Task = object  # type: ignore[assignment,misc]

    class SoftTimeLimitExceeded(Exception):
        pass

    _CELERY_AVAILABLE = False

if TYPE_CHECKING:  # pragma: no cover
    from celery import Celery

logger = logging.getLogger("firmlock.tasks")
_celery_app: "Celery | None" = None


def _get_celery_app() -> "Celery":
    global _celery_app
    if _celery_app is None:
        from app.core.celery_config import get_celery_app

        _celery_app = get_celery_app()
    return _celery_app


class _PlaceholderTask:
    name: str = ""

    def __init__(self, func: Callable[..., Any], name: str):
        self._func = func
        self.name = name
        self.__name__ = getattr(func, "__name__", name)
        self.__doc__ = func.__doc__

    def __call__(self, *args, **kwargs):
        return self._func(*args, **kwargs)

    def delay(self, *args, **kwargs):  # pragma: no cover
        raise RuntimeError("Celery is not available; cannot enqueue task")

    def apply_async(self, args=None, kwargs=None, **options):  # pragma: no cover
        raise RuntimeError("Celery is not available; cannot enqueue task")

    def run(self, *args, **kwargs):
        return self._func(*args, **kwargs)


if _CELERY_AVAILABLE:

    class ScanTask(Task):
        retry_backoff = True
        retry_backoff_max = 600
        retry_jitter = True
        max_retries = 3
        acks_late = True
        reject_on_worker_lost = True

        def __init__(self):
            super().__init__()
            self._shutdown_requested = False
            try:
                signal.signal(signal.SIGTERM, self._handle_shutdown)
                signal.signal(signal.SIGINT, self._handle_shutdown)
            except Exception:
                pass

        def _handle_shutdown(self, signum, frame):
            logger.info("Received shutdown signal %s, finishing current task...", signum)
            self._shutdown_requested = True

        def on_failure(self, exc, task_id, args, kwargs, einfo):
            scan_id = args[0] if args else kwargs.get("scan_id")
            if scan_id:
                self._mark_scan_failed(scan_id, f"Task failed: {exc}")

        def _mark_scan_failed(self, scan_id: int, reason: str) -> None:
            db = SessionLocal()
            try:
                scan = db.get(Scan, scan_id)
                if scan and scan.status in ("pending", "running"):
                    scan.status = "failed"
                    scan.completed_at = datetime.now(timezone.utc)
                    db.commit()
                    logger.error("Scan %s marked as failed: %s", scan_id, reason)
            except Exception as e:
                logger.exception("Failed to mark scan %s as failed: %s", scan_id, e)
                db.rollback()
            finally:
                db.close()

    def _task_decorator(*args, **kwargs):
        def wrapper(func):
            return _get_celery_app().task(*args, **kwargs)(func)
        return wrapper

else:  # pragma: no cover

    class ScanTask(object):  # type: ignore[no-redef]
        max_retries = 3
        _shutdown_requested = False

        def _mark_scan_failed(self, scan_id: int, reason: str) -> None:
            db = SessionLocal()
            try:
                scan = db.get(Scan, scan_id)
                if scan and scan.status in ("pending", "running"):
                    scan.status = "failed"
                    scan.completed_at = datetime.now(timezone.utc)
                    db.commit()
            except Exception:
                db.rollback()
            finally:
                db.close()

    def _task_decorator(*args, **kwargs):
        def wrapper(func):
            return _PlaceholderTask(func, kwargs.get("name", getattr(func, "__name__", "task")))
        return wrapper


@_task_decorator(
    bind=True,
    base=ScanTask,
    name="app.tasks.scan_tasks.execute_scan",
    queue="scans",
)
def execute_scan(self: ScanTask, scan_id: int) -> dict:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s not found", scan_id)
            return {"status": "not_found", "scan_id": scan_id}

        if scan.status in ("completed", "failed"):
            logger.info("Scan %s already in terminal state (%s), skipping", scan_id, scan.status)
            return {"status": "skipped", "scan_id": scan_id, "reason": f"Already {scan.status}"}

        scan.celery_task_id = getattr(getattr(self, "request", None), "id", None)
        scan.queue_timestamp = datetime.now(timezone.utc)
        scan.attempt_count = (scan.attempt_count or 0) + 1
        req = getattr(self, "request", None)
        if req is not None:
            scan.worker_metadata = {
                "hostname": getattr(req, "hostname", None),
                "pid": getattr(req, "pid", None),
                "retries": getattr(req, "retries", 0),
            }
        db.commit()
    except Exception as e:
        logger.exception("Failed to update scan %s before execution: %s", scan_id, e)
        db.rollback()
        db.close()
        raise
    finally:
        db.close()

    retries = getattr(getattr(self, "request", None), "retries", 0)
    logger.info("Starting scan %s (attempt %s)", scan_id, retries + 1)

    try:
        run_scan(scan_id=scan_id, session_factory=SessionLocal)

        db = SessionLocal()
        try:
            scan = db.get(Scan, scan_id)
            if scan and scan.status == "completed":
                logger.info("Scan %s completed successfully", scan_id)
                return {"status": "completed", "scan_id": scan_id}
            elif scan and scan.status == "failed":
                logger.warning("Scan %s completed with failed status", scan_id)
                return {"status": "failed", "scan_id": scan_id}
            else:
                logger.warning("Scan %s in unexpected state: %s", scan_id, scan.status if scan else "missing")
                return {"status": "unexpected", "scan_id": scan_id}
        finally:
            db.close()

    except SoftTimeLimitExceeded:
        logger.error("Scan %s exceeded soft time limit", scan_id)
        self._mark_scan_failed(scan_id, "Scan exceeded time limit")
        raise

    except Exception as exc:
        logger.exception("Scan %s raised exception: %s", scan_id, exc)
        if _is_transient_failure(exc) and _CELERY_AVAILABLE and hasattr(self, "retry"):
            max_retries = getattr(self, "max_retries", settings.celery_max_retries)
            logger.info("Scan %s transient failure, will retry (attempt %s/%s)", scan_id, retries + 1, max_retries)
            countdown = min(600, settings.celery_retry_base_delay * (2 ** retries))
            raise self.retry(exc=exc, countdown=countdown)
        else:
            logger.error("Scan %s permanent failure, not retrying: %s", scan_id, exc)
            self._mark_scan_failed(scan_id, f"Permanent failure: {exc}")
            return {"status": "failed", "scan_id": scan_id, "error": str(exc)}

    finally:
        if getattr(self, "_shutdown_requested", False):
            logger.warning("Shutdown requested after scan %s completion", scan_id)


@_task_decorator(
    bind=True,
    name="app.tasks.scan_tasks.recover_stuck_scans",
    queue="scans",
)
def recover_stuck_scans(self: Task) -> dict:
    from sqlalchemy import select

    db = SessionLocal()
    recovered = 0
    errors = 0
    try:
        cutoff = datetime.now(timezone.utc)
        cutoff = cutoff.replace(minute=cutoff.minute - 10)
        stuck_scans = db.scalars(
            select(Scan).where(
                Scan.status.in_(("running", "pending")),
                Scan.started_at.isnot(None),
                Scan.started_at < cutoff,
            )
        ).all()
        for scan in stuck_scans:
            try:
                logger.info("Recovering stuck scan %s (status: %s, started: %s)", scan.id, scan.status, scan.started_at)
                scan.status = "pending"
                scan.started_at = None
                scan.celery_task_id = None
                db.commit()
                recovered += 1
            except Exception as e:
                logger.exception("Failed to recover scan %s: %s", scan.id, e)
                db.rollback()
                errors += 1
    finally:
        db.close()
    return {"recovered": recovered, "errors": errors}


def _is_transient_failure(exc: Exception) -> bool:
    from app.services.scanner.target_validator import (
        InvalidTargetError,
        TargetDNSResolutionError,
        TargetValidationError,
        UnsafeTargetError,
    )

    if isinstance(exc, (InvalidTargetError, UnsafeTargetError, TargetValidationError)):
        return False
    if isinstance(exc, TargetDNSResolutionError):
        return True

    transient_indicators = (
        "timeout", "connection", "connect", "refused", "reset", "unreachable",
        "temporary", "try again", "eagain", "etimedout", "econnrefused", "econnreset", "ehostunreach", "enetunreach",
    )
    exc_str = str(exc).lower()
    return any(indicator in exc_str for indicator in transient_indicators)


__all__ = ["execute_scan", "recover_stuck_scans", "ScanTask", "_is_transient_failure"]
