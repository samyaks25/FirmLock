"""Celery configuration for FirmLock background workers.

This module provides a modular Celery configuration that uses Redis as the
message broker. Configuration is driven by environment variables through the
Settings class to keep credentials out of source code.

Important: importing this module must not connect to Redis or eagerly create a
Celery app. Inline scan execution mode relies on that guarantee.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from app.core.config import settings

if TYPE_CHECKING:  # pragma: no cover
    from celery import Celery


_celery_app: "Celery | None" = None


def _get_redis_url() -> str:
    """Get Redis URL from settings or environment."""
    # Check environment directly for test overrides
    return os.getenv("FIRMLOCK_REDIS_URL", settings.redis_url).strip()


def create_celery_app() -> "Celery":
    """Create and configure the Celery application.

    Returns:
        Configured Celery app instance.

    Raises:
        ValueError: If FIRMLOCK_REDIS_URL is not set.
    """
    from celery import Celery

    redis_url = _get_redis_url()
    if not redis_url:
        raise ValueError(
            "FIRMLOCK_REDIS_URL must be set to use Celery. "
            "Set the environment variable to a valid Redis URL (e.g., redis://localhost:6379/0)."
        )

    app = Celery("firmlock")

    # Broker and result backend configuration
    app.conf.broker_url = redis_url
    app.conf.result_backend = redis_url

    # Task execution settings
    app.conf.task_serializer = "json"
    app.conf.result_serializer = "json"
    app.conf.accept_content = ["json"]
    app.conf.timezone = "UTC"
    app.conf.enable_utc = True

    # Worker settings
    app.conf.worker_concurrency = settings.celery_worker_concurrency
    app.conf.worker_prefetch_multiplier = 1  # Fair dispatch, one task per worker at a time
    app.conf.worker_max_tasks_per_child = 100  # Recycle workers to prevent memory leaks

    # Task time limits
    app.conf.task_time_limit = settings.celery_task_time_limit
    app.conf.task_soft_time_limit = settings.celery_task_soft_time_limit

    # Reliability settings
    app.conf.task_acks_late = True  # Acknowledge after task completion
    app.conf.task_reject_on_worker_lost = True  # Requeue if worker dies mid-task
    app.conf.task_acks_on_failure_or_timeout = False  # Don't ack on failure/timeout
    app.conf.broker_heartbeat = 30  # Heartbeat interval for connection health

    # Retry policy for transient failures
    app.conf.task_publish_retry = True
    app.conf.task_publish_retry_policy = {
        "max_retries": 3,
        "interval_start": 1,
        "interval_step": 1,
        "interval_max": 5,
    }

    # Result backend settings
    app.conf.result_expires = 3600  # Results expire after 1 hour
    app.conf.result_compression = "gzip"

    # Task routing - all scan tasks go to the scan queue
    app.conf.task_routes = {
        "app.tasks.scan_tasks.execute_scan": {"queue": "scans"},
    }

    # Default queue configuration
    app.conf.task_default_queue = "scans"
    app.conf.task_create_missing_queues = True

    # Task discovery - auto-discover tasks in the tasks module
    app.autodiscover_tasks(["app.tasks"])

    return app


def get_celery_app() -> "Celery":
    """Get or create the Celery app instance (lazy initialization).

    Returns:
        Configured Celery app instance.

    Raises:
        ValueError: If FIRMLOCK_REDIS_URL is not set.
    """
    global _celery_app
    if _celery_app is None:
        _celery_app = create_celery_app()
    return _celery_app


def __getattr__(name: str):
    """Lazily expose ``celery_app`` for Celery CLI usage without side effects."""
    if name == "celery_app":
        app = get_celery_app()
        globals()[name] = app
        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")