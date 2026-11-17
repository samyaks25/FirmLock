"""Worker health monitoring utilities.

Provides functions to check Redis broker availability and Celery worker status
without exposing credentials or requiring Redis for API startup. In inline scan
execution mode this never attempts Redis or Celery connections.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from app.core.config import settings

logger = logging.getLogger("firmlock.worker_health")


@dataclass
class WorkerHealthStatus:
    """Health status of the worker infrastructure."""

    redis_available: bool
    redis_error: Optional[str] = None
    workers_online: int = 0
    workers_error: Optional[str] = None
    queues: Optional[dict] = None
    queues_error: Optional[str] = None


def check_redis_connection(redis_url: Optional[str] = None) -> tuple[bool, Optional[str]]:
    """Check if Redis is available.

    Args:
        redis_url: Redis URL to check. Defaults to settings.redis_url.

    Returns:
        Tuple of (is_available, error_message).
    """
    if settings.scan_execution_mode == "inline":
        return False, "Inline scan execution mode (Redis not required)"

    url = (redis_url or settings.redis_url).strip()
    if not url:
        return False, "FIRMLOCK_REDIS_URL not configured"

    try:
        import redis

        client = redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
        client.ping()
        return True, None
    except Exception as e:
        # redis exceptions are only meaningful in celery mode; keep generic here
        name = type(e).__name__
        if name == "ConnectionError":
            return False, f"Redis connection failed: {e}"
        if name == "AuthenticationError":
            return False, f"Redis authentication failed: {e}"
        return False, f"Redis check failed: {name}: {e}"


def get_worker_health() -> WorkerHealthStatus:
    """Get comprehensive worker health status.

    This function gracefully handles unavailable Redis and does not raise
    exceptions. It returns a status object with all available information.
    """
    if settings.scan_execution_mode == "inline":
        return WorkerHealthStatus(
            redis_available=False,
            redis_error="Inline scan execution mode (Redis not required)",
            workers_online=0,
            workers_error="Inline scan execution mode (Celery workers not required)",
        )

    redis_ok, redis_error = check_redis_connection()

    status = WorkerHealthStatus(
        redis_available=redis_ok,
        redis_error=redis_error,
    )

    if not redis_ok:
        logger.warning("Redis unavailable for worker health check: %s", redis_error)
        return status

    # Try to get worker info via Celery inspect
    try:
        from app.core.celery_config import get_celery_app

        celery_app = get_celery_app()
        inspect = celery_app.control.inspect(timeout=3)

        stats = inspect.stats()
        status.workers_online = len(stats) if stats else 0

        try:
            active_queues = inspect.active_queues()
            if active_queues:
                status.queues = {
                    worker: [q["name"] for q in queues]
                    for worker, queues in active_queues.items()
                }
        except Exception as e:
            status.queues_error = f"Failed to get queue info: {e}"

    except Exception as e:
        status.workers_error = f"Worker inspection failed: {type(e).__name__}: {e}"
        logger.warning("Worker health check failed: %s", status.workers_error)

    return status


def is_worker_healthy() -> bool:
    """Quick check if workers are healthy.

    Returns True if Redis is available and at least one worker is online.
    In inline mode workers are not required, so this reflects direct execution.
    """
    if settings.scan_execution_mode == "inline":
        return True
    health = get_worker_health()
    return health.redis_available and health.workers_online > 0


def get_queue_depth(queue_name: str = "scans") -> Optional[int]:
    """Get the number of pending tasks in a queue.

    Returns None if unavailable.
    """
    if settings.scan_execution_mode == "inline":
        return None
    redis_ok, _ = check_redis_connection()
    if not redis_ok:
        return None

    try:
        import redis

        client = redis.from_url(settings.redis_url)
        # Celery uses list for queues, key format: "celery" for default queue
        queue_key = queue_name if queue_name != "scans" else "celery"
        length = client.llen(queue_key)
        return length
    except Exception as e:
        logger.warning("Failed to get queue depth for %s: %s", queue_name, e)
        return None