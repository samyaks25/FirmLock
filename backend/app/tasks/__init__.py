"""Task package for FirmLock.

This package must remain safe to import in inline scan execution mode (no
Redis/Celery/worker required). Celery task registration is explicit/lazy.
"""

from __future__ import annotations

__all__ = ["scan_tasks"]