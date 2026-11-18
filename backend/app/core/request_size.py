"""Request size limiting middleware for FirmLock."""

from __future__ import annotations

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse

from app.core.config import settings


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Limit maximum request body size.

    Rejects oversized requests with HTTP 413 Payload Too Large.
    Validates Content-Length header and handles streamed requests safely.
    """

    def __init__(
        self,
        app,
        max_size_bytes: int | None = None,
        max_size_mb: float | None = None,
    ):
        super().__init__(app)
        if max_size_bytes is not None:
            self.max_size = max_size_bytes
        elif max_size_mb is not None:
            self.max_size = int(max_size_mb * 1024 * 1024)
        else:
            # Default: 10 MB
            self.max_size = 10 * 1024 * 1024

        # Endpoints that may need larger limits (e.g., CSV report downloads)
        self.exempt_paths = {
            "/api/scans/",
            "/api/reports/",
        }

    def _is_exempt(self, path: str) -> bool:
        """Check if path is exempt from size limits."""
        for exempt in self.exempt_paths:
            if path.startswith(exempt) and path.endswith(".csv"):
                return True
        return False

    async def dispatch(self, request: Request, call_next):
        # Skip size limit for exempt paths
        if self._is_exempt(request.url.path):
            return await call_next(request)

        # Check Content-Length header first (if present)
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                if length > self.max_size:
                    return PlainTextResponse(
                        f"Request body too large. Maximum size: {self.max_size} bytes",
                        status_code=413,
                    )
            except ValueError:
                pass  # Invalid Content-Length, let stream handling deal with it

        # For streamed requests, we need to read and count bytes
        # We'll wrap the body iterator to enforce the limit
        if request.headers.get("transfer-encoding") == "chunked" or not content_length:
            # Streamed request - enforce limit during read
            original_body = request.stream()
            limited_stream = _LimitedStream(original_body, self.max_size)
            request._body = b""  # Clear cached body
            request._stream = limited_stream

        return await call_next(request)


class _LimitedStream:
    """Wrapper around async iterator that enforces a maximum byte count."""

    def __init__(self, iterator, max_bytes: int):
        self.iterator = iterator
        self.max_bytes = max_bytes
        self.bytes_read = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            chunk = await self.iterator.__anext__()
        except StopAsyncIteration:
            raise

        self.bytes_read += len(chunk)
        if self.bytes_read > self.max_bytes:
            raise ValueError(f"Request body exceeds maximum size of {self.max_bytes} bytes")

        return chunk


def get_request_size_limit() -> int:
    """Get maximum request size from environment variable.

    Returns size in bytes. Default: 10 MB.
    """
    raw_mb = os.getenv("FIRMLOCK_MAX_REQUEST_SIZE_MB", "10")
    try:
        return int(float(raw_mb) * 1024 * 1024)
    except ValueError:
        return 10 * 1024 * 1024


import os