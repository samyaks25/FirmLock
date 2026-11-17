"""Logging utilities for FirmLock.

Provides secure logging with automatic redaction of sensitive data.
"""

from __future__ import annotations

import logging
import re
from typing import Any


class SensitiveDataFilter(logging.Filter):
    """Logging filter that redacts sensitive information from log records.

    Redacts:
    - Passwords in JSON/form data
    - JWT tokens (Authorization headers, token fields)
    - Database connection strings with credentials
    - API keys and secrets
    """

    # Patterns to match and redact sensitive data
    _SENSITIVE_PATTERNS = [
        # Password fields
        (re.compile(r'("password"\s*:\s*")([^"]+)(")', re.IGNORECASE), r'\1***REDACTED***\3'),
        (re.compile(r'(password\s*=\s*)([^&\s]+)', re.IGNORECASE), r'\1***REDACTED***'),
        # JWT tokens
        (re.compile(r'("access_token"\s*:\s*")([^"]+)(")', re.IGNORECASE), r'\1***REDACTED***\3'),
        (re.compile(r'(Bearer\s+)([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+)', re.IGNORECASE), r'\1***REDACTED***'),
        # Authorization headers
        (re.compile(r'("authorization"\s*:\s*")([^"]+)(")', re.IGNORECASE), r'\1***REDACTED***\3'),
        (re.compile(r'(authorization\s*:\s*)([^\n\r]+)', re.IGNORECASE), r'\1***REDACTED***'),
        # Database URLs with credentials
        (re.compile(r'(sqlite://|postgresql://|mysql://)([^:@/]+:[^@/]+@)', re.IGNORECASE), r'\1***REDACTED***@'),
        # Generic secret/key patterns
        (re.compile(r'("secret"\s*:\s*")([^"]+)(")', re.IGNORECASE), r'\1***REDACTED***\3'),
        (re.compile(r'("api[_-]?key"\s*:\s*")([^"]+)(")', re.IGNORECASE), r'\1***REDACTED***\3'),
        (re.compile(r'(api[_-]?key\s*=\s*)([^&\s]+)', re.IGNORECASE), r'\1***REDACTED***'),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive data from log message and args."""
        if isinstance(record.msg, str):
            record.msg = self._redact(record.msg)

        if record.args:
            record.args = tuple(
                self._redact(arg) if isinstance(arg, str) else arg
                for arg in record.args
            )

        return True

    def _redact(self, text: str) -> str:
        """Apply all redaction patterns to text."""
        for pattern, replacement in self._SENSITIVE_PATTERNS:
            text = pattern.sub(replacement, text)
        return text


def setup_secure_logging(level: int = logging.INFO) -> None:
    """Configure secure logging with sensitive data redaction.

    Args:
        level: Logging level (default: INFO)
    """
    # Create filter
    sensitive_filter = SensitiveDataFilter()

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers
    root_logger.handlers.clear()

    # Create console handler with filter
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.addFilter(sensitive_filter)

    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)

    root_logger.addHandler(handler)

    # Apply filter to all existing loggers
    for logger_name in logging.root.manager.loggerDict:
        logger = logging.getLogger(logger_name)
        logger.addFilter(sensitive_filter)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with secure logging configured.

    This is a convenience function - the logger will inherit the
    sensitive data filter from the root logger configuration.
    """
    return logging.getLogger(name)


# Initialize secure logging on module import
setup_secure_logging()