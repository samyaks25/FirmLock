"""Pydantic schemas and domain normalization helpers for assets."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Literal, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class AssetCreate(BaseModel):
    domain: str = Field(..., min_length=1, max_length=255)
    authorization_confirmed: bool = Field(...)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        return normalize_domain(value)

    @field_validator("authorization_confirmed")
    @classmethod
    def validate_authorization(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError(
                "Explicit authorization confirmation (true) is required before registering an asset."
            )
        return value


class AssetUpdate(BaseModel):
    monitoring_enabled: Optional[bool] = None
    status: Optional[Literal["active", "paused"]] = None


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    business_id: int
    domain: str
    authorization_confirmed: bool
    authorization_confirmed_at: datetime
    monitoring_enabled: bool
    status: str
    last_scanned_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


def normalize_domain(raw_value: str) -> str:
    """Normalize and validate a hostname or root HTTP(S) URL.

    Accepts a hostname or a valid HTTP/HTTPS website URL and returns the
    normalised hostname. Rejects malformed domains, embedded credentials,
    paths beyond the root path, and literal IP addresses for this MVP.
    """
    value = (raw_value or "").strip().lower()
    if not value:
        raise ValueError("Domain cannot be empty.")

    if "://" in value:
        parts = urlsplit(value)
    elif "/" in value or "?" in value or "#" in value:
        parts = urlsplit(f"http://{value}")
    else:
        parts = urlsplit(f"http://{value}")

    if parts.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS website URLs are accepted.")
    if parts.username or parts.password:
        raise ValueError("Embedded credentials are not allowed in domain input.")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise ValueError("Paths beyond the root path are not allowed.")

    hostname = (parts.hostname or "").strip().lower().strip(".")
    if not hostname:
        raise ValueError("A valid hostname is required.")
    if parts.port and (parts.netloc.count(":") > 1 and not hostname.startswith("[")):
        # urlsplit handles ports; this guards odd cases. Normalization proceeds.
        pass

    # Reject literal IP addresses for this hostname-based MVP.
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        raise ValueError("Literal IP addresses are not accepted for this hostname-based MVP.")
    except ValueError as exc:
        if "not accepted" in str(exc):
            raise
        # Not an IP address; continue hostname validation.

    if not _HOSTNAME_RE.match(hostname):
        raise ValueError("Invalid domain name.")

    return hostname
