"""Target validation and SSRF protection for the scanner.

Responsibilities:
    * Accept only syntactically valid, hostname-based targets (never bare IP
      literals).
    * Resolve A and AAAA records for the hostname.
    * Reject loopback, private, link-local, multicast, reserved, unspecified
      and cloud-metadata addresses.
    * Pin the connection to a validated public IP so that no later stage can
      re-resolve the hostname to a different (possibly internal) address.

The pinning strategy is central to SSRF protection:

    1. Resolve the hostname and validate every returned address.
    2. Choose one validated public IP as the "pinned" address.
    3. All subsequent network connections use the pinned IP for the TCP
       socket while preserving the original hostname for the HTTP ``Host``
       header, TLS SNI and certificate verification.

Redirects are validated independently (see ``validate_redirect_target``) and
are never followed automatically.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from urllib.parse import urljoin, urlsplit

from app.services.scanner.config import DEFAULT_CONFIG, ScannerConfig

# A conservative hostname pattern: one or more dot-separated labels with a
# valid TLD. IP literals are rejected separately.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class TargetValidationError(Exception):
    """Base class for all target validation failures."""


class InvalidTargetError(TargetValidationError):
    """The supplied hostname is not a valid, hostname-based target."""


class TargetDNSResolutionError(TargetValidationError):
    """DNS resolution failed (operational/transient error)."""


class UnsafeTargetError(TargetValidationError):
    """The target resolved to one or more unsafe (non-public) addresses."""


@dataclass
class ValidatedTarget:
    """A hostname that has been resolved and validated for safe scanning."""

    hostname: str
    pinned_ip: str
    addresses: List[str] = field(default_factory=list)
    safe_addresses: List[str] = field(default_factory=list)


@dataclass
class RedirectCheck:
    """Result of independently validating a redirect destination."""

    valid: bool
    reason: str
    url: Optional[str] = None
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    pinned_ip: Optional[str] = None
    addresses: List[str] = field(default_factory=list)


def is_ip_literal(value: str) -> bool:
    """Return True if ``value`` is a literal IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def is_safe_ip(ip: str, config: ScannerConfig = DEFAULT_CONFIG) -> bool:
    """Return True only for globally routable public IP addresses.

    Rejects loopback, private, link-local, multicast, reserved, unspecified
    and known cloud-metadata addresses. Fails closed for anything that cannot
    be parsed.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    # Explicit rejections (documented individually for auditability).
    if addr.is_loopback:
        return False
    if addr.is_private:
        return False
    if addr.is_link_local:
        return False
    if addr.is_multicast:
        return False
    if addr.is_reserved:
        return False
    if addr.is_unspecified:
        return False

    # Positive check: must be globally routable.
    if not addr.is_global:
        return False

    # Known cloud metadata endpoints are link-local in practice, but we reject
    # them explicitly so the intent is unambiguous and future-proof.
    if str(addr) in config.cloud_metadata_ips:
        return False

    return True


def validate_hostname(hostname: str, config: ScannerConfig = DEFAULT_CONFIG) -> str:
    """Validate that ``hostname`` is a syntactically valid hostname.

    IP literals, embedded schemes, paths, credentials and malformed names are
    rejected. Returns the normalised hostname.
    """
    if not hostname or not isinstance(hostname, str):
        raise InvalidTargetError("A hostname is required.")

    candidate = hostname.strip().lower().rstrip(".")
    if not candidate:
        raise InvalidTargetError("A hostname is required.")

    # Reject anything that still looks like a URL / contains path or scheme.
    if any(sep in candidate for sep in ("/", "\\", "?", "#", "@", ":", " ")):
        raise InvalidTargetError(f"Invalid hostname: {hostname!r}")

    # Reject bare IP literals outright.
    if is_ip_literal(candidate):
        raise InvalidTargetError("Literal IP addresses are not accepted as targets.")

    if len(candidate) > 253:
        raise InvalidTargetError("Hostname is too long.")

    if not _HOSTNAME_RE.match(candidate):
        raise InvalidTargetError(f"Invalid hostname: {hostname!r}")

    return candidate


def _default_resolver(hostname: str, config: ScannerConfig) -> List[str]:
    """Resolve A and AAAA records using the system resolver.

    ``getaddrinfo`` returns both IPv4 (A) and IPv6 (AAAA) addresses. Errors are
    surfaced as :class:`TargetDNSResolutionError`.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetDNSResolutionError(f"DNS resolution failed for {hostname!r}: {exc}") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise TargetDNSResolutionError(f"DNS resolution timed out for {hostname!r}: {exc}") from exc
    except OSError as exc:
        raise TargetDNSResolutionError(f"DNS resolution error for {hostname!r}: {exc}") from exc

    addresses: List[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_str = sockaddr[0]
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip_str not in addresses:
            addresses.append(ip_str)
    return addresses


def _select_pinned_ip(addresses: List[str], config: ScannerConfig = DEFAULT_CONFIG) -> str:
    """Choose a single pinned IP, preferring IPv4 for broad compatibility."""
    for ip in addresses:
        try:
            if ipaddress.ip_address(ip).version == 4:
                return ip
        except ValueError:
            continue
    return addresses[0]


def resolve_addresses(
    hostname: str,
    config: ScannerConfig = DEFAULT_CONFIG,
    resolver: Optional[Callable[[str, ScannerConfig], List[str]]] = None,
) -> List[str]:
    """Resolve ``hostname`` to a list of IP addresses (A and AAAA)."""
    resolve = resolver or _default_resolver
    return resolve(hostname, config)


def resolve_and_validate(
    hostname: str,
    config: ScannerConfig = DEFAULT_CONFIG,
    resolver: Optional[Callable[[str, ScannerConfig], List[str]]] = None,
) -> ValidatedTarget:
    """Validate a hostname and pin it to a safe public IP.

    Raises:
        InvalidTargetError: if the hostname is malformed or an IP literal.
        TargetDNSResolutionError: if DNS resolution fails.
        UnsafeTargetError: if the hostname resolves only to unsafe addresses.
    """
    normalised = validate_hostname(hostname, config)
    addresses = resolve_addresses(normalised, config, resolver)
    if not addresses:
        raise TargetDNSResolutionError(f"No A/AAAA records found for {normalised!r}.")

    safe_addresses = [ip for ip in addresses if is_safe_ip(ip, config)]
    if not safe_addresses:
        raise UnsafeTargetError(
            f"Target {normalised!r} resolves only to non-public addresses: {addresses}"
        )

    pinned_ip = _select_pinned_ip(safe_addresses, config)
    return ValidatedTarget(
        hostname=normalised,
        pinned_ip=pinned_ip,
        addresses=addresses,
        safe_addresses=safe_addresses,
    )


def validate_redirect_target(
    location: str,
    base_url: str,
    config: ScannerConfig = DEFAULT_CONFIG,
    resolver: Optional[Callable[[str, ScannerConfig], List[str]]] = None,
) -> RedirectCheck:
    """Independently validate a redirect ``Location`` value.

    The destination is resolved and checked with the same SSRF rules as the
    original target. No request is made to the destination here; the scanner
    never follows redirects automatically.
    """
    if not location:
        return RedirectCheck(valid=False, reason="Empty Location header.")

    try:
        absolute = urljoin(base_url, location)
        parts = urlsplit(absolute)
        scheme = (parts.scheme or "").lower()
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        return RedirectCheck(valid=False, reason=f"Malformed redirect target: {exc}")

    if scheme not in config.allowed_schemes:
        return RedirectCheck(
            valid=False,
            reason=f"Redirect scheme {scheme!r} is not allowed (only HTTP/HTTPS).",
            url=absolute,
            scheme=scheme,
            host=host,
        )

    if not host:
        return RedirectCheck(
            valid=False, reason="Redirect target has no hostname.", url=absolute, scheme=scheme
        )

    try:
        effective_port = port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        return RedirectCheck(valid=False, reason=f"Invalid port: {exc}", url=absolute, scheme=scheme, host=host)

    if effective_port not in config.allowed_ports:
        return RedirectCheck(
            valid=False,
            reason=f"Redirect port {effective_port} is not allowed (only 80/443).",
            url=absolute,
            scheme=scheme,
            host=host,
            port=effective_port,
        )

    if is_ip_literal(host):
        if not is_safe_ip(host, config):
            return RedirectCheck(
                valid=False,
                reason=f"Redirect target {host} is a non-public address (SSRF protection).",
                url=absolute,
                scheme=scheme,
                host=host,
                port=effective_port,
                addresses=[host],
            )
        return RedirectCheck(
            valid=True,
            reason="Redirect target is a public IP address.",
            url=absolute,
            scheme=scheme,
            host=host,
            port=effective_port,
            pinned_ip=host,
            addresses=[host],
        )

    try:
        normalised = validate_hostname(host, config)
        addresses = resolve_addresses(normalised, config, resolver)
    except TargetValidationError as exc:
        return RedirectCheck(
            valid=False,
            reason=str(exc),
            url=absolute,
            scheme=scheme,
            host=host,
            port=effective_port,
        )

    safe_addresses = [ip for ip in addresses if is_safe_ip(ip, config)]
    if not safe_addresses:
        return RedirectCheck(
            valid=False,
            reason=f"Redirect target {normalised!r} resolves only to non-public addresses: {addresses}",
            url=absolute,
            scheme=scheme,
            host=normalised,
            port=effective_port,
            addresses=addresses,
        )

    pinned_ip = _select_pinned_ip(safe_addresses, config)
    return RedirectCheck(
        valid=True,
        reason="Redirect target resolves to public address(es).",
        url=absolute,
        scheme=scheme,
        host=normalised,
        port=effective_port,
        pinned_ip=pinned_ip,
        addresses=safe_addresses,
    )