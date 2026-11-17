"""DNS-pinned HTTP(S) transport primitives.

The scanner must never let a hostname be re-resolved after it has been
validated. These helpers open a TCP connection directly to an already
validated, pinned IP address while preserving the original hostname for:

    * the HTTP ``Host`` header,
    * TLS SNI, and
    * TLS certificate hostname verification.

This is the mechanism that makes SSRF protection effective: the address that
is connected to is exactly the address that was validated.
"""

from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, Optional

from app.services.scanner.config import DEFAULT_CONFIG, ScannerConfig


@dataclass
class HttpResponse:
    """A minimal HTTP response captured by the scanner."""

    status: int = 0
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    error_type: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


def build_ssl_context() -> ssl.SSLContext:
    """Return a verifying TLS context (certificate + hostname checks on)."""
    return ssl.create_default_context()


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that dials a pinned IP instead of re-resolving DNS."""

    def __init__(self, host: str, pinned_ip: str, port: int = 80, timeout: float = 8.0):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:  # pragma: no cover - exercised via http_get
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        if self._tunnel_host:
            self._tunnel()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials a pinned IP but verifies the real hostname.

    The TCP socket is opened against ``pinned_ip``; TLS is then negotiated
    with ``server_hostname`` set to the original hostname so that SNI and
    certificate hostname verification behave exactly as a normal client.
    """

    def __init__(
        self,
        host: str,
        pinned_ip: str,
        port: int = 443,
        timeout: float = 8.0,
        context: Optional[ssl.SSLContext] = None,
    ):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:  # pragma: no cover - exercised via http_get
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        server_hostname = self._tunnel_host or self.host
        self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)


def http_request(
    scheme: str,
    host: str,
    pinned_ip: str,
    port: int,
    config: ScannerConfig = DEFAULT_CONFIG,
    path: str = "/",
    method: str = "GET",
) -> HttpResponse:
    """Perform a single, bounded HTTP(S) request against a pinned IP.

    Only response headers are captured. The body is never downloaded; the
    connection is closed after the status line and headers are read. All
    network errors are converted into an :class:`HttpResponse` with an
    ``error``/``error_type`` rather than raising.
    """
    headers = {
        "Host": host,
        "User-Agent": config.user_agent,
        "Accept": "*/*",
        "Connection": "close",
    }

    connection: http.client.HTTPConnection
    if scheme == "https":
        connection = PinnedHTTPSConnection(
            host,
            pinned_ip,
            port=port,
            timeout=config.connect_timeout,
            context=build_ssl_context(),
        )
    elif scheme == "http":
        connection = PinnedHTTPConnection(host, pinned_ip, port=port, timeout=config.connect_timeout)
    else:
        return HttpResponse(error=f"Unsupported scheme: {scheme!r}", error_type="scheme")

    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        return HttpResponse(
            status=response.status,
            reason=response.reason,
            headers=response_headers,
        )
    except ssl.SSLCertVerificationError as exc:
        return HttpResponse(error=str(exc), error_type="cert_verify")
    except ssl.SSLError as exc:
        return HttpResponse(error=str(exc), error_type="ssl")
    except (socket.timeout, TimeoutError) as exc:
        return HttpResponse(error=str(exc), error_type="timeout")
    except (http.client.HTTPException, ConnectionError, OSError) as exc:
        return HttpResponse(error=str(exc), error_type="connection")
    except Exception as exc:  # pragma: no cover - defensive catch-all
        return HttpResponse(error=str(exc), error_type="unknown")
    finally:
        connection.close()