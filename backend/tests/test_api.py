"""API smoke tests for the FirmLock backend.

The tests use only the Python standard library plus uvicorn (already a
project dependency), so no extra test dependencies are required.

Run from the ``backend`` directory:
    python -m unittest discover -s tests -v
"""

import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

import uvicorn

from app.main import app

HOST = "127.0.0.1"
PORT = 8765
BASE_URL = f"http://{HOST}:{PORT}"
STARTUP_TIMEOUT_SECONDS = 20
REQUEST_TIMEOUT_SECONDS = 5

_server_thread: Optional["_ServerThread"] = None


class _ServerThread(threading.Thread):
    """Runs the FastAPI app with uvicorn in a background thread."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        config = uvicorn.Config(app, host=HOST, port=PORT, log_level="warning")
        self.server = uvicorn.Server(config)

    def run(self) -> None:
        self.server.run()

    def stop(self) -> None:
        self.server.should_exit = True
        self.join(timeout=STARTUP_TIMEOUT_SECONDS)


def _request(
    path: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Any, str]:
    """Perform an HTTP request and always return (status, headers, body)."""
    request = urllib.request.Request(
        BASE_URL + path, method=method, headers=headers or {}
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return response.status, response.headers, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read().decode("utf-8")


def setUpModule() -> None:
    """Start the test server once for the whole module."""
    global _server_thread
    _server_thread = _ServerThread()
    _server_thread.start()

    deadline = time.time() + STARTUP_TIMEOUT_SECONDS
    while time.time() < deadline:
        try:
            status, _, _ = _request("/api/health")
            if status == 200:
                return
        except OSError:
            time.sleep(0.2)

    raise RuntimeError("Test server did not start in time")


def tearDownModule() -> None:
    """Stop the test server."""
    if _server_thread is not None:
        _server_thread.stop()


class RootEndpointTests(unittest.TestCase):
    def test_root_returns_welcome_message(self) -> None:
        status, _, body = _request("/")
        payload = json.loads(body)

        self.assertEqual(status, 200)
        self.assertIn("FirmLock", payload["message"])
        self.assertEqual(payload["service"], "FirmLock")


class HealthEndpointTests(unittest.TestCase):
    def test_health_reports_ok(self) -> None:
        status, _, body = _request("/api/health")
        payload = json.loads(body)

        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["service"])
        self.assertTrue(payload["version"])


class DocumentationTests(unittest.TestCase):
    def test_swagger_docs_are_available(self) -> None:
        status, headers, body = _request("/docs")

        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn("swagger", body.lower())

    def test_openapi_schema_is_available(self) -> None:
        status, _, body = _request("/openapi.json")
        schema = json.loads(body)

        self.assertEqual(status, 200)
        self.assertEqual(schema["info"]["title"], "FirmLock API")


class CorsTests(unittest.TestCase):
    def test_localhost_origin_is_allowed(self) -> None:
        status, headers, _ = _request(
            "/api/health", headers={"Origin": "http://localhost:5173"}
        )

        self.assertEqual(status, 200)
        self.assertEqual(headers.get("access-control-allow-origin"), "http://localhost:5173")

    def test_loopback_origin_is_allowed(self) -> None:
        status, headers, _ = _request(
            "/api/health", headers={"Origin": "http://127.0.0.1:5173"}
        )

        self.assertEqual(status, 200)
        self.assertEqual(headers.get("access-control-allow-origin"), "http://127.0.0.1:5173")

    def test_unknown_origin_is_not_allowed(self) -> None:
        status, headers, _ = _request(
            "/api/health", headers={"Origin": "http://example.com"}
        )

        self.assertNotEqual(headers.get("access-control-allow-origin"), "*")
        self.assertNotEqual(headers.get("access-control-allow-origin"), "http://example.com")
        self.assertEqual(status, 200)

    def test_preflight_request_is_answered(self) -> None:
        status, headers, _ = _request(
            "/api/health",
            method="OPTIONS",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )

        self.assertEqual(status, 200)
        self.assertEqual(headers.get("access-control-allow-origin"), "http://localhost:5173")


if __name__ == "__main__":
    unittest.main()