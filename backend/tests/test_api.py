"""API smoke tests for the FirmLock backend.

The tests use only the Python standard library plus uvicorn (already a
project dependency), so no extra test dependencies are required.

Run from the ``backend`` directory:
    python -m unittest discover -s tests -v
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

HOST = "127.0.0.1"
STARTUP_TIMEOUT_SECONDS = 20
REQUEST_TIMEOUT_SECONDS = 5

_server_proc: Optional[subprocess.Popen] = None
_tmpdir: Optional[tempfile.TemporaryDirectory] = None
_base_url: str = ""


def _free_port() -> int:
    """Return an available localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def _request(
    path: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Any, str]:
    """Perform an HTTP request and always return (status, headers, body)."""
    request = urllib.request.Request(
        _base_url + path, method=method, headers=headers or {}
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return response.status, response.headers, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read().decode("utf-8")


def setUpModule() -> None:
    """Start the test server once in a subprocess using an isolated DB."""
    global _server_proc, _tmpdir, _base_url

    _tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(_tmpdir.name) / "smoke.db"
    data_dir = Path(_tmpdir.name) / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    port = _free_port()
    _base_url = f"http://{HOST}:{port}"

    env = os.environ.copy()
    env["FIRMLOCK_DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"
    env["FIRMLOCK_DATA_DIR"] = str(data_dir)

    backend_dir = str(Path(__file__).resolve().parents[1])
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        HOST,
        "--port",
        str(port),
        "--log-level",
        "warning",
    ]
    _server_proc = subprocess.Popen(
        cmd,
        cwd=backend_dir,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.time() + STARTUP_TIMEOUT_SECONDS
    last_error: Optional[BaseException] = None
    while time.time() < deadline:
        if _server_proc.poll() is not None:
            raise RuntimeError(
                f"Test server exited early with code {_server_proc.returncode} on {_base_url}"
            )
        try:
            status, _, _ = _request("/api/health")
            if status == 200:
                return
        except OSError as error:
            last_error = error
            time.sleep(0.2)

    raise RuntimeError(
        f"Test server did not start in time on {_base_url}: {last_error}"
    )


def tearDownModule() -> None:
    """Stop the test server and clean temporary resources."""
    global _server_proc, _tmpdir, _base_url

    try:
        if _server_proc is not None and _server_proc.poll() is None:
            _server_proc.terminate()
            try:
                _server_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                _server_proc.kill()
                _server_proc.wait(timeout=5)
    finally:
        if _tmpdir is not None:
            _tmpdir.cleanup()
        _server_proc = None
        _tmpdir = None
        _base_url = ""


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
        self.assertIn("openapi", schema)


class CorsTests(unittest.TestCase):
    def test_localhost_origin_is_allowed(self) -> None:
        status, headers, _ = _request("/api/health", headers={"Origin": "http://localhost:5173"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("access-control-allow-origin"), "http://localhost:5173")
        self.assertEqual(headers.get("access-control-allow-credentials"), "true")

    def test_loopback_origin_is_allowed(self) -> None:
        status, headers, _ = _request("/api/health", headers={"Origin": "http://127.0.0.1:5173"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("access-control-allow-origin"), "http://127.0.0.1:5173")
        self.assertEqual(headers.get("access-control-allow-credentials"), "true")

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
        self.assertIn("GET", headers.get("access-control-allow-methods", ""))

    def test_unknown_origin_is_not_allowed(self) -> None:
        status, headers, _ = _request("/api/health", headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 200)
        self.assertIsNone(headers.get("access-control-allow-origin"))
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