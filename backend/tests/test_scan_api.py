"""API tests for the scanner endpoints.

Covers:
    * ``POST /api/assets/{asset_id}/scan`` - authorization/active/monitoring
      guards (403), missing asset (404) and a successful queued scan (202).
    * ``GET /api/scans/{scan_id}`` - completed scan with persisted findings,
      failed scan, and 404 for unknown scans.
    * ``GET /api/assets/{asset_id}/scans`` - history listing and 404.

The scanner's network access is avoided by patching
``scan_manager.resolve_and_validate`` to raise a controlled error, so no real
DNS or HTTP requests are made. The background task still executes end-to-end
against an isolated temporary SQLite database.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient
from starlette.background import BackgroundTasks

from app.services.scanner.target_validator import (
    TargetDNSResolutionError,
    UnsafeTargetError,
)

from tests.test_auth_helpers import get_auth_headers, login_user, register_user


# Helper functions

def _register_and_login(client: TestClient) -> dict:
    """Register and login a test user, return headers with token."""
    register_user(client, "test@example.com", "password1234")
    token_data = login_user(client, "test@example.com", "password1234")
    return get_auth_headers(token_data["access_token"])


def _auth_post(client: TestClient, headers: dict, path: str, json: dict | None = None, **kwargs):
    return client.post(path, json=json, headers=headers, **kwargs)


def _auth_get(client: TestClient, headers: dict, path: str, **kwargs):
    return client.get(path, headers=headers, **kwargs)


def _auth_patch(client: TestClient, headers: dict, path: str, json: dict | None = None, **kwargs):
    return client.patch(path, json=json, headers=headers, **kwargs)


def _create_business(client: TestClient, headers: dict, name: str = "Acme") -> dict:
    return _auth_post(client, headers, "/api/businesses", json={"name": name}).json()


def _create_asset(client: TestClient, headers: dict, domain: str = "example.com") -> dict:
    biz = _create_business(client, headers)
    return _auth_post(
        client, headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": domain, "authorization_confirmed": True},
    ).json()


def _patch_resolve(exc):
    """Patch the scan manager's resolve_and_validate to raise ``exc``."""
    import app.services.scanner.scan_manager as scan_manager

    return mock.patch.object(scan_manager, "resolve_and_validate", side_effect=exc)


def _patch_background_tasks():
    """Patch BackgroundTasks.add_task to run functions synchronously."""
    def mock_add_task(self, func, *args, **kwargs):
        func(*args, **kwargs)
    return mock.patch.object(BackgroundTasks, "add_task", mock_add_task)


def _update_asset(db_session, asset_id: int, **fields) -> None:
    import app.models.models as models

    asset = db_session.get(models.Asset, asset_id)
    for key, value in fields.items():
        setattr(asset, key, value)
    db_session.commit()


# Start Scan Guard Tests

def test_scan_missing_asset_returns_404(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_post(client, headers, "/api/assets/999999/scan")
    assert resp.status_code == 404


def test_scan_unauthorised_asset_returns_403(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    _update_asset(db_session, asset["id"], authorization_confirmed=False)
    resp = _auth_post(client, headers, f"/api/assets/{asset['id']}/scan")
    assert resp.status_code == 403


def test_scan_paused_asset_returns_403(client: TestClient) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    _auth_patch(client, headers, f"/api/assets/{asset['id']}", json={"status": "paused"})
    resp = _auth_post(client, headers, f"/api/assets/{asset['id']}/scan")
    assert resp.status_code == 403


def test_scan_monitoring_disabled_returns_403(client: TestClient) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    _auth_patch(client, headers, f"/api/assets/{asset['id']}", json={"monitoring_enabled": False})
    resp = _auth_post(client, headers, f"/api/assets/{asset['id']}/scan")
    assert resp.status_code == 403


# Scan Lifecycle Tests

def test_start_scan_returns_202_with_pending_status(client: TestClient) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    with _patch_resolve(UnsafeTargetError("blocked")), _patch_background_tasks():
        resp = _auth_post(client, headers, f"/api/assets/{asset['id']}/scan")
    assert resp.status_code == 202
    data = resp.json()
    assert "scan_id" in data
    assert data["asset_id"] == asset["id"]
    assert data["status"] == "pending"


def test_completed_scan_persists_findings(client: TestClient) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    with _patch_resolve(UnsafeTargetError("resolves to 10.0.0.1")), _patch_background_tasks():
        start = _auth_post(client, headers, f"/api/assets/{asset['id']}/scan")
    scan_id = start.json()["scan_id"]

    resp = _auth_get(client, headers, f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["started_at"] is not None
    assert body["completed_at"] is not None
    assert len(body["findings"]) >= 1
    assert "TARGET_SSRF_REJECTED" in {f["check_code"] for f in body["findings"]}
    # Asset last_scanned_at updated.
    asset_resp = _auth_get(client, headers, f"/api/assets/{asset['id']}")
    assert asset_resp.json()["last_scanned_at"] is not None


def test_failed_scan_marked_failed(client: TestClient) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    with _patch_resolve(TargetDNSResolutionError("no such host")), _patch_background_tasks():
        start = _auth_post(client, headers, f"/api/assets/{asset['id']}/scan")
    scan_id = start.json()["scan_id"]

    resp = _auth_get(client, headers, f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failed"
    assert body["completed_at"] is not None


def test_get_unknown_scan_returns_404(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_get(client, headers, "/api/scans/999999")
    assert resp.status_code == 404


# Scan History Tests

def test_list_scans_for_asset(client: TestClient) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    with _patch_resolve(UnsafeTargetError("blocked")), _patch_background_tasks():
        _auth_post(client, headers, f"/api/assets/{asset['id']}/scan")

    resp = _auth_get(client, headers, f"/api/assets/{asset['id']}/scans")
    assert resp.status_code == 200
    scans = resp.json()
    assert len(scans) == 1
    assert scans[0]["asset_id"] == asset["id"]


def test_list_scans_missing_asset_returns_404(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_get(client, headers, "/api/assets/999999/scans")
    assert resp.status_code == 404