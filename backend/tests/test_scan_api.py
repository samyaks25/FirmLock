"""API tests for the scanner endpoints.

Network access is avoided by patching ``scan_manager.resolve_and_validate``.
In celery mode the enqueue is mocked and scans are executed directly. In inline
mode scans execute via FastAPI BackgroundTasks with a fresh DB session.
"""

from __future__ import annotations

from unittest import mock

from fastapi.testclient import TestClient

from app.core.config import settings
from app.services.scanner.target_validator import (
    TargetDNSResolutionError,
    UnsafeTargetError,
)

from tests.test_auth_helpers import get_auth_headers, login_user, register_user


def _register_and_login(client: TestClient) -> dict:
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
        client,
        headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": domain, "authorization_confirmed": True},
    ).json()


def _patch_resolve(exc):
    import app.services.scanner.scan_manager as scan_manager

    return mock.patch.object(scan_manager, "resolve_and_validate", side_effect=exc)


def _run_scan_direct(scan_id: int) -> None:
    from app.database.connection import SessionLocal
    from app.services.scanner.scan_manager import run_scan

    run_scan(scan_id, session_factory=SessionLocal)


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
    exc = UnsafeTargetError("blocked")
    with _patch_resolve(exc):
        resp = _auth_post(client, headers, f"/api/assets/{asset['id']}/scan")
    assert resp.status_code == 202
    data = resp.json()
    assert "scan_id" in data
    assert data["asset_id"] == asset["id"]
    assert data["status"] == "pending"


def test_completed_scan_persists_findings(client: TestClient) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    exc = UnsafeTargetError("resolves to 10.0.0.1")
    with _patch_resolve(exc):
        start = _auth_post(client, headers, f"/api/assets/{asset['id']}/scan")
    scan_id = start.json()["scan_id"]

    if settings.scan_execution_mode == "celery":
        with _patch_resolve(exc):
            _run_scan_direct(scan_id)

    resp = _auth_get(client, headers, f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["started_at"] is not None
    assert body["completed_at"] is not None
    assert len(body["findings"]) >= 1
    assert "TARGET_SSRF_REJECTED" in {f["check_code"] for f in body["findings"]}
    asset_resp = _auth_get(client, headers, f"/api/assets/{asset['id']}")
    assert asset_resp.json()["last_scanned_at"] is not None


def test_failed_scan_marked_failed(client: TestClient) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    exc = TargetDNSResolutionError("no such host")
    with _patch_resolve(exc):
        start = _auth_post(client, headers, f"/api/assets/{asset['id']}/scan")
    scan_id = start.json()["scan_id"]

    if settings.scan_execution_mode == "celery":
        with _patch_resolve(exc):
            _run_scan_direct(scan_id)

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
    with _patch_resolve(UnsafeTargetError("blocked")):
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


def test_worker_health_endpoint_exposes_mode(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_get(client, headers, "/api/health/workers")
    assert resp.status_code == 200
    body = resp.json()
    assert "mode" in body
    assert "redis" in body and "workers" in body
