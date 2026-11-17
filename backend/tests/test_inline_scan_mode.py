"""Execution-mode tests for local inline demo mode (no Redis/Celery/worker)."""

from __future__ import annotations

import builtins
import importlib
import sys

from fastapi.testclient import TestClient

from tests.test_auth_helpers import get_auth_headers, login_user, register_user


def _register_and_login(client: TestClient) -> dict:
    register_user(client, "inline@example.com", "password1234")
    token_data = login_user(client, "inline@example.com", "password1234")
    return get_auth_headers(token_data["access_token"])


def _auth_post(client: TestClient, headers: dict, path: str, json: dict | None = None):
    return client.post(path, json=json, headers=headers)


def _auth_get(client: TestClient, headers: dict, path: str):
    return client.get(path, headers=headers)


def _reload_for_inline(monkeypatch):
    monkeypatch.setenv("FIRMLOCK_SCAN_EXECUTION_MODE", "inline")
    monkeypatch.delenv("FIRMLOCK_REDIS_URL", raising=False)

    # Ensure lazy Celery app state does not leak from previous imports.
    for mod in [
        "app.core.celery_config",
        "app.core.worker_health",
        "app.core.config",
        "app.api.routes.scans",
        "app.main",
        "app.api.router",
    ]:
        sys.modules.pop(mod, None)

    config = importlib.import_module("app.core.config")
    scans_route = importlib.import_module("app.api.routes.scans")
    main = importlib.import_module("app.main")
    worker_health = importlib.import_module("app.core.worker_health")
    return config, scans_route, main, worker_health


def _make_client(test_db, monkeypatch):
    engine, TestingSessionLocal = test_db
    from app.database.connection import get_db
    from app.services.scanner import scan_manager
    from app.database import connection

    orig_conn_sl = connection.SessionLocal
    orig_conn_engine = connection.engine
    orig_scan_sl = scan_manager.SessionLocal
    connection.SessionLocal = TestingSessionLocal
    connection.engine = engine
    scan_manager.SessionLocal = TestingSessionLocal

    config, scans_route, main, worker_health = _reload_for_inline(monkeypatch)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = override_get_db
    client = TestClient(main.app)
    return client, config, scans_route, main, worker_health, (orig_conn_sl, orig_conn_engine, orig_scan_sl)


def _cleanup_client(client, main, originals):
    client.close()
    main.app.dependency_overrides.clear()
    from app.database import connection
    from app.services.scanner import scan_manager

    connection.SessionLocal, connection.engine, scan_manager.SessionLocal = originals


def _setup_authorized_asset(client: TestClient, headers: dict) -> int:
    biz = _auth_post(client, headers, "/api/businesses", json={"name": "InlineCo"}).json()
    asset = _auth_post(
        client,
        headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": "example.com", "authorization_confirmed": True},
    ).json()
    return asset["id"]


def test_inline_mode_does_not_import_redis_or_connect(test_db, monkeypatch):
    real_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "redis" or name.startswith("redis."):
            raise AssertionError("redis imported in inline mode")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    client, config, scans_route, main, worker_health, originals = _make_client(test_db, monkeypatch)
    try:
        assert config.settings.scan_execution_mode == "inline"
        health = worker_health.get_worker_health()
        assert health.redis_available is False
        assert "Inline" in (health.redis_error or "")
    finally:
        _cleanup_client(client, main, originals)


def test_inline_scan_completes_and_persists_real_findings_risk_alerts(test_db, monkeypatch):
    client, config, scans_route, main, worker_health, originals = _make_client(test_db, monkeypatch)
    try:
        from app.services.scanner.target_validator import UnsafeTargetError
        from app.services.scanner import scan_manager

        headers = _register_and_login(client)
        asset_id = _setup_authorized_asset(client, headers)

        monkeypatch.setattr(
            scan_manager,
            "resolve_and_validate",
            lambda hostname, cfg, resolver=None: (_ for _ in ()).throw(
                UnsafeTargetError("resolves to 10.0.0.1")
            ),
        )

        resp = _auth_post(client, headers, f"/api/assets/{asset_id}/scan")
        assert resp.status_code == 202
        scan_id = resp.json()["scan_id"]

        scan_resp = _auth_get(client, headers, f"/api/scans/{scan_id}")
        assert scan_resp.status_code == 200
        scan = scan_resp.json()
        assert scan["status"] == "completed"
        assert scan["started_at"] is not None and scan["completed_at"] is not None
        assert len(scan["findings"]) >= 1
        assert "TARGET_SSRF_REJECTED" in {f["check_code"] for f in scan["findings"]}

        risk_resp = _auth_get(client, headers, f"/api/scans/{scan_id}/risk")
        assert risk_resp.status_code == 200
        risk = risk_resp.json()
        assert "score_available" in risk
        assert risk["findings_total"] >= 1

        biz_list = _auth_get(client, headers, "/api/businesses").json()
        assert biz_list
        business_id = biz_list[0]["id"]
        alerts_resp = _auth_get(client, headers, f"/api/businesses/{business_id}/alerts")
        assert alerts_resp.status_code == 200
        # Alerts are generated from actionable persisted findings in the real pipeline.
        assert isinstance(alerts_resp.json().get("total"), int)

        asset_resp = _auth_get(client, headers, f"/api/assets/{asset_id}")
        assert asset_resp.json()["last_scanned_at"] is not None
    finally:
        _cleanup_client(client, main, originals)


def test_inline_scan_failed_does_not_get_stuck(test_db, monkeypatch):
    client, config, scans_route, main, worker_health, originals = _make_client(test_db, monkeypatch)
    try:
        from app.services.scanner.target_validator import TargetDNSResolutionError
        from app.services.scanner import scan_manager

        headers = _register_and_login(client)
        asset_id = _setup_authorized_asset(client, headers)

        monkeypatch.setattr(
            scan_manager,
            "resolve_and_validate",
            lambda hostname, cfg, resolver=None: (_ for _ in ()).throw(
                TargetDNSResolutionError("no such host")
            ),
        )

        resp = _auth_post(client, headers, f"/api/assets/{asset_id}/scan")
        assert resp.status_code == 202
        scan_id = resp.json()["scan_id"]

        scan_resp = _auth_get(client, headers, f"/api/scans/{scan_id}")
        assert scan_resp.status_code == 200
        body = scan_resp.json()
        assert body["status"] == "failed"
        assert body["completed_at"] is not None
    finally:
        _cleanup_client(client, main, originals)


def test_inline_authorization_guards_still_enforced(test_db, monkeypatch):
    client, config, scans_route, main, worker_health, originals = _make_client(test_db, monkeypatch)
    try:
        headers = _register_and_login(client)
        biz = _auth_post(client, headers, "/api/businesses", json={"name": "InlineAuth"}).json()
        asset_resp = _auth_post(
            client,
            headers,
            f"/api/businesses/{biz['id']}/assets",
            json={"domain": "auth.example", "authorization_confirmed": True},
        )
        assert asset_resp.status_code == 201
        asset_id = asset_resp.json()["id"]

        # Remove authorization after creation to exercise scan-time guard.
        from app.database import connection
        import app.models.models as models

        db = connection.SessionLocal()
        try:
            asset = db.get(models.Asset, asset_id)
            asset.authorization_confirmed = False
            db.commit()
        finally:
            db.close()

        resp = _auth_post(client, headers, f"/api/assets/{asset_id}/scan")
        assert resp.status_code == 403
    finally:
        _cleanup_client(client, main, originals)


def test_inline_worker_health_endpoint_reports_mode(test_db, monkeypatch):
    client, config, scans_route, main, worker_health, originals = _make_client(test_db, monkeypatch)
    try:
        headers = _register_and_login(client)
        resp = _auth_get(client, headers, "/api/health/workers")
        assert resp.status_code == 200
        body = resp.json()
        assert body["mode"] == "inline"
        assert body["redis"]["available"] is False
    finally:
        _cleanup_client(client, main, originals)
