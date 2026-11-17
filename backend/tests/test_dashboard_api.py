"""API tests for Stage 05 business dashboard."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

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


def _create_business(client: TestClient, headers: dict, name="Acme") -> dict:
    return _auth_post(client, headers, "/api/businesses", json={"name": name}).json()


def _create_asset(client: TestClient, headers: dict, business_id: int, domain="example.com") -> dict:
    return _auth_post(
        client, headers,
        f"/api/businesses/{business_id}/assets",
        json={"domain": domain, "authorization_confirmed": True},
    ).json()


def _seed_scan(
    db_session,
    asset_id: int,
    findings=None,
    status="completed",
    completed_at=None,
) -> int:
    import app.models.models as models
    from app.services.scanner.check_catalog import ALL_GROUPS
    now = completed_at or datetime.now(timezone.utc)
    scan = models.Scan(
        asset_id=asset_id, status=status,
        started_at=now if status in ("running", "completed", "failed") else None,
        completed_at=now if status in ("completed", "failed") else None,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    for code, severity, title, desc, rec, evidence in (findings or []):
        db_session.add(models.Finding(
            scan_id=scan.id, check_code=code, title=title,
            description=desc, severity=severity, recommendation=rec, evidence=evidence,
        ))
    if status == "completed":
        for group in ALL_GROUPS:
            db_session.add(models.CheckResult(
                scan_id=scan.id, check_id=group.check_id, module=group.module, outcome="passed",
            ))
    db_session.commit()
    return scan.id


def _generate_alerts(db_session, scan_id: int):
    from app.services import alert_service
    return alert_service.generate_alerts_for_scan(db_session, scan_id)


# Dashboard Tests

def test_empty_business_dashboard(client: TestClient) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    resp = _auth_get(client, headers, f"/api/businesses/{biz['id']}/dashboard")
    assert resp.status_code == 200
    body = resp.json()
    assert body["business_id"] == biz["id"]
    assert body["total_monitored_websites"] == 0
    assert body["active_websites"] == 0
    assert body["paused_websites"] == 0
    assert body["latest_scan"] is None
    assert body["alert_counts"]["total_unread"] == 0
    assert body["alert_counts"]["total"] == 0
    assert body["critical_security_findings"] == []
    assert body["security_overview"]["average_security_score"] is None
    assert body["security_overview"]["overall_risk_level"] == "unknown"


def test_dashboard_with_assets_scans_alerts(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    a1 = _create_asset(client, headers, biz["id"], "one.example.com")
    a2 = _create_asset(client, headers, biz["id"], "two.example.com")
    # pause one
    _auth_patch(client, headers, f"/api/assets/{a2['id']}", json={"status": "paused"})

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    s1 = _seed_scan(db_session, a1["id"], findings=[
        ("TLS_EXPIRED", "critical", "Cert expired", "Expired", "Renew", "e"),
        ("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None),
    ], completed_at=base)
    s2 = _seed_scan(db_session, a1["id"], findings=[
        ("CSP_MISSING", "medium", "CSP missing", "No CSP", "Add CSP", None),
    ], completed_at=base + timedelta(hours=1))
    _generate_alerts(db_session, s1)
    _generate_alerts(db_session, s2)

    resp = _auth_get(client, headers, f"/api/businesses/{biz['id']}/dashboard")
    assert resp.status_code == 200
    body = resp.json()

    assert body["total_monitored_websites"] == 2
    assert body["active_websites"] == 1
    assert body["paused_websites"] == 1
    assert body["latest_scan"] is not None
    assert body["latest_scan"]["asset_id"] == a1["id"]
    assert body["latest_scan"]["scan_id"] == s2  # most recent by created/id
    assert len(body["critical_security_findings"]) >= 0
    # latest completed scan for asset 1 is s2 (medium only), so no critical in latest
    assert body["alert_counts"]["total_unread"] == 3
    assert "average_security_score" in body["latest_security_scores"]
    assert "overall_risk_level" in body["security_overview"]
    assert len(body["recent_security_activity"]) >= 1


def test_dashboard_missing_business(client: TestClient) -> None:
    headers = _register_and_login(client)
    assert _auth_get(client, headers, "/api/businesses/9999/dashboard").status_code == 404