"""API and service tests for Stage 05 alerts.

Covers:
    * Automatic alert generation from actionable findings.
    * Severity classification and info/non-actionable exclusion.
    * Duplicate prevention and reappearing resolved issues.
    * Read/resolve operations.
    * Filtering, pagination and summary accuracy.

Tests run against an isolated temporary SQLite database and never make network
requests.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.services.scanner.target_validator import UnsafeTargetError, TargetDNSResolutionError
from unittest import mock

from tests.test_auth_helpers import get_auth_headers, login_user, register_user


# Helper functions

def _register_and_login(client: TestClient) -> tuple[str, dict]:
    """Register and login a test user, return token and headers."""
    register_user(client, "test@example.com", "password1234")
    token_data = login_user(client, "test@example.com", "password1234")
    token = token_data["access_token"]
    headers = get_auth_headers(token)
    return token, headers


def _auth_post(client: TestClient, headers: dict, path: str, json: dict | None = None, **kwargs):
    return client.post(path, json=json, headers=headers, **kwargs)


def _auth_get(client: TestClient, headers: dict, path: str, **kwargs):
    return client.get(path, headers=headers, **kwargs)


def _auth_patch(client: TestClient, headers: dict, path: str, json: dict | None = None, **kwargs):
    return client.patch(path, json=json, headers=headers, **kwargs)


def _create_business(client: TestClient, headers: dict, name: str = "Acme") -> dict:
    return _auth_post(client, headers, "/api/businesses", json={"name": name}).json()


def _create_asset(client: TestClient, headers: dict, business_id: int, domain: str = "example.com") -> dict:
    return _auth_post(
        client, headers,
        f"/api/businesses/{business_id}/assets",
        json={"domain": domain, "authorization_confirmed": True},
    ).json()


def _seed_scan_with_findings(db_session, asset_id: int, findings):
    import app.models.models as models
    from app.services.scanner.check_catalog import ALL_GROUPS

    now = datetime.now(timezone.utc)
    scan = models.Scan(
        asset_id=asset_id,
        status="completed",
        started_at=now,
        completed_at=now,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    for code, severity, title, desc, rec, evidence in findings:
        db_session.add(
            models.Finding(
                scan_id=scan.id,
                check_code=code,
                title=title,
                description=desc,
                severity=severity,
                recommendation=rec,
                evidence=evidence,
            )
        )
    for group in ALL_GROUPS:
        db_session.add(
            models.CheckResult(
                scan_id=scan.id,
                check_id=group.check_id,
                module=group.module,
                outcome="passed",
            )
        )
    db_session.commit()
    return scan.id


def _generate_alerts(db_session, scan_id: int):
    from app.services import alert_service

    return alert_service.generate_alerts_for_scan(db_session, scan_id)


def _setup_alerts(client: TestClient, headers: dict, db_session):
    biz = _create_business(client, headers)
    asset = _create_asset(client, headers, biz["id"])
    scan_id = _seed_scan_with_findings(
        db_session, asset["id"],
        [
            ("TLS_EXPIRED", "critical", "Cert expired", "Expired", "Renew", "e"),
            ("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None),
            ("CSP_MISSING", "medium", "CSP missing", "No CSP", "Add CSP", None),
            ("REF_MISSING", "low", "Referrer missing", "No RP", "Add RP", None),
        ],
    )
    _generate_alerts(db_session, scan_id)
    return biz, asset


# Alert Generation Tests

def test_generates_alerts_for_actionable_severities(client: TestClient, db_session) -> None:
    token, headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _create_asset(client, headers, biz["id"])
    scan_id = _seed_scan_with_findings(
        db_session, asset["id"],
        [
            ("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None),
            ("CSP_MISSING", "medium", "CSP missing", "No CSP", "Add CSP", None),
            ("REF_MISSING", "low", "Referrer missing", "No RP", "Add RP", None),
            ("TLS_EXPIRED", "critical", "Cert expired", "Expired", "Renew", "exp"),
            ("CAA_PRESENT", "info", "CAA present", "CAA ok", "None", None),
        ],
    )
    created = _generate_alerts(db_session, scan_id)
    assert len(created) == 4
    assert {a.severity for a in created} == {"critical", "high", "medium", "low"}


def test_no_alert_for_info_only(client: TestClient, db_session) -> None:
    token, headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _create_asset(client, headers, biz["id"])
    scan_id = _seed_scan_with_findings(
        db_session, asset["id"],
        [("CAA_PRESENT", "info", "CAA present", "CAA ok", "None", None)],
    )
    created = _generate_alerts(db_session, scan_id)
    assert created == []


def test_no_duplicate_unresolved_alert_for_same_issue(client: TestClient, db_session) -> None:
    token, headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _create_asset(client, headers, biz["id"])
    scan1 = _seed_scan_with_findings(
        db_session, asset["id"],
        [("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None)],
    )
    scan2 = _seed_scan_with_findings(
        db_session, asset["id"],
        [("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None)],
    )
    first = _generate_alerts(db_session, scan1)
    second = _generate_alerts(db_session, scan2)
    assert len(first) == 1
    assert len(second) == 0


def test_reappearing_resolved_issue_creates_new_alert(client: TestClient, db_session) -> None:
    token, headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _create_asset(client, headers, biz["id"])
    scan1 = _seed_scan_with_findings(
        db_session, asset["id"],
        [("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None)],
    )
    first = _generate_alerts(db_session, scan1)
    assert len(first) == 1
    # resolve existing alert
    resp = _auth_patch(client, headers, f"/api/alerts/{first[0].id}", json={"resolved": True})
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"

    scan2 = _seed_scan_with_findings(
        db_session, asset["id"],
        [("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None)],
    )
    second = _generate_alerts(db_session, scan2)
    assert len(second) == 1
    assert second[0].id != first[0].id

    # history preserved: resolved alert still exists
    all_alerts = _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts?page_size=50").json()
    assert all_alerts["total"] == 2
    statuses = {a["status"] for a in all_alerts["items"]}
    assert statuses == {"resolved", "unread"}


# Alert API Tests

def test_list_alerts_and_get_detail(client: TestClient, db_session) -> None:
    token, headers = _register_and_login(client)
    biz, _ = _setup_alerts(client, headers, db_session)
    resp = _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 4
    assert len(body["items"]) == 4
    alert_id = body["items"][0]["id"]
    detail = _auth_get(client, headers, f"/api/alerts/{alert_id}")
    assert detail.status_code == 200
    assert detail.json()["id"] == alert_id


def test_filter_by_severity_and_status(client: TestClient, db_session) -> None:
    token, headers = _register_and_login(client)
    biz, _ = _setup_alerts(client, headers, db_session)
    resp = _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts?severity=critical")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "critical"

    alert_id = body["items"][0]["id"]
    _auth_patch(client, headers, f"/api/alerts/{alert_id}", json={"read": True})
    unread = _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts?status=unread")
    assert unread.json()["total"] == 3
    read = _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts?status=read")
    assert read.json()["total"] == 1


def test_pagination(client: TestClient, db_session) -> None:
    token, headers = _register_and_login(client)
    biz, _ = _setup_alerts(client, headers, db_session)
    p1 = _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts?page=1&page_size=2").json()
    p2 = _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts?page=2&page_size=2").json()
    assert p1["total"] == 4
    assert len(p1["items"]) == 2
    assert len(p2["items"]) == 2
    assert p1["pages"] == 2
    ids1 = {a["id"] for a in p1["items"]}
    ids2 = {a["id"] for a in p2["items"]}
    assert ids1.isdisjoint(ids2)


def test_mark_read_and_resolve(client: TestClient, db_session) -> None:
    token, headers = _register_and_login(client)
    biz, _ = _setup_alerts(client, headers, db_session)
    alert_id = _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts").json()["items"][0]["id"]
    read_resp = _auth_patch(client, headers, f"/api/alerts/{alert_id}", json={"read": True})
    assert read_resp.status_code == 200
    assert read_resp.json()["status"] == "read"
    assert read_resp.json()["read_at"] is not None

    resolve_resp = _auth_patch(client, headers, f"/api/alerts/{alert_id}", json={"resolved": True})
    assert resolve_resp.status_code == 200
    assert resolve_resp.json()["status"] == "resolved"
    assert resolve_resp.json()["resolved_at"] is not None


def test_summary_counts(client: TestClient, db_session) -> None:
    token, headers = _register_and_login(client)
    biz, _ = _setup_alerts(client, headers, db_session)
    summary = _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts/summary").json()
    assert summary["total"] == 4
    assert summary["unread"] == 4
    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert summary["medium"] == 1
    assert summary["low"] == 1
    assert summary["resolved"] == 0

    alert_id = _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts?severity=high").json()["items"][0]["id"]
    _auth_patch(client, headers, f"/api/alerts/{alert_id}", json={"resolved": True})
    summary2 = _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts/summary").json()
    assert summary2["resolved"] == 1
    assert summary2["unread"] == 3
    assert summary2["high"] == 1


def test_alert_404s(client: TestClient, db_session) -> None:
    token, headers = _register_and_login(client)
    assert _auth_get(client, headers, "/api/alerts/9999").status_code == 404
    assert _auth_patch(client, headers, "/api/alerts/9999", json={"read": True}).status_code == 404
    assert _auth_get(client, headers, "/api/businesses/9999/alerts").status_code == 404
    assert _auth_get(client, headers, "/api/businesses/9999/alerts/summary").status_code == 404


def test_invalid_filters(client: TestClient, db_session) -> None:
    token, headers = _register_and_login(client)
    biz, _ = _setup_alerts(client, headers, db_session)
    assert _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts?severity=bogus").status_code == 422
    assert _auth_get(client, headers, f"/api/businesses/{biz['id']}/alerts?status=bogus").status_code == 422