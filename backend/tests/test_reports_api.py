"""API tests for Stage 05 security reports.

Covers scan report generation, findings/recommendations, missing score handling,
CSV export, historical asset reports, and missing asset/scan handling.
"""

from __future__ import annotations

import csv
import io
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
    outcomes=None,
    status="completed",
    completed_at=None,
) -> int:
    import app.models.models as models
    from app.services.scanner.check_catalog import ALL_GROUPS

    now = completed_at or datetime.now(timezone.utc)
    scan = models.Scan(
        asset_id=asset_id,
        status=status,
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
    db_session.commit()
    if status == "completed":
        outcomes = outcomes or {}
        for group in ALL_GROUPS:
            db_session.add(models.CheckResult(
                scan_id=scan.id, check_id=group.check_id, module=group.module,
                outcome=outcomes.get(group.check_id, "passed"),
            ))
        db_session.commit()
    return scan.id


# Scan Report Tests

def test_scan_report_with_findings_and_score(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _create_asset(client, headers, biz["id"])
    scan_id = _seed_scan(db_session, asset["id"], findings=[
        ("HSTS_MISSING", "high", "HSTS missing", "No header", "Add HSTS", "e1"),
        ("CSP_MISSING", "medium", "CSP missing", "No CSP", "Add CSP", None),
    ])
    resp = _auth_get(client, headers, f"/api/scans/{scan_id}/report")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == scan_id
    assert body["scan_status"] == "completed"
    assert body["business_name"] == "Acme"
    assert body["asset_domain"] == "example.com"
    assert body["findings_total"] == 2
    assert body["findings_by_severity"]["high"] == 1
    assert body["findings_by_severity"]["medium"] == 1
    assert body["score_available"] is True
    assert body["security_score"] == 77  # 100-15-8
    assert body["risk_assessment"] is not None
    assert len(body["findings"]) == 2
    assert len(body["recommendations"]) >= 1


def test_scan_report_missing_score_for_failed_scan(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _create_asset(client, headers, biz["id"])
    scan_id = _seed_scan(db_session, asset["id"], status="failed")
    resp = _auth_get(client, headers, f"/api/scans/{scan_id}/report")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_status"] == "failed"
    assert body["score_available"] is False
    assert body["security_score"] is None
    assert body["unavailable_reason"] is not None
    assert body["risk_assessment"] is None


def test_scan_report_insufficient_coverage(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _create_asset(client, headers, biz["id"])
    outcomes = {"SPF": "unknown", "DMARC": "unknown", "CAA": "unknown"}
    scan_id = _seed_scan(db_session, asset["id"], outcomes=outcomes)
    body = _auth_get(client, headers, f"/api/scans/{scan_id}/report").json()
    assert body["score_available"] is False
    assert body["security_score"] is None
    assert body["unavailable_reason"] is not None
    assert body["scan_coverage"] is not None


def test_missing_scan_report_404(client: TestClient) -> None:
    headers = _register_and_login(client)
    assert _auth_get(client, headers, "/api/scans/9999/report").status_code == 404
    assert _auth_get(client, headers, "/api/scans/9999/report.csv").status_code == 404


# CSV Report Tests

def test_csv_export(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _create_asset(client, headers, biz["id"])
    scan_id = _seed_scan(db_session, asset["id"], findings=[
        ("HSTS_MISSING", "high", "HSTS missing", "No header", "Add HSTS", "ev"),
    ])
    resp = _auth_get(client, headers, f"/api/scans/{scan_id}/report.csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("content-type", "")
    assert f"scan-{scan_id}-report.csv" in resp.headers.get("content-disposition", "")
    reader = csv.DictReader(io.StringIO(resp.text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["scan_id"] == str(scan_id)
    assert rows[0]["check_code"] == "HSTS_MISSING"
    assert rows[0]["severity"] == "high"
    assert rows[0]["asset_domain"] == "example.com"


def test_csv_export_no_findings(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _create_asset(client, headers, biz["id"])
    scan_id = _seed_scan(db_session, asset["id"])
    resp = _auth_get(client, headers, f"/api/scans/{scan_id}/report.csv")
    assert resp.status_code == 200
    reader = csv.DictReader(io.StringIO(resp.text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["finding_id"] == ""


def test_csv_export_sanitizes_formula_injection(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers, name="Acme")
    asset = _create_asset(client, headers, biz["id"], domain="example.com")

    import app.models.models as models

    with db_session:
        business = db_session.get(models.Business, biz["id"])
        stored_asset = db_session.get(models.Asset, asset["id"])
        assert business is not None
        assert stored_asset is not None
        business.name = "=SUM(A1:A2)"
        stored_asset.domain = "+example.com"
        db_session.commit()

    scan_id = _seed_scan(db_session, asset["id"], findings=[
        ("HSTS_MISSING", "high", "@malicious-title", "-danger-desc", "=HYPERLINK(\"http://x\")", "=cmd|' /C calc'!A0"),
    ])
    resp = _auth_get(client, headers, f"/api/scans/{scan_id}/report.csv")
    assert resp.status_code == 200
    reader = csv.DictReader(io.StringIO(resp.text))
    rows = list(reader)
    assert len(rows) == 1
    row = rows[0]
    assert row["business_name"] == "'=SUM(A1:A2)"
    assert row["asset_domain"] == "'+example.com"
    assert row["title"] == "'@malicious-title"
    assert row["description"] == "'-danger-desc"
    assert row["recommendation"] == "'=HYPERLINK(\"http://x\")"
    assert row["evidence"] == "'=cmd|' /C calc'!A0"
    assert row["check_code"] == "HSTS_MISSING"
    assert row["severity"] == "high"


# Asset History Reports Tests

def test_asset_reports_history(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _create_asset(client, headers, biz["id"])
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    _seed_scan(db_session, asset["id"], findings=[("HSTS_MISSING", "high", "H", "d", "r", None)], completed_at=base)
    _seed_scan(db_session, asset["id"], findings=[("CSP_MISSING", "medium", "C", "d", "r", None)], completed_at=base + timedelta(hours=1))
    resp = _auth_get(client, headers, f"/api/assets/{asset['id']}/reports")
    assert resp.status_code == 200
    body = resp.json()
    assert body["asset_id"] == asset["id"]
    assert body["asset_domain"] == "example.com"
    assert len(body["scans"]) == 2
    assert "security_score" in body["scans"][0]
    assert "risk_level" in body["scans"][0]
    assert "scan_status" in body["scans"][0]


def test_asset_reports_missing_asset(client: TestClient) -> None:
    headers = _register_and_login(client)
    assert _auth_get(client, headers, "/api/assets/9999/reports").status_code == 404