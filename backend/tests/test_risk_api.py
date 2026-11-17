"""API tests for the risk assessment endpoints.

Covers:

    * ``GET /api/scans/{scan_id}/risk`` - completed, failed, insufficient
      coverage and unknown scans;
    * ``GET /api/assets/{asset_id}/risk`` - latest completed scan, previous
      score comparison, no-completed-scan and missing-asset errors;
    * ``GET /api/assets/{asset_id}/risk/history`` - historical scores and
      preservation.

Each test runs against an isolated temporary SQLite database. No scanner
network access occurs: scans and findings are persisted directly.
"""

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


def _create_business(client: TestClient, headers: dict, name: str = "Acme") -> dict:
    return _auth_post(client, headers, "/api/businesses", json={"name": name}).json()


def _create_asset(client: TestClient, headers: dict, domain: str = "example.com") -> dict:
    biz = _create_business(client, headers)
    return _auth_post(
        client, headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": domain, "authorization_confirmed": True},
    ).json()


def _seed_scan(
    db_session,
    asset_id: int,
    *,
    findings: list[tuple[str, str]] | None = None,
    outcomes: dict[str, str] | None = None,
    status: str = "completed",
    security_score: int | None = None,
    completed_at: datetime | None = None,
) -> int:
    """Persist a scan with findings and check results; return its ID."""
    import app.models.models as models
    from app.services.scanner.check_catalog import ALL_GROUPS

    now = completed_at or datetime.now(timezone.utc)
    scan = models.Scan(
        asset_id=asset_id,
        status=status,
        security_score=security_score,
        started_at=now if status == "completed" else None,
        completed_at=now if status == "completed" else None,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    for code, severity in findings or []:
        db_session.add(
            models.Finding(
                scan_id=scan.id,
                check_code=code,
                title=f"title {code}",
                description=f"description {code}",
                severity=severity,
                recommendation=f"fix {code}",
            )
        )
    db_session.commit()

    outcomes = outcomes or {}
    if status == "completed":
        for group in ALL_GROUPS:
            db_session.add(
                models.CheckResult(
                    scan_id=scan.id,
                    check_id=group.check_id,
                    module=group.module,
                    outcome=outcomes.get(group.check_id, "passed"),
                    detail=f"test outcome {outcomes.get(group.check_id, 'passed')}",
                )
            )
        db_session.commit()

    return scan.id


def _update_scan_findings(db_session, scan_id: int, code: str, severity: str) -> None:
    import app.models.models as models

    db_session.add(
        models.Finding(
            scan_id=scan_id,
            check_code=code,
            title=f"title {code}",
            description=f"description {code}",
            severity=severity,
            recommendation=f"fix {code}",
        )
    )
    db_session.commit()


# Scan Risk Endpoint Tests

def test_completed_scan_risk(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    scan_id = _seed_scan(
        db_session, asset["id"], findings=[("HSTS_MISSING", "high")]
    )

    resp = _auth_get(client, headers, f"/api/scans/{scan_id}/risk")

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == scan_id
    assert body["asset_id"] == asset["id"]
    assert body["scan_status"] == "completed"
    assert body["score_available"] is True
    assert body["security_score"] == 85
    assert body["risk_level"] == "high"
    assert body["grade"] == "B"
    assert body["coverage"]["percentage"] == 100.0
    assert body["findings_by_severity"]["high"] == 1
    assert len(body["deductions"]) == 1
    assert body["deductions"][0]["check_code"] == "HSTS_MISSING"
    assert body["score_weights"]["critical"] == 25


def test_unknown_scan_returns_404(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_get(client, headers, "/api/scans/999999/risk")
    assert resp.status_code == 404


def test_failed_scan_returns_no_score(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    scan_id = _seed_scan(db_session, asset["id"], status="failed")

    resp = _auth_get(client, headers, f"/api/scans/{scan_id}/risk")

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_status"] == "failed"
    assert body["score_available"] is False
    assert body["security_score"] is None
    assert "failed" in (body["unavailable_reason"] or "").lower()


def test_insufficient_coverage_returns_no_score(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    outcomes = {"SPF": "unknown", "DMARC": "unknown", "CAA": "unknown"}
    scan_id = _seed_scan(db_session, asset["id"], outcomes=outcomes)

    resp = _auth_get(client, headers, f"/api/scans/{scan_id}/risk")

    assert resp.status_code == 200
    body = resp.json()
    assert body["score_available"] is False
    assert body["security_score"] is None
    assert body["coverage"]["unknown"] == 3
    assert body["coverage"]["percentage"] == 78.6
    assert "coverage" in (body["unavailable_reason"] or "").lower()


# Asset Risk Endpoint Tests

def test_latest_completed_scan_is_returned(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    base = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    older = _seed_scan(
        db_session, asset["id"], security_score=90, completed_at=base
    )
    newer = _seed_scan(
        db_session, asset["id"],
        security_score=80,
        completed_at=base + timedelta(hours=1),
    )

    resp = _auth_get(client, headers, f"/api/assets/{asset['id']}/risk")

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == newer
    assert body["scan_id"] != older
    assert body["security_score"] == 80
    assert body["asset_domain"] == "example.com"
    assert body["previous_assessment"]["scan_id"] == older
    assert body["previous_assessment"]["security_score"] == 90
    assert body["score_change"] == -10


def test_latest_completed_ignores_newer_failed_scan(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    base = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    completed = _seed_scan(
        db_session, asset["id"], security_score=80, completed_at=base
    )
    _seed_scan(
        db_session, asset["id"],
        status="failed",
        completed_at=base + timedelta(hours=1),
    )

    body = _auth_get(client, headers, f"/api/assets/{asset['id']}/risk").json()

    assert body["scan_id"] == completed
    assert body["security_score"] == 80


def test_no_completed_scan_returns_404(client: TestClient) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    resp = _auth_get(client, headers, f"/api/assets/{asset['id']}/risk")
    assert resp.status_code == 404


def test_missing_asset_returns_404(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_get(client, headers, "/api/assets/999999/risk")
    assert resp.status_code == 404


def test_history_lists_completed_scans_newest_first(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    base = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    older = _seed_scan(db_session, asset["id"], security_score=90, completed_at=base)
    newer = _seed_scan(
        db_session, asset["id"],
        security_score=80,
        completed_at=base + timedelta(hours=1),
    )

    resp = _auth_get(client, headers, f"/api/assets/{asset['id']}/risk/history")

    assert resp.status_code == 200
    body = resp.json()
    assert [entry["scan_id"] for entry in body] == [newer, older]
    assert [entry["security_score"] for entry in body] == [80, 90]


def test_history_missing_asset_returns_404(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_get(client, headers, "/api/assets/999999/risk/history")
    assert resp.status_code == 404


def test_historical_score_is_not_recomputed(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    scan_id = _seed_scan(
        db_session, asset["id"], findings=[("CRIT", "critical")]
    )

    first = _auth_get(client, headers, f"/api/scans/{scan_id}/risk").json()
    assert first["security_score"] == 75

    # A later finding must not alter the already-persisted assessment.
    _update_scan_findings(db_session, scan_id, "CRIT_2", "critical")
    second = _auth_get(client, headers, f"/api/scans/{scan_id}/risk").json()

    assert second["security_score"] == 75
    assert len(second["deductions"]) == 1


def test_pre_existing_score_is_preserved(client: TestClient, db_session) -> None:
    headers = _register_and_login(client)
    asset = _create_asset(client, headers)
    scan_id = _seed_scan(
        db_session, asset["id"],
        findings=[("CRIT", "critical")],
        security_score=42,
    )

    body = _auth_get(client, headers, f"/api/scans/{scan_id}/risk").json()

    assert body["security_score"] == 42
    assert body["score_source"] == "stored"