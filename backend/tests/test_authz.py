"""Authorization and membership tests for Stage 06.

Covers:
    * Business ownership auto-assignment on creation
    * Owner/admin/member permissions
    * Cross-business data isolation
    * Role-based access to assets, scans, alerts, reports, dashboard
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_auth_helpers import get_auth_headers, login_user, register_user


# Helper functions

def _register_and_login(client: TestClient, email: str) -> dict:
    """Register and login a user, return headers with token."""
    register_user(client, email, "strongpassword123")
    token_data = login_user(client, email, "strongpassword123")
    return get_auth_headers(token_data["access_token"])


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


def _add_member(db_session, owner_headers: dict, business_id: int, member_email: str, role: str) -> dict:
    """Add a member to a business (direct DB manipulation for testing)."""
    import app.models.models as models
    from app.services import membership_service

    # Get member user
    member = db_session.query(models.User).filter(models.User.email == member_email).first()
    # Create membership
    membership = membership_service.create_membership(db_session, member.id, business_id, role)
    db_session.refresh(membership)
    return {"id": membership.id, "user_id": member.id, "role": membership.role}


# Business Ownership Tests

def test_creator_becomes_owner(client: TestClient) -> None:
    headers = _register_and_login(client, "owner@example.com")
    biz = _create_business(client, headers, "Acme")
    # Creator should be able to manage assets (owner permission)
    asset = _create_asset(client, headers, biz["id"])
    assert asset["business_id"] == biz["id"]


def test_cannot_access_other_users_business(client: TestClient) -> None:
    owner_headers = _register_and_login(client, "owner@example.com")
    other_headers = _register_and_login(client, "other@example.com")

    biz = _create_business(client, owner_headers, "Acme")

    # Other user should not be able to access the business
    resp = _auth_get(client, other_headers, f"/api/businesses/{biz['id']}")
    assert resp.status_code == 403

    # Other user should not be able to list the business
    resp = _auth_get(client, other_headers, "/api/businesses")
    assert resp.status_code == 200
    assert len(resp.json()) == 0  # No businesses visible


def test_business_listing_is_scoped_to_user(client: TestClient) -> None:
    owner1_headers = _register_and_login(client, "owner1@example.com")
    owner2_headers = _register_and_login(client, "owner2@example.com")

    biz1 = _create_business(client, owner1_headers, "Business 1")
    biz2 = _create_business(client, owner2_headers, "Business 2")

    resp1 = _auth_get(client, owner1_headers, "/api/businesses")
    assert len(resp1.json()) == 1
    assert resp1.json()[0]["id"] == biz1["id"]

    resp2 = _auth_get(client, owner2_headers, "/api/businesses")
    assert len(resp2.json()) == 1
    assert resp2.json()[0]["id"] == biz2["id"]


# Role Based Permission Tests

def test_owner_can_manage_assets(client: TestClient) -> None:
    owner_headers = _register_and_login(client, "owner@example.com")
    biz = _create_business(client, owner_headers, "Acme")
    asset = _create_asset(client, owner_headers, biz["id"])
    assert asset["business_id"] == biz["id"]


def test_admin_can_manage_assets(client: TestClient, db_session) -> None:
    owner_headers = _register_and_login(client, "owner@example.com")
    biz = _create_business(client, owner_headers, "Acme")

    admin_headers = _register_and_login(client, "admin@example.com")
    _add_member(db_session, owner_headers, biz["id"], "admin@example.com", "admin")

    asset = _create_asset(client, admin_headers, biz["id"])
    assert asset["business_id"] == biz["id"]


def test_member_cannot_manage_assets(client: TestClient, db_session) -> None:
    owner_headers = _register_and_login(client, "owner@example.com")
    biz = _create_business(client, owner_headers, "Acme")

    member_headers = _register_and_login(client, "member@example.com")
    _add_member(db_session, owner_headers, biz["id"], "member@example.com", "member")

    resp = _auth_post(
        client, member_headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": "example.com", "authorization_confirmed": True}
    )
    assert resp.status_code == 403


def test_owner_can_start_scans(client: TestClient) -> None:
    owner_headers = _register_and_login(client, "owner@example.com")
    biz = _create_business(client, owner_headers, "Acme")
    asset = _create_asset(client, owner_headers, biz["id"])

    # Mock the scan to avoid network calls
    from unittest import mock
    from app.services.scanner.target_validator import UnsafeTargetError

    with mock.patch("app.services.scanner.scan_manager.resolve_and_validate", side_effect=UnsafeTargetError("blocked")):
        resp = _auth_post(client, owner_headers, f"/api/assets/{asset['id']}/scan")
    assert resp.status_code == 202


def test_admin_can_start_scans(client: TestClient, db_session) -> None:
    owner_headers = _register_and_login(client, "owner@example.com")
    biz = _create_business(client, owner_headers, "Acme")
    asset = _create_asset(client, owner_headers, biz["id"])

    admin_headers = _register_and_login(client, "admin@example.com")
    _add_member(db_session, owner_headers, biz["id"], "admin@example.com", "admin")

    from unittest import mock
    from app.services.scanner.target_validator import UnsafeTargetError

    with mock.patch("app.services.scanner.scan_manager.resolve_and_validate", side_effect=UnsafeTargetError("blocked")):
        resp = _auth_post(client, admin_headers, f"/api/assets/{asset['id']}/scan")
    assert resp.status_code == 202


def test_member_cannot_start_scans(client: TestClient, db_session) -> None:
    owner_headers = _register_and_login(client, "owner@example.com")
    biz = _create_business(client, owner_headers, "Acme")
    asset = _create_asset(client, owner_headers, biz["id"])

    member_headers = _register_and_login(client, "member@example.com")
    _add_member(db_session, owner_headers, biz["id"], "member@example.com", "member")

    from unittest import mock
    from app.services.scanner.target_validator import UnsafeTargetError

    with mock.patch("app.services.scanner.scan_manager.resolve_and_validate", side_effect=UnsafeTargetError("blocked")):
        resp = _auth_post(client, member_headers, f"/api/assets/{asset['id']}/scan")
    assert resp.status_code == 403


def test_all_roles_can_read_assets(client: TestClient, db_session) -> None:
    owner_headers = _register_and_login(client, "owner@example.com")
    biz = _create_business(client, owner_headers, "Acme")
    asset = _create_asset(client, owner_headers, biz["id"])

    for role, email in [("admin", "admin@example.com"), ("member", "member@example.com")]:
        member_headers = _register_and_login(client, email)
        _add_member(db_session, owner_headers, biz["id"], email, role)

        resp = _auth_get(client, member_headers, f"/api/assets/{asset['id']}")
        assert resp.status_code == 200
        assert resp.json()["id"] == asset["id"]


def test_all_roles_can_read_scans(client: TestClient, db_session) -> None:
    owner_headers = _register_and_login(client, "owner@example.com")
    biz = _create_business(client, owner_headers, "Acme")
    asset = _create_asset(client, owner_headers, biz["id"])

    from unittest import mock
    from app.services.scanner.target_validator import UnsafeTargetError

    with mock.patch("app.services.scanner.scan_manager.resolve_and_validate", side_effect=UnsafeTargetError("blocked")):
        scan_resp = _auth_post(client, owner_headers, f"/api/assets/{asset['id']}/scan")
    scan_id = scan_resp.json()["scan_id"]

    for role, email in [("admin", "admin@example.com"), ("member", "member@example.com")]:
        member_headers = _register_and_login(client, email)
        _add_member(db_session, owner_headers, biz["id"], email, role)

        resp = _auth_get(client, member_headers, f"/api/scans/{scan_id}")
        assert resp.status_code == 200


def test_all_roles_can_access_reports(client: TestClient, db_session) -> None:
    owner_headers = _register_and_login(client, "owner@example.com")
    biz = _create_business(client, owner_headers, "Acme")
    asset = _create_asset(client, owner_headers, biz["id"])

    from unittest import mock
    from app.services.scanner.target_validator import UnsafeTargetError

    with mock.patch("app.services.scanner.scan_manager.resolve_and_validate", side_effect=UnsafeTargetError("blocked")):
        scan_resp = _auth_post(client, owner_headers, f"/api/assets/{asset['id']}/scan")
    scan_id = scan_resp.json()["scan_id"]

    for role, email in [("admin", "admin@example.com"), ("member", "member@example.com")]:
        member_headers = _register_and_login(client, email)
        _add_member(db_session, owner_headers, biz["id"], email, role)

        resp = _auth_get(client, member_headers, f"/api/scans/{scan_id}/report")
        assert resp.status_code == 200


def test_all_roles_can_access_dashboard(client: TestClient, db_session) -> None:
    owner_headers = _register_and_login(client, "owner@example.com")
    biz = _create_business(client, owner_headers, "Acme")

    for role, email in [("admin", "admin@example.com"), ("member", "member@example.com")]:
        member_headers = _register_and_login(client, email)
        _add_member(db_session, owner_headers, biz["id"], email, role)

        resp = _auth_get(client, member_headers, f"/api/businesses/{biz['id']}/dashboard")
        assert resp.status_code == 200


# Cross Business Isolation Tests

def test_user_cannot_access_asset_from_other_business(client: TestClient) -> None:
    owner1_headers = _register_and_login(client, "owner1@example.com")
    owner2_headers = _register_and_login(client, "owner2@example.com")

    biz1 = _create_business(client, owner1_headers, "Business 1")
    biz2 = _create_business(client, owner2_headers, "Business 2")

    asset1 = _create_asset(client, owner1_headers, biz1["id"])

    # Owner2 should not be able to access Owner1's asset
    resp = _auth_get(client, owner2_headers, f"/api/assets/{asset1['id']}")
    assert resp.status_code == 403


def test_user_cannot_access_scan_from_other_business(client: TestClient) -> None:
    owner1_headers = _register_and_login(client, "owner1@example.com")
    owner2_headers = _register_and_login(client, "owner2@example.com")

    biz1 = _create_business(client, owner1_headers, "Business 1")
    biz2 = _create_business(client, owner2_headers, "Business 2")

    asset1 = _create_asset(client, owner1_headers, biz1["id"])

    from unittest import mock
    from app.services.scanner.target_validator import UnsafeTargetError

    with mock.patch("app.services.scanner.scan_manager.resolve_and_validate", side_effect=UnsafeTargetError("blocked")):
        scan_resp = _auth_post(client, owner1_headers, f"/api/assets/{asset1['id']}/scan")
    scan_id = scan_resp.json()["scan_id"]

    # Owner2 should not be able to access Owner1's scan
    resp = _auth_get(client, owner2_headers, f"/api/scans/{scan_id}")
    assert resp.status_code == 403


def test_user_cannot_access_alerts_from_other_business(client: TestClient) -> None:
    owner1_headers = _register_and_login(client, "owner1@example.com")
    owner2_headers = _register_and_login(client, "owner2@example.com")

    biz1 = _create_business(client, owner1_headers, "Business 1")
    biz2 = _create_business(client, owner2_headers, "Business 2")

    # Owner2 should not be able to access Owner1's business alerts
    resp = _auth_get(client, owner2_headers, f"/api/businesses/{biz1['id']}/alerts")
    assert resp.status_code == 403


def test_user_cannot_access_reports_from_other_business(client: TestClient) -> None:
    owner1_headers = _register_and_login(client, "owner1@example.com")
    owner2_headers = _register_and_login(client, "owner2@example.com")

    biz1 = _create_business(client, owner1_headers, "Business 1")
    biz2 = _create_business(client, owner2_headers, "Business 2")

    asset1 = _create_asset(client, owner1_headers, biz1["id"])

    from unittest import mock
    from app.services.scanner.target_validator import UnsafeTargetError

    with mock.patch("app.services.scanner.scan_manager.resolve_and_validate", side_effect=UnsafeTargetError("blocked")):
        scan_resp = _auth_post(client, owner1_headers, f"/api/assets/{asset1['id']}/scan")
    scan_id = scan_resp.json()["scan_id"]

    # Owner2 should not be able to access Owner1's scan report
    resp = _auth_get(client, owner2_headers, f"/api/scans/{scan_id}/report")
    assert resp.status_code == 403

    # Owner2 should not be able to access Owner1's CSV report
    resp = _auth_get(client, owner2_headers, f"/api/scans/{scan_id}/report.csv")
    assert resp.status_code == 403


def test_user_cannot_access_dashboard_from_other_business(client: TestClient) -> None:
    owner1_headers = _register_and_login(client, "owner1@example.com")
    owner2_headers = _register_and_login(client, "owner2@example.com")

    biz1 = _create_business(client, owner1_headers, "Business 1")
    biz2 = _create_business(client, owner2_headers, "Business 2")

    # Owner2 should not be able to access Owner1's dashboard
    resp = _auth_get(client, owner2_headers, f"/api/businesses/{biz1['id']}/dashboard")
    assert resp.status_code == 403