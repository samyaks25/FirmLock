"""Business and asset API tests for FirmLock."""

from __future__ import annotations

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


def _create_business(client: TestClient, headers: dict, name: str = "Acme", industry: str | None = None) -> dict:
    payload = {"name": name}
    if industry:
        payload["industry"] = industry
    return _auth_post(client, headers, "/api/businesses", json=payload).json()


# Business API Tests

def test_create_business_success(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_post(client, headers, "/api/businesses", json={"name": "Acme", "industry": "Retail"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Acme"
    assert data["industry"] == "Retail"
    assert "id" in data


def test_get_business_success(client: TestClient) -> None:
    headers = _register_and_login(client)
    created = _auth_post(client, headers, "/api/businesses", json={"name": "Acme"}).json()
    resp = _auth_get(client, headers, f"/api/businesses/{created['id']}")
    assert resp.status_code == 200
    assert resp.json()["id"] == created["id"]


def test_get_business_not_found(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_get(client, headers, "/api/businesses/9999")
    assert resp.status_code == 404


def test_list_businesses(client: TestClient) -> None:
    headers = _register_and_login(client)
    _auth_post(client, headers, "/api/businesses", json={"name": "A"})
    _auth_post(client, headers, "/api/businesses", json={"name": "B"})
    resp = _auth_get(client, headers, "/api/businesses")
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_create_business_empty_name_rejected(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_post(client, headers, "/api/businesses", json={"name": "   "})
    assert resp.status_code == 422


# Asset API Tests

def test_register_asset_success(client: TestClient) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    resp = _auth_post(
        client, headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": "example.com", "authorization_confirmed": True},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["domain"] == "example.com"
    assert data["business_id"] == biz["id"]
    assert data["monitoring_enabled"] is True
    assert data["status"] == "active"


def test_domain_normalisation(client: TestClient) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    resp = _auth_post(
        client, headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": "  HTTPS://Example.COM/  ", "authorization_confirmed": True},
    )
    assert resp.status_code == 201
    assert resp.json()["domain"] == "example.com"


def test_duplicate_domain_rejected(client: TestClient) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    payload = {"domain": "example.com", "authorization_confirmed": True}
    first = _auth_post(client, headers, f"/api/businesses/{biz['id']}/assets", json=payload)
    assert first.status_code == 201
    second = _auth_post(client, headers, f"/api/businesses/{biz['id']}/assets", json=payload)
    assert second.status_code == 409


def test_invalid_domain_rejected(client: TestClient) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    cases = [
        "not a domain",
        "192.168.1.1",
        "https://user:pass@example.com",
        "https://example.com/path",
        "http://example.com?q=1",
        "",
    ]
    for domain in cases:
        resp = _auth_post(
            client, headers,
            f"/api/businesses/{biz['id']}/assets",
            json={"domain": domain, "authorization_confirmed": True},
        )
        assert resp.status_code == 422


def test_missing_authorization_confirmation(client: TestClient) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    resp = _auth_post(
        client, headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": "example.com", "authorization_confirmed": False},
    )
    assert resp.status_code == 422


def test_nonexistent_business_rejection(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_post(
        client, headers,
        "/api/businesses/9999/assets",
        json={"domain": "example.com", "authorization_confirmed": True},
    )
    assert resp.status_code == 404


def test_asset_listing_for_business(client: TestClient) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    _auth_post(
        client, headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": "a.example.com", "authorization_confirmed": True},
    )
    _auth_post(
        client, headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": "b.example.com", "authorization_confirmed": True},
    )
    resp = _auth_get(client, headers, f"/api/businesses/{biz['id']}/assets")
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_asset_listing_business_not_found(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_get(client, headers, "/api/businesses/9999/assets")
    assert resp.status_code == 404


def test_monitoring_status_update(client: TestClient) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _auth_post(
        client, headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": "example.com", "authorization_confirmed": True},
    ).json()
    resp = _auth_patch(
        client, headers,
        f"/api/assets/{asset['id']}",
        json={"status": "paused"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "paused"
    assert data["monitoring_enabled"] is False

    resp2 = _auth_patch(
        client, headers,
        f"/api/assets/{asset['id']}",
        json={"status": "active"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "active"
    assert resp2.json()["monitoring_enabled"] is True


def test_get_asset(client: TestClient) -> None:
    headers = _register_and_login(client)
    biz = _create_business(client, headers)
    asset = _auth_post(
        client, headers,
        f"/api/businesses/{biz['id']}/assets",
        json={"domain": "example.com", "authorization_confirmed": True},
    ).json()
    resp = _auth_get(client, headers, f"/api/assets/{asset['id']}")
    assert resp.status_code == 200
    assert resp.json()["domain"] == "example.com"


def test_get_asset_not_found(client: TestClient) -> None:
    headers = _register_and_login(client)
    resp = _auth_get(client, headers, "/api/assets/9999")
    assert resp.status_code == 404