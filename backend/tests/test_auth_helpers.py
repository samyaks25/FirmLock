"""Test helpers for authentication."""

from __future__ import annotations

from fastapi.testclient import TestClient


def register_user(client: TestClient, email: str, password: str, full_name: str | None = None) -> dict:
    """Register a user and return the response JSON."""
    payload = {"email": email, "password": password}
    if full_name:
        payload["full_name"] = full_name
    resp = client.post("/api/auth/register", json=payload)
    return resp.json()


def login_user(client: TestClient, email: str, password: str) -> dict:
    """Login a user and return the token response JSON."""
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    return resp.json()


def get_auth_headers(token: str) -> dict:
    """Return headers with Bearer token."""
    return {"Authorization": f"Bearer {token}"}