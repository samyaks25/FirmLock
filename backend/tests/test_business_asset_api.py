"""Business and asset API tests for FirmLock."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


class ApiTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._db_fd, self._db_path = tempfile.mkstemp(suffix=".db", dir=self._tmpdir.name)
        os.close(self._db_fd)
        os.environ["FIRMLOCK_DATABASE_URL"] = f"sqlite:///{Path(self._db_path).as_posix()}"
        os.environ["FIRMLOCK_DATA_DIR"] = self._tmpdir.name

        # Reload config/connection so engine and Base bind to the isolated test DB.
        import app.core.config as config
        importlib.reload(config)
        import app.database.connection as connection
        importlib.reload(connection)

        # Reset ORM mappings/metadata so reloading models re-registers cleanly.
        connection.Base.registry.dispose()
        connection.Base.metadata.clear()
        if "app.models.models" in sys.modules:
            importlib.reload(sys.modules["app.models.models"])
        else:
            import app.models.models  # noqa: F401
        if "app.models" in sys.modules:
            importlib.reload(sys.modules["app.models"])

        for name in [
            "app.schemas.business",
            "app.schemas.asset",
            "app.schemas",
            "app.services.business_service",
            "app.services.asset_service",
            "app.api.routes.businesses",
            "app.api.routes.assets",
            "app.api.router",
            "app.main",
        ]:
            if name in sys.modules:
                importlib.reload(sys.modules[name])
            else:
                importlib.import_module(name)

        import app.main as main

        self.main = main
        self.client_ctx = TestClient(main.app)
        self.client = self.client_ctx.__enter__()

    def tearDown(self) -> None:
        self.client_ctx.__exit__(None, None, None)
        import app.database.connection as connection

        connection.engine.dispose()
        self._tmpdir.cleanup()
        os.environ.pop("FIRMLOCK_DATABASE_URL", None)
        os.environ.pop("FIRMLOCK_DATA_DIR", None)


class BusinessApiTests(ApiTestBase):
    def test_create_business_success(self) -> None:
        resp = self.client.post("/api/businesses", json={"name": "Acme", "industry": "Retail"})
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["name"], "Acme")
        self.assertEqual(data["industry"], "Retail")
        self.assertIn("id", data)

    def test_get_business_success(self) -> None:
        created = self.client.post("/api/businesses", json={"name": "Acme"}).json()
        resp = self.client.get(f"/api/businesses/{created['id']}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["id"], created["id"])

    def test_get_business_not_found(self) -> None:
        resp = self.client.get("/api/businesses/9999")
        self.assertEqual(resp.status_code, 404)

    def test_list_businesses(self) -> None:
        self.client.post("/api/businesses", json={"name": "A"})
        self.client.post("/api/businesses", json={"name": "B"})
        resp = self.client.get("/api/businesses")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()), 2)

    def test_create_business_empty_name_rejected(self) -> None:
        resp = self.client.post("/api/businesses", json={"name": "   "})
        self.assertEqual(resp.status_code, 422)


class AssetApiTests(ApiTestBase):
    def _create_business(self, name: str = "Acme") -> dict:
        return self.client.post("/api/businesses", json={"name": name}).json()

    def test_register_asset_success(self) -> None:
        biz = self._create_business()
        resp = self.client.post(
            f"/api/businesses/{biz['id']}/assets",
            json={"domain": "example.com", "authorization_confirmed": True},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["domain"], "example.com")
        self.assertEqual(data["business_id"], biz["id"])
        self.assertTrue(data["monitoring_enabled"])
        self.assertEqual(data["status"], "active")

    def test_domain_normalisation(self) -> None:
        biz = self._create_business()
        resp = self.client.post(
            f"/api/businesses/{biz['id']}/assets",
            json={"domain": "  HTTPS://Example.COM/  ", "authorization_confirmed": True},
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.json()["domain"], "example.com")

    def test_duplicate_domain_rejected(self) -> None:
        biz = self._create_business()
        payload = {"domain": "example.com", "authorization_confirmed": True}
        first = self.client.post(f"/api/businesses/{biz['id']}/assets", json=payload)
        self.assertEqual(first.status_code, 201)
        second = self.client.post(f"/api/businesses/{biz['id']}/assets", json=payload)
        self.assertEqual(second.status_code, 409)

    def test_invalid_domain_rejected(self) -> None:
        biz = self._create_business()
        cases = [
            "not a domain",
            "192.168.1.1",
            "https://user:pass@example.com",
            "https://example.com/path",
            "http://example.com?q=1",
            "",
        ]
        for domain in cases:
            with self.subTest(domain=domain):
                resp = self.client.post(
                    f"/api/businesses/{biz['id']}/assets",
                    json={"domain": domain, "authorization_confirmed": True},
                )
                self.assertEqual(resp.status_code, 422)

    def test_missing_authorization_confirmation(self) -> None:
        biz = self._create_business()
        resp = self.client.post(
            f"/api/businesses/{biz['id']}/assets",
            json={"domain": "example.com", "authorization_confirmed": False},
        )
        self.assertEqual(resp.status_code, 422)

    def test_nonexistent_business_rejection(self) -> None:
        resp = self.client.post(
            "/api/businesses/9999/assets",
            json={"domain": "example.com", "authorization_confirmed": True},
        )
        self.assertEqual(resp.status_code, 404)

    def test_asset_listing_for_business(self) -> None:
        biz = self._create_business()
        self.client.post(
            f"/api/businesses/{biz['id']}/assets",
            json={"domain": "a.example.com", "authorization_confirmed": True},
        )
        self.client.post(
            f"/api/businesses/{biz['id']}/assets",
            json={"domain": "b.example.com", "authorization_confirmed": True},
        )
        resp = self.client.get(f"/api/businesses/{biz['id']}/assets")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()), 2)

    def test_asset_listing_business_not_found(self) -> None:
        resp = self.client.get("/api/businesses/9999/assets")
        self.assertEqual(resp.status_code, 404)

    def test_monitoring_status_update(self) -> None:
        biz = self._create_business()
        asset = self.client.post(
            f"/api/businesses/{biz['id']}/assets",
            json={"domain": "example.com", "authorization_confirmed": True},
        ).json()
        resp = self.client.patch(
            f"/api/assets/{asset['id']}",
            json={"status": "paused"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "paused")
        self.assertFalse(data["monitoring_enabled"])

        resp2 = self.client.patch(
            f"/api/assets/{asset['id']}",
            json={"status": "active"},
        )
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.json()["status"], "active")
        self.assertTrue(resp2.json()["monitoring_enabled"])

    def test_get_asset(self) -> None:
        biz = self._create_business()
        asset = self.client.post(
            f"/api/businesses/{biz['id']}/assets",
            json={"domain": "example.com", "authorization_confirmed": True},
        ).json()
        resp = self.client.get(f"/api/assets/{asset['id']}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["domain"], "example.com")

    def test_get_asset_not_found(self) -> None:
        resp = self.client.get("/api/assets/9999")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
