"""API tests for the scanner endpoints.

Covers:
    * ``POST /api/assets/{asset_id}/scan`` - authorization/active/monitoring
      guards (403), missing asset (404) and a successful queued scan (202).
    * ``GET /api/scans/{scan_id}`` - completed scan with persisted findings,
      failed scan, and 404 for unknown scans.
    * ``GET /api/assets/{asset_id}/scans`` - history listing and 404.

The scanner's network access is avoided by patching
``scan_manager.resolve_and_validate`` to raise a controlled error, so no real
DNS or HTTP requests are made. The background task still executes end-to-end
against an isolated temporary SQLite database.
"""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from app.services.scanner.target_validator import (
    TargetDNSResolutionError,
    UnsafeTargetError,
)


class ScanApiTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._db_fd, self._db_path = tempfile.mkstemp(suffix=".db", dir=self._tmpdir.name)
        os.close(self._db_fd)
        os.environ["FIRMLOCK_DATABASE_URL"] = f"sqlite:///{Path(self._db_path).as_posix()}"
        os.environ["FIRMLOCK_DATA_DIR"] = self._tmpdir.name

        import app.core.config as config

        importlib.reload(config)
        import app.database.connection as connection

        importlib.reload(connection)

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
            "app.schemas.scan",
            "app.schemas",
            "app.services.business_service",
            "app.services.asset_service",
            "app.services.scanner.scan_manager",
            "app.api.routes.businesses",
            "app.api.routes.assets",
            "app.api.routes.scans",
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

    # --- helpers ---------------------------------------------------------
    def _create_business(self, name: str = "Acme") -> dict:
        return self.client.post("/api/businesses", json={"name": name}).json()

    def _create_asset(self, domain: str = "example.com") -> dict:
        biz = self._create_business()
        return self.client.post(
            f"/api/businesses/{biz['id']}/assets",
            json={"domain": domain, "authorization_confirmed": True},
        ).json()

    def _patch_resolve(self, exc):
        """Patch the scan manager's resolve_and_validate to raise ``exc``."""
        import app.services.scanner.scan_manager as scan_manager

        return mock.patch.object(scan_manager, "resolve_and_validate", side_effect=exc)

    def _update_asset(self, asset_id: int, **fields) -> None:
        import app.database.connection as connection
        import app.models.models as models

        with connection.SessionLocal() as db:
            asset = db.get(models.Asset, asset_id)
            for key, value in fields.items():
                setattr(asset, key, value)
            db.commit()


class StartScanGuardTests(ScanApiTestBase):
    def test_scan_missing_asset_returns_404(self) -> None:
        resp = self.client.post("/api/assets/999999/scan")
        self.assertEqual(resp.status_code, 404)

    def test_scan_unauthorised_asset_returns_403(self) -> None:
        asset = self._create_asset()
        self._update_asset(asset["id"], authorization_confirmed=False)
        resp = self.client.post(f"/api/assets/{asset['id']}/scan")
        self.assertEqual(resp.status_code, 403)

    def test_scan_paused_asset_returns_403(self) -> None:
        asset = self._create_asset()
        self.client.patch(f"/api/assets/{asset['id']}", json={"status": "paused"})
        resp = self.client.post(f"/api/assets/{asset['id']}/scan")
        self.assertEqual(resp.status_code, 403)

    def test_scan_monitoring_disabled_returns_403(self) -> None:
        asset = self._create_asset()
        self.client.patch(f"/api/assets/{asset['id']}", json={"monitoring_enabled": False})
        resp = self.client.post(f"/api/assets/{asset['id']}/scan")
        self.assertEqual(resp.status_code, 403)


class ScanLifecycleTests(ScanApiTestBase):
    def test_start_scan_returns_202_with_pending_status(self) -> None:
        asset = self._create_asset()
        with self._patch_resolve(UnsafeTargetError("blocked")):
            resp = self.client.post(f"/api/assets/{asset['id']}/scan")
        self.assertEqual(resp.status_code, 202)
        data = resp.json()
        self.assertIn("scan_id", data)
        self.assertEqual(data["asset_id"], asset["id"])
        self.assertEqual(data["status"], "pending")

    def test_completed_scan_persists_findings(self) -> None:
        asset = self._create_asset()
        with self._patch_resolve(UnsafeTargetError("resolves to 10.0.0.1")):
            start = self.client.post(f"/api/assets/{asset['id']}/scan")
        scan_id = start.json()["scan_id"]

        resp = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "completed")
        self.assertIsNotNone(body["started_at"])
        self.assertIsNotNone(body["completed_at"])
        self.assertTrue(len(body["findings"]) >= 1)
        self.assertIn("TARGET_SSRF_REJECTED", {f["check_code"] for f in body["findings"]})
        # Asset last_scanned_at updated.
        asset_resp = self.client.get(f"/api/assets/{asset['id']}")
        self.assertIsNotNone(asset_resp.json()["last_scanned_at"])

    def test_failed_scan_marked_failed(self) -> None:
        asset = self._create_asset()
        with self._patch_resolve(TargetDNSResolutionError("no such host")):
            start = self.client.post(f"/api/assets/{asset['id']}/scan")
        scan_id = start.json()["scan_id"]

        resp = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "failed")
        self.assertIsNotNone(body["completed_at"])

    def test_get_unknown_scan_returns_404(self) -> None:
        resp = self.client.get("/api/scans/999999")
        self.assertEqual(resp.status_code, 404)


class ScanHistoryTests(ScanApiTestBase):
    def test_list_scans_for_asset(self) -> None:
        asset = self._create_asset()
        with self._patch_resolve(UnsafeTargetError("blocked")):
            self.client.post(f"/api/assets/{asset['id']}/scan")

        resp = self.client.get(f"/api/assets/{asset['id']}/scans")
        self.assertEqual(resp.status_code, 200)
        scans = resp.json()
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["asset_id"], asset["id"])

    def test_list_scans_missing_asset_returns_404(self) -> None:
        resp = self.client.get("/api/assets/999999/scans")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()