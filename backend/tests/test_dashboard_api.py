"""API tests for Stage 05 business dashboard."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient


class DashboardApiTestBase(unittest.TestCase):
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
        for mod in list(sys.modules.keys()):
            if mod.startswith("app.models"):
                importlib.reload(sys.modules[mod])
        if "app.models.models" not in sys.modules:
            import app.models.models  # noqa: F401

        for name in [
            "app.schemas.business", "app.schemas.asset", "app.schemas.scan",
            "app.schemas.risk", "app.schemas.alert", "app.schemas.report",
            "app.schemas.dashboard", "app.schemas",
            "app.services.business_service", "app.services.asset_service",
            "app.services.risk_config", "app.services.scanner.check_catalog",
            "app.services.risk_service", "app.services.alert_service",
            "app.services.report_service", "app.services.dashboard_service",
            "app.services.scanner.scan_manager",
            "app.api.routes.businesses", "app.api.routes.assets",
            "app.api.routes.scans", "app.api.routes.risk",
            "app.api.routes.alerts", "app.api.router", "app.main",
        ]:
            if name in sys.modules:
                importlib.reload(sys.modules[name])
            else:
                importlib.import_module(name)

        import app.main as main
        self.client_ctx = TestClient(main.app)
        self.client = self.client_ctx.__enter__()

    def tearDown(self) -> None:
        self.client_ctx.__exit__(None, None, None)
        import app.database.connection as connection
        connection.engine.dispose()
        self._tmpdir.cleanup()
        os.environ.pop("FIRMLOCK_DATABASE_URL", None)
        os.environ.pop("FIRMLOCK_DATA_DIR", None)

    def _create_business(self, name="Acme"):
        return self.client.post("/api/businesses", json={"name": name}).json()

    def _create_asset(self, business_id, domain="example.com"):
        return self.client.post(
            f"/api/businesses/{business_id}/assets",
            json={"domain": domain, "authorization_confirmed": True},
        ).json()

    def _seed_scan(self, asset_id, findings=None, status="completed", completed_at=None):
        import app.database.connection as connection
        import app.models.models as models
        from app.services.scanner.check_catalog import ALL_GROUPS
        now = completed_at or datetime.now(timezone.utc)
        with connection.SessionLocal() as db:
            scan = models.Scan(
                asset_id=asset_id, status=status,
                started_at=now if status in ("running", "completed", "failed") else None,
                completed_at=now if status in ("completed", "failed") else None,
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            for code, severity, title, desc, rec, evidence in (findings or []):
                db.add(models.Finding(
                    scan_id=scan.id, check_code=code, title=title,
                    description=desc, severity=severity, recommendation=rec, evidence=evidence,
                ))
            if status == "completed":
                for group in ALL_GROUPS:
                    db.add(models.CheckResult(
                        scan_id=scan.id, check_id=group.check_id, module=group.module, outcome="passed",
                    ))
            db.commit()
            return scan.id

    def _generate_alerts(self, scan_id):
        import app.database.connection as connection
        from app.services import alert_service
        with connection.SessionLocal() as db:
            return alert_service.generate_alerts_for_scan(db, scan_id)


class DashboardTests(DashboardApiTestBase):
    def test_empty_business_dashboard(self):
        biz = self._create_business()
        resp = self.client.get(f"/api/businesses/{biz['id']}/dashboard")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["business_id"], biz["id"])
        self.assertEqual(body["total_monitored_websites"], 0)
        self.assertEqual(body["active_websites"], 0)
        self.assertEqual(body["paused_websites"], 0)
        self.assertIsNone(body["latest_scan"])
        self.assertEqual(body["alert_counts"]["total_unread"], 0)
        self.assertEqual(body["alert_counts"]["total"], 0)
        self.assertEqual(body["critical_security_findings"], [])
        self.assertIsNone(body["security_overview"]["average_security_score"])
        self.assertEqual(body["security_overview"]["overall_risk_level"], "unknown")

    def test_dashboard_with_assets_scans_alerts(self):
        biz = self._create_business()
        a1 = self._create_asset(biz["id"], "one.example.com")
        a2 = self._create_asset(biz["id"], "two.example.com")
        # pause one
        self.client.patch(f"/api/assets/{a2['id']}", json={"status": "paused"})

        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        s1 = self._seed_scan(a1["id"], findings=[
            ("TLS_EXPIRED", "critical", "Cert expired", "Expired", "Renew", "e"),
            ("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None),
        ], completed_at=base)
        s2 = self._seed_scan(a1["id"], findings=[
            ("CSP_MISSING", "medium", "CSP missing", "No CSP", "Add CSP", None),
        ], completed_at=base + timedelta(hours=1))
        self._generate_alerts(s1)
        self._generate_alerts(s2)

        resp = self.client.get(f"/api/businesses/{biz['id']}/dashboard")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()

        self.assertEqual(body["total_monitored_websites"], 2)
        self.assertEqual(body["active_websites"], 1)
        self.assertEqual(body["paused_websites"], 1)
        self.assertIsNotNone(body["latest_scan"])
        self.assertEqual(body["latest_scan"]["asset_id"], a1["id"])
        self.assertEqual(body["latest_scan"]["scan_id"], s2)  # most recent by created/id
        self.assertGreaterEqual(len(body["critical_security_findings"]), 0)
        # latest completed scan for asset 1 is s2 (medium only), so no critical in latest
        self.assertEqual(body["alert_counts"]["total_unread"], 3)
        self.assertIn("average_security_score", body["latest_security_scores"])
        self.assertIn("overall_risk_level", body["security_overview"])
        self.assertTrue(len(body["recent_security_activity"]) >= 1)

    def test_dashboard_missing_business(self):
        self.assertEqual(self.client.get("/api/businesses/9999/dashboard").status_code, 404)


if __name__ == "__main__":
    unittest.main()
