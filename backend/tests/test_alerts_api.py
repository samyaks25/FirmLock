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

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.services.scanner.target_validator import UnsafeTargetError, TargetDNSResolutionError
from unittest import mock


class AlertsApiTestBase(unittest.TestCase):
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
            "app.schemas.business",
            "app.schemas.asset",
            "app.schemas.scan",
            "app.schemas.risk",
            "app.schemas.alert",
            "app.schemas.report",
            "app.schemas.dashboard",
            "app.schemas",
            "app.services.business_service",
            "app.services.asset_service",
            "app.services.risk_config",
            "app.services.scanner.check_catalog",
            "app.services.risk_service",
            "app.services.alert_service",
            "app.services.report_service",
            "app.services.dashboard_service",
            "app.services.scanner.scan_manager",
            "app.api.routes.businesses",
            "app.api.routes.assets",
            "app.api.routes.scans",
            "app.api.routes.risk",
            "app.api.routes.alerts",
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

    # helpers
    def _create_business(self, name: str = "Acme") -> dict:
        return self.client.post("/api/businesses", json={"name": name}).json()

    def _create_asset(self, business_id: int, domain: str = "example.com") -> dict:
        return self.client.post(
            f"/api/businesses/{business_id}/assets",
            json={"domain": domain, "authorization_confirmed": True},
        ).json()

    def _seed_scan_with_findings(self, asset_id: int, findings):
        import app.database.connection as connection
        import app.models.models as models
        from app.services.scanner.check_catalog import ALL_GROUPS
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        with connection.SessionLocal() as db:
            scan = models.Scan(
                asset_id=asset_id,
                status="completed",
                started_at=now,
                completed_at=now,
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            for code, severity, title, desc, rec, evidence in findings:
                db.add(
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
                db.add(
                    models.CheckResult(
                        scan_id=scan.id,
                        check_id=group.check_id,
                        module=group.module,
                        outcome="passed",
                    )
                )
            db.commit()
            return scan.id

    def _generate_alerts(self, scan_id: int):
        import app.database.connection as connection
        from app.services import alert_service

        with connection.SessionLocal() as db:
            return alert_service.generate_alerts_for_scan(db, scan_id)


class AlertGenerationTests(AlertsApiTestBase):
    def test_generates_alerts_for_actionable_severities(self):
        biz = self._create_business()
        asset = self._create_asset(biz["id"])
        scan_id = self._seed_scan_with_findings(
            asset["id"],
            [
                ("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None),
                ("CSP_MISSING", "medium", "CSP missing", "No CSP", "Add CSP", None),
                ("REF_MISSING", "low", "Referrer missing", "No RP", "Add RP", None),
                ("TLS_EXPIRED", "critical", "Cert expired", "Expired", "Renew", "exp"),
                ("CAA_PRESENT", "info", "CAA present", "CAA ok", "None", None),
            ],
        )
        created = self._generate_alerts(scan_id)
        self.assertEqual(len(created), 4)
        self.assertEqual({a.severity for a in created}, {"critical", "high", "medium", "low"})

    def test_no_alert_for_info_only(self):
        biz = self._create_business()
        asset = self._create_asset(biz["id"])
        scan_id = self._seed_scan_with_findings(
            asset["id"],
            [("CAA_PRESENT", "info", "CAA present", "CAA ok", "None", None)],
        )
        created = self._generate_alerts(scan_id)
        self.assertEqual(created, [])

    def test_no_duplicate_unresolved_alert_for_same_issue(self):
        biz = self._create_business()
        asset = self._create_asset(biz["id"])
        scan1 = self._seed_scan_with_findings(
            asset["id"],
            [("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None)],
        )
        scan2 = self._seed_scan_with_findings(
            asset["id"],
            [("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None)],
        )
        first = self._generate_alerts(scan1)
        second = self._generate_alerts(scan2)
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 0)

    def test_reappearing_resolved_issue_creates_new_alert(self):
        biz = self._create_business()
        asset = self._create_asset(biz["id"])
        scan1 = self._seed_scan_with_findings(
            asset["id"],
            [("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None)],
        )
        first = self._generate_alerts(scan1)
        self.assertEqual(len(first), 1)
        # resolve existing alert
        resp = self.client.patch(f"/api/alerts/{first[0].id}", json={"resolved": True})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "resolved")

        scan2 = self._seed_scan_with_findings(
            asset["id"],
            [("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None)],
        )
        second = self._generate_alerts(scan2)
        self.assertEqual(len(second), 1)
        self.assertNotEqual(second[0].id, first[0].id)

        # history preserved: resolved alert still exists
        all_alerts = self.client.get(f"/api/businesses/{biz['id']}/alerts?page_size=50").json()
        self.assertEqual(all_alerts["total"], 2)
        statuses = {a["status"] for a in all_alerts["items"]}
        self.assertEqual(statuses, {"resolved", "unread"})


class AlertApiTests(AlertsApiTestBase):
    def _setup_alerts(self):
        biz = self._create_business()
        asset = self._create_asset(biz["id"])
        scan_id = self._seed_scan_with_findings(
            asset["id"],
            [
                ("TLS_EXPIRED", "critical", "Cert expired", "Expired", "Renew", "e"),
                ("HSTS_MISSING", "high", "HSTS missing", "No HSTS", "Add HSTS", None),
                ("CSP_MISSING", "medium", "CSP missing", "No CSP", "Add CSP", None),
                ("REF_MISSING", "low", "Referrer missing", "No RP", "Add RP", None),
            ],
        )
        self._generate_alerts(scan_id)
        return biz, asset

    def test_list_alerts_and_get_detail(self):
        biz, _ = self._setup_alerts()
        resp = self.client.get(f"/api/businesses/{biz['id']}/alerts")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["total"], 4)
        self.assertEqual(len(body["items"]), 4)
        alert_id = body["items"][0]["id"]
        detail = self.client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["id"], alert_id)

    def test_filter_by_severity_and_status(self):
        biz, _ = self._setup_alerts()
        resp = self.client.get(f"/api/businesses/{biz['id']}/alerts?severity=critical")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["severity"], "critical")

        alert_id = body["items"][0]["id"]
        self.client.patch(f"/api/alerts/{alert_id}", json={"read": True})
        unread = self.client.get(f"/api/businesses/{biz['id']}/alerts?status=unread")
        self.assertEqual(unread.json()["total"], 3)
        read = self.client.get(f"/api/businesses/{biz['id']}/alerts?status=read")
        self.assertEqual(read.json()["total"], 1)

    def test_pagination(self):
        biz, _ = self._setup_alerts()
        p1 = self.client.get(f"/api/businesses/{biz['id']}/alerts?page=1&page_size=2").json()
        p2 = self.client.get(f"/api/businesses/{biz['id']}/alerts?page=2&page_size=2").json()
        self.assertEqual(p1["total"], 4)
        self.assertEqual(len(p1["items"]), 2)
        self.assertEqual(len(p2["items"]), 2)
        self.assertEqual(p1["pages"], 2)
        ids1 = {a["id"] for a in p1["items"]}
        ids2 = {a["id"] for a in p2["items"]}
        self.assertTrue(ids1.isdisjoint(ids2))

    def test_mark_read_and_resolve(self):
        biz, _ = self._setup_alerts()
        alert_id = self.client.get(f"/api/businesses/{biz['id']}/alerts").json()["items"][0]["id"]
        read_resp = self.client.patch(f"/api/alerts/{alert_id}", json={"read": True})
        self.assertEqual(read_resp.status_code, 200)
        self.assertEqual(read_resp.json()["status"], "read")
        self.assertIsNotNone(read_resp.json()["read_at"])

        resolve_resp = self.client.patch(f"/api/alerts/{alert_id}", json={"resolved": True})
        self.assertEqual(resolve_resp.status_code, 200)
        self.assertEqual(resolve_resp.json()["status"], "resolved")
        self.assertIsNotNone(resolve_resp.json()["resolved_at"])

    def test_summary_counts(self):
        biz, _ = self._setup_alerts()
        summary = self.client.get(f"/api/businesses/{biz['id']}/alerts/summary").json()
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["unread"], 4)
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["medium"], 1)
        self.assertEqual(summary["low"], 1)
        self.assertEqual(summary["resolved"], 0)

        alert_id = self.client.get(f"/api/businesses/{biz['id']}/alerts?severity=high").json()["items"][0]["id"]
        self.client.patch(f"/api/alerts/{alert_id}", json={"resolved": True})
        summary2 = self.client.get(f"/api/businesses/{biz['id']}/alerts/summary").json()
        self.assertEqual(summary2["resolved"], 1)
        self.assertEqual(summary2["unread"], 3)
        self.assertEqual(summary2["high"], 1)

    def test_alert_404s(self):
        self.assertEqual(self.client.get("/api/alerts/9999").status_code, 404)
        self.assertEqual(self.client.patch("/api/alerts/9999", json={"read": True}).status_code, 404)
        self.assertEqual(self.client.get("/api/businesses/9999/alerts").status_code, 404)
        self.assertEqual(self.client.get("/api/businesses/9999/alerts/summary").status_code, 404)

    def test_invalid_filters(self):
        biz, _ = self._setup_alerts()
        self.assertEqual(
            self.client.get(f"/api/businesses/{biz['id']}/alerts?severity=bogus").status_code,
            422,
        )
        self.assertEqual(
            self.client.get(f"/api/businesses/{biz['id']}/alerts?status=bogus").status_code,
            422,
        )


if __name__ == "__main__":
    unittest.main()
