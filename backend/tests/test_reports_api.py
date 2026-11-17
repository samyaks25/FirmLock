"""API tests for Stage 05 security reports.

Covers scan report generation, findings/recommendations, missing score handling,
CSV export, historical asset reports, and missing asset/scan handling.
"""

from __future__ import annotations

import csv
import importlib
import io
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient


class ReportsApiTestBase(unittest.TestCase):
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

    def _seed_scan(self, asset_id, findings=None, outcomes=None, status="completed", completed_at=None):
        import app.database.connection as connection
        import app.models.models as models
        from app.services.scanner.check_catalog import ALL_GROUPS

        now = completed_at or datetime.now(timezone.utc)
        with connection.SessionLocal() as db:
            scan = models.Scan(
                asset_id=asset_id,
                status=status,
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
            db.commit()
            if status == "completed":
                outcomes = outcomes or {}
                for group in ALL_GROUPS:
                    db.add(models.CheckResult(
                        scan_id=scan.id, check_id=group.check_id, module=group.module,
                        outcome=outcomes.get(group.check_id, "passed"),
                    ))
                db.commit()
            return scan.id


class ScanReportTests(ReportsApiTestBase):
    def test_scan_report_with_findings_and_score(self):
        biz = self._create_business()
        asset = self._create_asset(biz["id"])
        scan_id = self._seed_scan(asset["id"], findings=[
            ("HSTS_MISSING", "high", "HSTS missing", "No header", "Add HSTS", "e1"),
            ("CSP_MISSING", "medium", "CSP missing", "No CSP", "Add CSP", None),
        ])
        resp = self.client.get(f"/api/scans/{scan_id}/report")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["scan_id"], scan_id)
        self.assertEqual(body["scan_status"], "completed")
        self.assertEqual(body["business_name"], "Acme")
        self.assertEqual(body["asset_domain"], "example.com")
        self.assertEqual(body["findings_total"], 2)
        self.assertEqual(body["findings_by_severity"]["high"], 1)
        self.assertEqual(body["findings_by_severity"]["medium"], 1)
        self.assertTrue(body["score_available"])
        self.assertEqual(body["security_score"], 77)  # 100-15-8
        self.assertIsNotNone(body["risk_assessment"])
        self.assertTrue(len(body["findings"]) == 2)
        self.assertTrue(len(body["recommendations"]) >= 1)

    def test_scan_report_missing_score_for_failed_scan(self):
        biz = self._create_business()
        asset = self._create_asset(biz["id"])
        scan_id = self._seed_scan(asset["id"], status="failed")
        resp = self.client.get(f"/api/scans/{scan_id}/report")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["scan_status"], "failed")
        self.assertFalse(body["score_available"])
        self.assertIsNone(body["security_score"])
        self.assertIsNotNone(body["unavailable_reason"])
        self.assertIsNone(body["risk_assessment"])

    def test_scan_report_insufficient_coverage(self):
        biz = self._create_business()
        asset = self._create_asset(biz["id"])
        outcomes = {"SPF": "unknown", "DMARC": "unknown", "CAA": "unknown"}
        scan_id = self._seed_scan(asset["id"], outcomes=outcomes)
        body = self.client.get(f"/api/scans/{scan_id}/report").json()
        self.assertFalse(body["score_available"])
        self.assertIsNone(body["security_score"])
        self.assertIsNotNone(body["unavailable_reason"])
        self.assertIsNotNone(body["scan_coverage"])

    def test_missing_scan_report_404(self):
        self.assertEqual(self.client.get("/api/scans/9999/report").status_code, 404)
        self.assertEqual(self.client.get("/api/scans/9999/report.csv").status_code, 404)


class CsvReportTests(ReportsApiTestBase):
    def test_csv_export(self):
        biz = self._create_business()
        asset = self._create_asset(biz["id"])
        scan_id = self._seed_scan(asset["id"], findings=[
            ("HSTS_MISSING", "high", "HSTS missing", "No header", "Add HSTS", "ev"),
        ])
        resp = self.client.get(f"/api/scans/{scan_id}/report.csv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.headers.get("content-type", ""))
        self.assertIn(f"scan-{scan_id}-report.csv", resp.headers.get("content-disposition", ""))
        reader = csv.DictReader(io.StringIO(resp.text))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scan_id"], str(scan_id))
        self.assertEqual(rows[0]["check_code"], "HSTS_MISSING")
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["asset_domain"], "example.com")

    def test_csv_export_no_findings(self):
        biz = self._create_business()
        asset = self._create_asset(biz["id"])
        scan_id = self._seed_scan(asset["id"])
        resp = self.client.get(f"/api/scans/{scan_id}/report.csv")
        self.assertEqual(resp.status_code, 200)
        reader = csv.DictReader(io.StringIO(resp.text))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["finding_id"], "")

    def test_csv_export_sanitizes_formula_injection(self):
        biz = self._create_business(name="Acme")
        asset = self._create_asset(biz["id"], domain="example.com")

        import app.database.connection as connection
        import app.models.models as models

        with connection.SessionLocal() as db:
            business = db.get(models.Business, biz["id"])
            stored_asset = db.get(models.Asset, asset["id"])
            self.assertIsNotNone(business)
            self.assertIsNotNone(stored_asset)
            business.name = "=SUM(A1:A2)"
            stored_asset.domain = "+example.com"
            db.commit()

        scan_id = self._seed_scan(asset["id"], findings=[
            ("HSTS_MISSING", "high", "@malicious-title", "-danger-desc", "=HYPERLINK(\"http://x\")", "=cmd|' /C calc'!A0"),
        ])
        resp = self.client.get(f"/api/scans/{scan_id}/report.csv")
        self.assertEqual(resp.status_code, 200)
        reader = csv.DictReader(io.StringIO(resp.text))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["business_name"], "'=SUM(A1:A2)")
        self.assertEqual(row["asset_domain"], "'+example.com")
        self.assertEqual(row["title"], "'@malicious-title")
        self.assertEqual(row["description"], "'-danger-desc")
        self.assertEqual(row["recommendation"], "'=HYPERLINK(\"http://x\")")
        self.assertEqual(row["evidence"], "'=cmd|' /C calc'!A0")
        self.assertEqual(row["check_code"], "HSTS_MISSING")
        self.assertEqual(row["severity"], "high")


class AssetHistoryReportsTests(ReportsApiTestBase):
    def test_asset_reports_history(self):
        biz = self._create_business()
        asset = self._create_asset(biz["id"])
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self._seed_scan(asset["id"], findings=[("HSTS_MISSING", "high", "H", "d", "r", None)], completed_at=base)
        self._seed_scan(asset["id"], findings=[("CSP_MISSING", "medium", "C", "d", "r", None)], completed_at=base + timedelta(hours=1))
        resp = self.client.get(f"/api/assets/{asset['id']}/reports")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["asset_id"], asset["id"])
        self.assertEqual(body["asset_domain"], "example.com")
        self.assertEqual(len(body["scans"]), 2)
        self.assertIn("security_score", body["scans"][0])
        self.assertIn("risk_level", body["scans"][0])
        self.assertIn("scan_status", body["scans"][0])

    def test_asset_reports_missing_asset(self):
        self.assertEqual(self.client.get("/api/assets/9999/reports").status_code, 404)


if __name__ == "__main__":
    unittest.main()
