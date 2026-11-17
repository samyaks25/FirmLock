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

import importlib
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient


class RiskApiTestBase(unittest.TestCase):
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
            "app.schemas.risk",
            "app.schemas",
            "app.services.business_service",
            "app.services.asset_service",
            "app.services.risk_config",
            "app.services.scanner.check_catalog",
            "app.services.risk_service",
            "app.services.scanner.scan_manager",
            "app.api.routes.businesses",
            "app.api.routes.assets",
            "app.api.routes.scans",
            "app.api.routes.risk",
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

    def _seed_scan(
        self,
        asset_id: int,
        *,
        findings: list[tuple[str, str]] | None = None,
        outcomes: dict[str, str] | None = None,
        status: str = "completed",
        security_score: int | None = None,
        completed_at: datetime | None = None,
    ) -> int:
        """Persist a scan with findings and check results; return its ID."""
        import app.database.connection as connection
        import app.models.models as models
        from app.services.scanner.check_catalog import ALL_GROUPS

        now = completed_at or datetime.now(timezone.utc)
        with connection.SessionLocal() as db:
            scan = models.Scan(
                asset_id=asset_id,
                status=status,
                security_score=security_score,
                started_at=now if status == "completed" else None,
                completed_at=now if status == "completed" else None,
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)

            for code, severity in findings or []:
                db.add(
                    models.Finding(
                        scan_id=scan.id,
                        check_code=code,
                        title=f"title {code}",
                        description=f"description {code}",
                        severity=severity,
                        recommendation=f"fix {code}",
                    )
                )
            db.commit()

            outcomes = outcomes or {}
            if status == "completed":
                for group in ALL_GROUPS:
                    db.add(
                        models.CheckResult(
                            scan_id=scan.id,
                            check_id=group.check_id,
                            module=group.module,
                            outcome=outcomes.get(group.check_id, "passed"),
                            detail=f"test outcome {outcomes.get(group.check_id, 'passed')}",
                        )
                    )
                db.commit()

            return scan.id

    def _update_scan_findings(self, scan_id: int, code: str, severity: str) -> None:
        import app.database.connection as connection
        import app.models.models as models

        with connection.SessionLocal() as db:
            db.add(
                models.Finding(
                    scan_id=scan_id,
                    check_code=code,
                    title=f"title {code}",
                    description=f"description {code}",
                    severity=severity,
                    recommendation=f"fix {code}",
                )
            )
            db.commit()


class ScanRiskEndpointTests(RiskApiTestBase):
    def test_completed_scan_risk(self) -> None:
        asset = self._create_asset()
        scan_id = self._seed_scan(
            asset["id"], findings=[("HSTS_MISSING", "high")]
        )

        resp = self.client.get(f"/api/scans/{scan_id}/risk")

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["scan_id"], scan_id)
        self.assertEqual(body["asset_id"], asset["id"])
        self.assertEqual(body["scan_status"], "completed")
        self.assertTrue(body["score_available"])
        self.assertEqual(body["security_score"], 85)
        self.assertEqual(body["risk_level"], "high")
        self.assertEqual(body["grade"], "B")
        self.assertEqual(body["coverage"]["percentage"], 100.0)
        self.assertEqual(body["findings_by_severity"]["high"], 1)
        self.assertEqual(len(body["deductions"]), 1)
        self.assertEqual(body["deductions"][0]["check_code"], "HSTS_MISSING")
        self.assertEqual(body["score_weights"]["critical"], 25)

    def test_unknown_scan_returns_404(self) -> None:
        resp = self.client.get("/api/scans/999999/risk")
        self.assertEqual(resp.status_code, 404)

    def test_failed_scan_returns_no_score(self) -> None:
        asset = self._create_asset()
        scan_id = self._seed_scan(asset["id"], status="failed")

        resp = self.client.get(f"/api/scans/{scan_id}/risk")

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["scan_status"], "failed")
        self.assertFalse(body["score_available"])
        self.assertIsNone(body["security_score"])
        self.assertIn("failed", (body["unavailable_reason"] or "").lower())

    def test_insufficient_coverage_returns_no_score(self) -> None:
        asset = self._create_asset()
        outcomes = {"SPF": "unknown", "DMARC": "unknown", "CAA": "unknown"}
        scan_id = self._seed_scan(asset["id"], outcomes=outcomes)

        resp = self.client.get(f"/api/scans/{scan_id}/risk")

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["score_available"])
        self.assertIsNone(body["security_score"])
        self.assertEqual(body["coverage"]["unknown"], 3)
        self.assertEqual(body["coverage"]["percentage"], 78.6)
        self.assertIn("coverage", (body["unavailable_reason"] or "").lower())


class AssetRiskEndpointTests(RiskApiTestBase):
    def test_latest_completed_scan_is_returned(self) -> None:
        asset = self._create_asset()
        base = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        older = self._seed_scan(
            asset["id"], security_score=90, completed_at=base
        )
        newer = self._seed_scan(
            asset["id"],
            security_score=80,
            completed_at=base + timedelta(hours=1),
        )

        resp = self.client.get(f"/api/assets/{asset['id']}/risk")

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["scan_id"], newer)
        self.assertNotEqual(body["scan_id"], older)
        self.assertEqual(body["security_score"], 80)
        self.assertEqual(body["asset_domain"], "example.com")
        self.assertEqual(body["previous_assessment"]["scan_id"], older)
        self.assertEqual(body["previous_assessment"]["security_score"], 90)
        self.assertEqual(body["score_change"], -10)

    def test_latest_completed_ignores_newer_failed_scan(self) -> None:
        asset = self._create_asset()
        base = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        completed = self._seed_scan(
            asset["id"], security_score=80, completed_at=base
        )
        self._seed_scan(
            asset["id"],
            status="failed",
            completed_at=base + timedelta(hours=1),
        )

        body = self.client.get(f"/api/assets/{asset['id']}/risk").json()

        self.assertEqual(body["scan_id"], completed)
        self.assertEqual(body["security_score"], 80)

    def test_no_completed_scan_returns_404(self) -> None:
        asset = self._create_asset()
        resp = self.client.get(f"/api/assets/{asset['id']}/risk")
        self.assertEqual(resp.status_code, 404)

    def test_missing_asset_returns_404(self) -> None:
        resp = self.client.get("/api/assets/999999/risk")
        self.assertEqual(resp.status_code, 404)

    def test_history_lists_completed_scans_newest_first(self) -> None:
        asset = self._create_asset()
        base = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        older = self._seed_scan(asset["id"], security_score=90, completed_at=base)
        newer = self._seed_scan(
            asset["id"],
            security_score=80,
            completed_at=base + timedelta(hours=1),
        )

        resp = self.client.get(f"/api/assets/{asset['id']}/risk/history")

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual([entry["scan_id"] for entry in body], [newer, older])
        self.assertEqual([entry["security_score"] for entry in body], [80, 90])

    def test_history_missing_asset_returns_404(self) -> None:
        resp = self.client.get("/api/assets/999999/risk/history")
        self.assertEqual(resp.status_code, 404)

    def test_historical_score_is_not_recomputed(self) -> None:
        asset = self._create_asset()
        scan_id = self._seed_scan(
            asset["id"], findings=[("CRIT", "critical")]
        )

        first = self.client.get(f"/api/scans/{scan_id}/risk").json()
        self.assertEqual(first["security_score"], 75)

        # A later finding must not alter the already-persisted assessment.
        self._update_scan_findings(scan_id, "CRIT_2", "critical")
        second = self.client.get(f"/api/scans/{scan_id}/risk").json()

        self.assertEqual(second["security_score"], 75)
        self.assertEqual(len(second["deductions"]), 1)

    def test_pre_existing_score_is_preserved(self) -> None:
        asset = self._create_asset()
        scan_id = self._seed_scan(
            asset["id"],
            findings=[("CRIT", "critical")],
            security_score=42,
        )

        body = self.client.get(f"/api/scans/{scan_id}/risk").json()

        self.assertEqual(body["security_score"], 42)
        self.assertEqual(body["score_source"], "stored")


if __name__ == "__main__":
    unittest.main()