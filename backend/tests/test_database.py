"""Database model and relationship tests for FirmLock."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.database import connection as db_connection
from app.models.models import Alert, Asset, Business, Finding, Scan


class DatabaseModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.db_url = f"sqlite:///{self._tmp.name}"
        self.engine = db_connection._build_engine(self.db_url)
        # Ensure FK pragma is active for this engine.
        from sqlalchemy import event

        @event.listens_for(self.engine, "connect")
        def _fk(dbapi_connection, _):  # pragma: no cover - simple wiring
            cur = dbapi_connection.cursor()
            try:
                cur.execute("PRAGMA foreign_keys=ON")
            finally:
                cur.close()

        self.Session = sessionmaker(bind=self.engine, autoflush=False, autocommit=False, future=True)
        db_connection.Base.metadata.create_all(bind=self.engine)

    def tearDown(self) -> None:
        self.engine.dispose()
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    def test_database_connection(self) -> None:
        with self.engine.connect() as conn:
            result = conn.execute(text("SELECT 1")).scalar_one()
        self.assertEqual(result, 1)

    def test_table_creation(self) -> None:
        inspector = inspect(self.engine)
        tables = set(inspector.get_table_names())
        self.assertTrue({"businesses", "assets", "scans", "findings", "alerts"}.issubset(tables))

    def test_foreign_key_enforcement(self) -> None:
        with self.engine.connect() as conn:
            fk = conn.execute(text("PRAGMA foreign_keys")).scalar_one()
        self.assertEqual(fk, 1)

    def test_business_creation(self) -> None:
        with self.Session() as db:
            biz = Business(name="Acme Co", industry="Retail")
            db.add(biz)
            db.commit()
            db.refresh(biz)
            self.assertIsNotNone(biz.id)
            self.assertIsNotNone(biz.created_at)
            self.assertIsNotNone(biz.updated_at)

    def test_asset_creation_and_business_relationship(self) -> None:
        with self.Session() as db:
            biz = Business(name="Acme Co")
            db.add(biz)
            db.commit()
            now = datetime.now(timezone.utc)
            asset = Asset(
                business_id=biz.id,
                domain="example.com",
                authorization_confirmed=True,
                authorization_confirmed_at=now,
                monitoring_enabled=True,
                status="active",
            )
            db.add(asset)
            db.commit()
            db.refresh(biz)
            db.refresh(asset)
            self.assertEqual(asset.business_id, biz.id)
            self.assertEqual(len(biz.assets), 1)
            self.assertEqual(biz.assets[0].domain, "example.com")

    def test_asset_to_scan_relationship(self) -> None:
        with self.Session() as db:
            biz = Business(name="Acme Co")
            db.add(biz)
            db.commit()
            asset = Asset(
                business_id=biz.id,
                domain="example.com",
                authorization_confirmed=True,
                authorization_confirmed_at=datetime.now(timezone.utc),
            )
            db.add(asset)
            db.commit()
            scan = Scan(asset_id=asset.id, status="pending")
            db.add(scan)
            db.commit()
            db.refresh(asset)
            self.assertEqual(len(asset.scans), 1)
            self.assertEqual(asset.scans[0].status, "pending")

    def test_scan_to_finding_relationship(self) -> None:
        with self.Session() as db:
            biz = Business(name="Acme Co")
            db.add(biz)
            db.commit()
            asset = Asset(
                business_id=biz.id,
                domain="example.com",
                authorization_confirmed=True,
                authorization_confirmed_at=datetime.now(timezone.utc),
            )
            db.add(asset)
            db.commit()
            scan = Scan(asset_id=asset.id, status="completed", security_score=80)
            db.add(scan)
            db.commit()
            finding = Finding(
                scan_id=scan.id,
                check_code="TLS_CERT",
                title="TLS cert issue",
                description="desc",
                severity="high",
                recommendation="fix it",
            )
            db.add(finding)
            db.commit()
            db.refresh(scan)
            self.assertEqual(len(scan.findings), 1)
            self.assertEqual(scan.findings[0].check_code, "TLS_CERT")

    def test_alert_relationships(self) -> None:
        with self.Session() as db:
            biz = Business(name="Acme Co")
            db.add(biz)
            db.commit()
            asset = Asset(
                business_id=biz.id,
                domain="example.com",
                authorization_confirmed=True,
                authorization_confirmed_at=datetime.now(timezone.utc),
            )
            db.add(asset)
            db.commit()
            scan = Scan(asset_id=asset.id, status="completed")
            db.add(scan)
            db.commit()
            finding = Finding(
                scan_id=scan.id,
                check_code="HDR",
                title="Header",
                description="desc",
                severity="medium",
                recommendation="rec",
            )
            db.add(finding)
            db.commit()
            alert = Alert(
                business_id=biz.id,
                asset_id=asset.id,
                finding_id=finding.id,
                title="Alert",
                message="msg",
                severity="medium",
                status="unread",
            )
            db.add(alert)
            db.commit()
            db.refresh(biz)
            db.refresh(asset)
            db.refresh(finding)
            self.assertEqual(len(biz.alerts), 1)
            self.assertEqual(len(asset.alerts), 1)
            self.assertEqual(len(finding.alerts), 1)

    def test_foreign_key_violation_rejected(self) -> None:
        with self.Session() as db:
            asset = Asset(
                business_id=9999,
                domain="example.com",
                authorization_confirmed=True,
                authorization_confirmed_at=datetime.now(timezone.utc),
            )
            db.add(asset)
            with self.assertRaises(IntegrityError):
                db.commit()
            db.rollback()


if __name__ == "__main__":
    unittest.main()
