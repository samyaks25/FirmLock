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
from app.models.models import Alert, Asset, Business, BusinessMembership, Finding, Scan, User


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
        self.assertTrue(
            {"businesses", "assets", "scans", "findings", "alerts", "users", "business_memberships"}.issubset(tables)
        )

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

    def test_user_creation(self) -> None:
        with self.Session() as db:
            user = User(
                email="test@example.com",
                hashed_password="hashed_password_here",
                full_name="Test User",
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            self.assertIsNotNone(user.id)
            self.assertEqual(user.email, "test@example.com")
            self.assertEqual(user.full_name, "Test User")
            self.assertTrue(user.is_active)
            self.assertIsNotNone(user.created_at)
            self.assertIsNotNone(user.updated_at)

    def test_user_email_unique(self) -> None:
        with self.Session() as db:
            user1 = User(
                email="test@example.com",
                hashed_password="hashed_password_here",
            )
            db.add(user1)
            db.commit()

            user2 = User(
                email="test@example.com",
                hashed_password="another_hash",
            )
            db.add(user2)
            with self.assertRaises(IntegrityError):
                db.commit()
            db.rollback()

    def test_business_membership_creation(self) -> None:
        with self.Session() as db:
            user = User(
                email="test@example.com",
                hashed_password="hashed_password_here",
            )
            biz = Business(name="Acme Co")
            db.add(user)
            db.add(biz)
            db.commit()

            membership = BusinessMembership(user_id=user.id, business_id=biz.id, role="owner")
            db.add(membership)
            db.commit()
            db.refresh(membership)
            self.assertIsNotNone(membership.id)
            self.assertEqual(membership.user_id, user.id)
            self.assertEqual(membership.business_id, biz.id)
            self.assertEqual(membership.role, "owner")
            self.assertIsNotNone(membership.created_at)

    def test_business_membership_unique_user_business(self) -> None:
        with self.Session() as db:
            user = User(
                email="test@example.com",
                hashed_password="hashed_password_here",
            )
            biz = Business(name="Acme Co")
            db.add(user)
            db.add(biz)
            db.commit()

            membership1 = BusinessMembership(user_id=user.id, business_id=biz.id, role="owner")
            db.add(membership1)
            db.commit()

            membership2 = BusinessMembership(user_id=user.id, business_id=biz.id, role="admin")
            db.add(membership2)
            with self.assertRaises(IntegrityError):
                db.commit()
            db.rollback()

    def test_business_membership_role_constraint(self) -> None:
        with self.Session() as db:
            user = User(
                email="test@example.com",
                hashed_password="hashed_password_here",
            )
            biz = Business(name="Acme Co")
            db.add(user)
            db.add(biz)
            db.commit()

            membership = BusinessMembership(user_id=user.id, business_id=biz.id, role="invalid_role")
            db.add(membership)
            with self.assertRaises(IntegrityError):
                db.commit()
            db.rollback()

    def test_business_membership_cascade_delete_user(self) -> None:
        with self.Session() as db:
            user = User(
                email="test@example.com",
                hashed_password="hashed_password_here",
            )
            biz = Business(name="Acme Co")
            db.add(user)
            db.add(biz)
            db.commit()

            membership = BusinessMembership(user_id=user.id, business_id=biz.id, role="owner")
            db.add(membership)
            db.commit()
            membership_id = membership.id

            db.delete(user)
            db.commit()

            # Membership should be cascade deleted
            remaining = db.get(BusinessMembership, membership_id)
            self.assertIsNone(remaining)

    def test_business_membership_cascade_delete_business(self) -> None:
        with self.Session() as db:
            user = User(
                email="test@example.com",
                hashed_password="hashed_password_here",
            )
            biz = Business(name="Acme Co")
            db.add(user)
            db.add(biz)
            db.commit()

            membership = BusinessMembership(user_id=user.id, business_id=biz.id, role="owner")
            db.add(membership)
            db.commit()
            membership_id = membership.id

            db.delete(biz)
            db.commit()

            # Membership should be cascade deleted
            remaining = db.get(BusinessMembership, membership_id)
            self.assertIsNone(remaining)

    def test_user_memberships_relationship(self) -> None:
        with self.Session() as db:
            user = User(
                email="test@example.com",
                hashed_password="hashed_password_here",
            )
            biz1 = Business(name="Acme Co")
            biz2 = Business(name="Beta Inc")
            db.add(user)
            db.add(biz1)
            db.add(biz2)
            db.commit()

            membership1 = BusinessMembership(user_id=user.id, business_id=biz1.id, role="owner")
            membership2 = BusinessMembership(user_id=user.id, business_id=biz2.id, role="admin")
            db.add(membership1)
            db.add(membership2)
            db.commit()
            db.refresh(user)

            self.assertEqual(len(user.memberships), 2)
            roles = {m.role for m in user.memberships}
            self.assertEqual(roles, {"owner", "admin"})

    def test_business_memberships_relationship(self) -> None:
        with self.Session() as db:
            user1 = User(email="user1@example.com", hashed_password="hash1")
            user2 = User(email="user2@example.com", hashed_password="hash2")
            biz = Business(name="Acme Co")
            db.add(user1)
            db.add(user2)
            db.add(biz)
            db.commit()

            membership1 = BusinessMembership(user_id=user1.id, business_id=biz.id, role="owner")
            membership2 = BusinessMembership(user_id=user2.id, business_id=biz.id, role="member")
            db.add(membership1)
            db.add(membership2)
            db.commit()
            db.refresh(biz)

            self.assertEqual(len(biz.memberships), 2)
            roles = {m.role for m in biz.memberships}
            self.assertEqual(roles, {"owner", "member"})


if __name__ == "__main__":
    unittest.main()