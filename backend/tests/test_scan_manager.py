"""Tests for the scan manager orchestration and persistence.

These tests use an isolated temporary SQLite database and injected fake
inspectors/resolver so that no real network access occurs. They cover:

    * Successful scan end-to-end (all modules run, findings persisted,
      status transitions and ``last_scanned_at`` updated).
    * De-duplication of check codes within a scan.
    * Failure handling for DNS resolution failures, unauthorised/inactive
      assets and missing scans.
    * Target validation outcomes (invalid / SSRF-rejected) recorded as
      completed scans with findings.
    * Isolation of a failing module so the rest of the scan still completes.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.database.connection import Base
from app.models.models import Asset, Business, Finding as FindingModel, Scan
from app.services.scanner import scan_manager
from app.services.scanner.findings import Finding
from app.services.scanner.target_validator import (
    InvalidTargetError,
    TargetDNSResolutionError,
    UnsafeTargetError,
)

PUBLIC_RESOLVER = lambda hostname, config: ["8.8.8.8"]  # noqa: E731


def _finding(code, severity="info"):
    return Finding(
        check_code=code,
        title=f"title {code}",
        description=f"description {code}",
        severity=severity,
        recommendation="do something",
        evidence="evidence",
    )


class ScanManagerTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.engine = create_engine(
            f"sqlite:///{self._tmp.name}",
            connect_args={"check_same_thread": False},
            future=True,
        )

        @event.listens_for(self.engine, "connect")
        def _fk(dbapi_connection, _):  # pragma: no cover - simple wiring
            cur = dbapi_connection.cursor()
            try:
                cur.execute("PRAGMA foreign_keys=ON")
            finally:
                cur.close()

        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(
            bind=self.engine, autoflush=False, autocommit=False, future=True
        )

    def tearDown(self) -> None:
        self.engine.dispose()
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    def _seed(self, *, authorization=True, status="active", monitoring=True):
        with self.Session() as db:
            biz = Business(name="Acme")
            db.add(biz)
            db.commit()
            asset = Asset(
                business_id=biz.id,
                domain="example.com",
                authorization_confirmed=authorization,
                authorization_confirmed_at=datetime.now(timezone.utc),
                monitoring_enabled=monitoring,
                status=status,
            )
            db.add(asset)
            db.commit()
            scan = Scan(asset_id=asset.id, status="pending")
            db.add(scan)
            db.commit()
            return asset.id, scan.id

    def _get_scan(self, scan_id):
        with self.Session() as db:
            scan = db.get(Scan, scan_id)
            findings = list(db.scalars(select(FindingModel).where(FindingModel.scan_id == scan_id)))
            asset = db.get(Asset, scan.asset_id) if scan else None
            return scan, findings, asset


class SuccessfulScanTests(ScanManagerTestBase):
    def test_full_scan_persists_findings_and_completes(self) -> None:
        _, scan_id = self._seed()

        def tls(target, config):
            return [_finding("TLS_CERT_VALID")]

        def https(target, config):
            return [_finding("HTTPS_ACCESSIBLE")]

        def headers(target, config):
            return [_finding("HSTS_MISSING", severity="high")]

        def dns(domain, config):
            return [_finding("SPF_MISSING", severity="medium")]

        scan_manager.run_scan(
            scan_id,
            session_factory=self.Session,
            resolver=PUBLIC_RESOLVER,
            tls_inspector=tls,
            https_inspector=https,
            header_inspector=headers,
            dns_inspector=dns,
        )

        scan, findings, asset = self._get_scan(scan_id)
        self.assertEqual(scan.status, "completed")
        self.assertIsNotNone(scan.started_at)
        self.assertIsNotNone(scan.completed_at)
        self.assertIsNotNone(asset.last_scanned_at)
        self.assertEqual(
            {f.check_code for f in findings},
            {"TLS_CERT_VALID", "HTTPS_ACCESSIBLE", "HSTS_MISSING", "SPF_MISSING"},
        )

    def test_duplicate_check_codes_are_deduplicated(self) -> None:
        _, scan_id = self._seed()

        def tls(target, config):
            return [_finding("DUPLICATE"), _finding("DUPLICATE")]

        def https(target, config):
            return [_finding("DUPLICATE")]

        scan_manager.run_scan(
            scan_id,
            session_factory=self.Session,
            resolver=PUBLIC_RESOLVER,
            tls_inspector=tls,
            https_inspector=https,
            header_inspector=lambda t, c: [],
            dns_inspector=lambda d, c: [],
        )

        _, findings, _ = self._get_scan(scan_id)
        dupes = [f for f in findings if f.check_code == "DUPLICATE"]
        self.assertEqual(len(dupes), 1)

    def test_failing_module_does_not_abort_scan(self) -> None:
        _, scan_id = self._seed()

        def tls(target, config):
            raise RuntimeError("boom")

        def https(target, config):
            return [_finding("HTTPS_ACCESSIBLE")]

        scan_manager.run_scan(
            scan_id,
            session_factory=self.Session,
            resolver=PUBLIC_RESOLVER,
            tls_inspector=tls,
            https_inspector=https,
            header_inspector=lambda t, c: [],
            dns_inspector=lambda d, c: [],
        )

        scan, findings, _ = self._get_scan(scan_id)
        self.assertEqual(scan.status, "completed")
        self.assertEqual({f.check_code for f in findings}, {"HTTPS_ACCESSIBLE"})


class TargetValidationOutcomeTests(ScanManagerTestBase):
    def test_invalid_target_recorded_as_completed_with_finding(self) -> None:
        _, scan_id = self._seed()

        def bad_resolver(hostname, config):
            raise InvalidTargetError("bad target")

        scan_manager.run_scan(
            scan_id,
            session_factory=self.Session,
            resolver=bad_resolver,
            tls_inspector=lambda t, c: [],
            https_inspector=lambda t, c: [],
            header_inspector=lambda t, c: [],
            dns_inspector=lambda d, c: [],
        )

        scan, findings, _ = self._get_scan(scan_id)
        self.assertEqual(scan.status, "completed")
        self.assertIn("TARGET_INVALID", {f.check_code for f in findings})

    def test_unsafe_target_recorded_as_completed_with_finding(self) -> None:
        _, scan_id = self._seed()

        def unsafe_resolver(hostname, config):
            raise UnsafeTargetError("resolves to 10.0.0.1")

        scan_manager.run_scan(
            scan_id,
            session_factory=self.Session,
            resolver=unsafe_resolver,
            tls_inspector=lambda t, c: [],
            https_inspector=lambda t, c: [],
            header_inspector=lambda t, c: [],
            dns_inspector=lambda d, c: [],
        )

        scan, findings, _ = self._get_scan(scan_id)
        self.assertEqual(scan.status, "completed")
        self.assertIn("TARGET_SSRF_REJECTED", {f.check_code for f in findings})


class FailedScanTests(ScanManagerTestBase):
    def test_dns_resolution_failure_marks_scan_failed(self) -> None:
        _, scan_id = self._seed()

        def dns_fail(hostname, config):
            raise TargetDNSResolutionError("no such host")

        scan_manager.run_scan(
            scan_id,
            session_factory=self.Session,
            resolver=dns_fail,
            tls_inspector=lambda t, c: [],
            https_inspector=lambda t, c: [],
            header_inspector=lambda t, c: [],
            dns_inspector=lambda d, c: [],
        )

        scan, findings, _ = self._get_scan(scan_id)
        self.assertEqual(scan.status, "failed")
        self.assertIsNotNone(scan.completed_at)
        self.assertEqual(findings, [])

    def test_unauthorised_asset_scan_fails(self) -> None:
        _, scan_id = self._seed(authorization=False)
        scan_manager.run_scan(
            scan_id,
            session_factory=self.Session,
            resolver=PUBLIC_RESOLVER,
            tls_inspector=lambda t, c: [],
            https_inspector=lambda t, c: [],
            header_inspector=lambda t, c: [],
            dns_inspector=lambda d, c: [],
        )
        scan, _, _ = self._get_scan(scan_id)
        self.assertEqual(scan.status, "failed")

    def test_paused_asset_scan_fails(self) -> None:
        _, scan_id = self._seed(status="paused")
        scan_manager.run_scan(
            scan_id,
            session_factory=self.Session,
            resolver=PUBLIC_RESOLVER,
            tls_inspector=lambda t, c: [],
            https_inspector=lambda t, c: [],
            header_inspector=lambda t, c: [],
            dns_inspector=lambda d, c: [],
        )
        scan, _, _ = self._get_scan(scan_id)
        self.assertEqual(scan.status, "failed")

    def test_monitoring_disabled_asset_scan_fails(self) -> None:
        _, scan_id = self._seed(monitoring=False)
        scan_manager.run_scan(
            scan_id,
            session_factory=self.Session,
            resolver=PUBLIC_RESOLVER,
            tls_inspector=lambda t, c: [],
            https_inspector=lambda t, c: [],
            header_inspector=lambda t, c: [],
            dns_inspector=lambda d, c: [],
        )
        scan, _, _ = self._get_scan(scan_id)
        self.assertEqual(scan.status, "failed")

    def test_missing_scan_is_noop(self) -> None:
        # Should not raise even though the scan id does not exist.
        scan_manager.run_scan(
            999999,
            session_factory=self.Session,
            resolver=PUBLIC_RESOLVER,
            tls_inspector=lambda t, c: [],
            https_inspector=lambda t, c: [],
            header_inspector=lambda t, c: [],
            dns_inspector=lambda d, c: [],
        )


if __name__ == "__main__":
    unittest.main()