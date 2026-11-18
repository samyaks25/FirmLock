"""Tests for the risk assessment and security scoring engine.

These tests use an isolated temporary SQLite database and persist findings and
check results directly, so they do not depend on the scanner's network
behaviour. They cover:

    * every severity penalty and the configurable weights;
    * multiple findings and duplicate-finding protection;
    * the minimum-score boundary;
    * informational findings;
    * unknown check outcomes (never penalised, reduce coverage);
    * failed, pending and running scans (no misleading score);
    * coverage calculation and the coverage threshold;
    * historical score preservation;
    * risk level, grade, priority issues and recommendations;
    * integration with the scan manager's check-result persistence.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.database.connection import Base
from app.models.models import (
    Asset,
    Business,
    CheckResult,
    Finding as FindingModel,
    RiskAssessment,
    Scan,
)
from app.services import risk_service
from app.services.risk_config import RiskConfig
from app.services.scanner import scan_manager
from app.services.scanner.check_catalog import ALL_GROUPS
from app.services.scanner.findings import Finding
from app.services.scanner.target_validator import UnsafeTargetError

PUBLIC_RESOLVER = lambda hostname, config: ["8.8.8.8"]  # noqa: E731


def _finding(code: str, severity: str = "info") -> Finding:
    return Finding(
        check_code=code,
        title=f"title {code}",
        description=f"description {code}",
        severity=severity,
        recommendation=f"fix {code}",
        evidence="evidence",
    )


class RiskEngineTestBase(unittest.TestCase):
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

    # --- helpers ---------------------------------------------------------
    def _seed(
        self,
        *,
        status: str = "completed",
        security_score: int | None = None,
        completed: bool = True,
    ) -> tuple[int, int]:
        now = datetime.now(timezone.utc)
        with self.Session() as db:
            biz = Business(name="Acme")
            db.add(biz)
            db.commit()
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
            scan = Scan(
                asset_id=asset.id,
                status=status,
                security_score=security_score,
                started_at=now if completed else None,
                completed_at=now if completed else None,
            )
            db.add(scan)
            db.commit()
            return asset.id, scan.id

    def _add_finding(
        self,
        scan_id: int,
        code: str,
        severity: str,
        *,
        title: str | None = None,
        recommendation: str | None = None,
    ) -> None:
        with self.Session() as db:
            db.add(
                FindingModel(
                    scan_id=scan_id,
                    check_code=code,
                    title=title or f"title {code}",
                    description=f"description {code}",
                    severity=severity,
                    recommendation=recommendation or f"fix {code}",
                    evidence="evidence",
                )
            )
            db.commit()

    def _set_checks(
        self, scan_id: int, outcomes: dict[str, str] | None = None
    ) -> None:
        """Persist one outcome per expected check group (default: passed)."""
        outcomes = outcomes or {}
        with self.Session() as db:
            for group in ALL_GROUPS:
                outcome = outcomes.get(group.check_id, "passed")
                db.add(
                    CheckResult(
                        scan_id=scan_id,
                        check_id=group.check_id,
                        module=group.module,
                        outcome=outcome,
                        detail=f"test outcome {outcome}",
                    )
                )
            db.commit()

    def _assess(self, scan_id: int, config: RiskConfig | None = None):
        with self.Session() as db:
            scan = db.get(Scan, scan_id)
            return risk_service.get_scan_risk(
                db, scan, config or risk_service.DEFAULT_RISK_CONFIG
            )

    def _get_scan(self, scan_id: int):
        with self.Session() as db:
            scan = db.get(Scan, scan_id)
            findings = list(
                db.scalars(
                    select(FindingModel).where(FindingModel.scan_id == scan_id)
                ).all()
            )
            checks = list(
                db.scalars(
                    select(CheckResult).where(CheckResult.scan_id == scan_id)
                ).all()
            )
            assessment = db.scalar(
                select(RiskAssessment).where(RiskAssessment.scan_id == scan_id)
            )
            return scan, findings, checks, assessment


class SeverityPenaltyTests(RiskEngineTestBase):
    def test_each_severity_penalty(self) -> None:
        cases = [
            ("critical", 25, 75),
            ("high", 15, 85),
            ("medium", 8, 92),
            ("low", 3, 97),
            ("info", 0, 100),
        ]
        for severity, expected_penalty, expected_score in cases:
            with self.subTest(severity=severity):
                _, scan_id = self._seed()
                self._set_checks(scan_id)
                self._add_finding(scan_id, f"{severity.upper()}_FINDING", severity)

                response = self._assess(scan_id)

                self.assertTrue(response.score_available)
                self.assertEqual(response.security_score, expected_score)
                self.assertEqual(response.total_penalty, expected_penalty)
                self.assertEqual(response.base_score, 100)
                if expected_penalty:
                    self.assertEqual(len(response.deductions), 1)
                    self.assertEqual(
                        response.deductions[0].severity, severity
                    )
                    self.assertEqual(
                        response.deductions[0].penalty, expected_penalty
                    )
                    self.assertTrue(response.deductions[0].reason)
                else:
                    self.assertEqual(response.deductions, [])

    def test_multiple_findings_are_summed(self) -> None:
        _, scan_id = self._seed()
        self._set_checks(scan_id)
        self._add_finding(scan_id, "CRIT", "critical")
        self._add_finding(scan_id, "HIGH", "high")
        self._add_finding(scan_id, "MED", "medium")
        self._add_finding(scan_id, "LOW", "low")
        self._add_finding(scan_id, "INFO", "info")

        response = self._assess(scan_id)

        self.assertEqual(response.security_score, 49)
        self.assertEqual(response.total_penalty, 51)
        self.assertEqual(len(response.deductions), 4)
        counts = response.findings_by_severity
        self.assertEqual(counts.critical, 1)
        self.assertEqual(counts.high, 1)
        self.assertEqual(counts.medium, 1)
        self.assertEqual(counts.low, 1)
        self.assertEqual(counts.info, 1)
        self.assertEqual(counts.total, 5)


class DuplicateFindingTests(RiskEngineTestBase):
    def test_duplicate_check_codes_are_deduplicated(self) -> None:
        findings = [
            _finding("DUP", "critical"),
            _finding("DUP", "critical"),
            _finding("DUP", "high"),
        ]
        deduped = risk_service._dedupe_findings(findings)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].severity, "critical")

    def test_database_rejects_duplicate_check_code(self) -> None:
        _, scan_id = self._seed()
        with self.Session() as db:
            db.add(
                FindingModel(
                    scan_id=scan_id,
                    check_code="DUP",
                    title="first",
                    description="first",
                    severity="low",
                    recommendation="fix",
                )
            )
            db.commit()
            db.add(
                FindingModel(
                    scan_id=scan_id,
                    check_code="DUP",
                    title="second",
                    description="second",
                    severity="low",
                    recommendation="fix",
                )
            )
            with self.assertRaises(IntegrityError):
                db.commit()
            db.rollback()


class MinimumScoreTests(RiskEngineTestBase):
    def test_minimum_score_boundary(self) -> None:
        _, scan_id = self._seed()
        self._set_checks(scan_id)
        for index in range(5):
            self._add_finding(scan_id, f"CRIT_{index}", "critical")

        response = self._assess(scan_id)

        self.assertEqual(response.security_score, 0)
        self.assertEqual(response.total_penalty, 100)
        self.assertEqual(len(response.deductions), 5)
        # The final deduction is capped at the minimum score.
        self.assertEqual(response.deductions[-1].applied_penalty, 0)
        self.assertEqual(response.deductions[-1].score_after, 0)

    def test_score_never_goes_negative(self) -> None:
        _, scan_id = self._seed()
        self._set_checks(scan_id)
        for index in range(10):
            self._add_finding(scan_id, f"CRIT_{index}", "critical")
        response = self._assess(scan_id)
        self.assertEqual(response.security_score, 0)


class InformationalFindingTests(RiskEngineTestBase):
    def test_informational_findings_do_not_penalise(self) -> None:
        _, scan_id = self._seed()
        self._set_checks(scan_id)
        self._add_finding(scan_id, "INFO_1", "info")
        self._add_finding(scan_id, "INFO_2", "info")

        response = self._assess(scan_id)

        self.assertEqual(response.security_score, 100)
        self.assertEqual(response.total_penalty, 0)
        self.assertEqual(response.deductions, [])
        self.assertEqual(response.risk_level, "minimal")
        self.assertEqual(response.grade, "A")


class UnknownResultTests(RiskEngineTestBase):
    def test_unknown_results_are_not_penalised(self) -> None:
        _, scan_id = self._seed()
        self._set_checks(scan_id, {"CAA": "unknown"})

        response = self._assess(scan_id)

        self.assertTrue(response.score_available)
        self.assertEqual(response.security_score, 100)
        self.assertEqual(response.total_penalty, 0)
        self.assertEqual(response.coverage.unknown, 1)
        self.assertIn("CAA", response.coverage.unknown_checks)
        self.assertAlmostEqual(response.coverage.percentage, 92.9, places=1)

    def test_technical_failure_findings_are_not_penalised(self) -> None:
        _, scan_id = self._seed()
        self._set_checks(
            scan_id,
            {"SPF": "unknown", "DMARC": "unknown", "CAA": "unknown"},
        )
        # Unknown markers are informational today; use a high severity here to
        # prove they are excluded from scoring regardless of severity.
        self._add_finding(scan_id, "DNS_TIMEOUT", "high")

        response = self._assess(scan_id)

        self.assertEqual(response.findings_total, 0)
        self.assertEqual(response.deductions, [])
        self.assertFalse(response.score_available)

    def test_unknown_checks_lower_coverage_and_block_score(self) -> None:
        _, scan_id = self._seed()
        self._set_checks(
            scan_id,
            {"SPF": "unknown", "DMARC": "unknown", "CAA": "unknown"},
        )

        response = self._assess(scan_id)

        self.assertFalse(response.score_available)
        self.assertIsNone(response.security_score)
        self.assertEqual(response.coverage.unknown, 3)
        self.assertAlmostEqual(response.coverage.percentage, 78.6, places=1)
        self.assertFalse(response.coverage.sufficient)
        self.assertIn("coverage", (response.unavailable_reason or "").lower())

    def test_unknown_result_does_not_hide_a_real_finding(self) -> None:
        _, scan_id = self._seed()
        self._set_checks(scan_id, {"CAA": "unknown"})
        self._add_finding(scan_id, "HSTS_MISSING", "high")

        response = self._assess(scan_id)

        self.assertTrue(response.score_available)
        self.assertEqual(response.security_score, 85)
        self.assertEqual(response.risk_level, "high")
        self.assertEqual(response.coverage.unknown, 1)


class IncompleteScanTests(RiskEngineTestBase):
    def test_failed_scan_has_no_score(self) -> None:
        _, scan_id = self._seed(status="failed", completed=False)
        response = self._assess(scan_id)
        self.assertEqual(response.scan_status, "failed")
        self.assertFalse(response.score_available)
        self.assertIsNone(response.security_score)
        self.assertIn("failed", (response.unavailable_reason or "").lower())

    def test_pending_and_running_scans_have_no_score(self) -> None:
        for status in ("pending", "running"):
            with self.subTest(status=status):
                _, scan_id = self._seed(status=status, completed=False)
                response = self._assess(scan_id)
                self.assertFalse(response.score_available)
                self.assertIsNone(response.security_score)
                self.assertIn(status, (response.unavailable_reason or "").lower())

    def test_pending_scan_is_not_persisted_as_assessment(self) -> None:
        _, scan_id = self._seed(status="pending", completed=False)
        self._assess(scan_id)
        _, _, _, assessment = self._get_scan(scan_id)
        self.assertIsNone(assessment)


    def test_legacy_target_rejection_scan_has_no_score(self) -> None:
        # Simulates a scan completed before check results were persisted.
        _, scan_id = self._seed()
        self._add_finding(scan_id, "TARGET_SSRF_REJECTED", "high")

        response = self._assess(scan_id)

        self.assertFalse(response.score_available)
        self.assertEqual(response.coverage.percentage, 0.0)
        self.assertEqual(response.coverage.unknown, len(ALL_GROUPS))


class CoverageTests(RiskEngineTestBase):
    def test_full_coverage(self) -> None:
        _, scan_id = self._seed()
        self._set_checks(scan_id)
        response = self._assess(scan_id)
        self.assertEqual(response.coverage.total, len(ALL_GROUPS))
        self.assertEqual(response.coverage.evaluated, len(ALL_GROUPS))
        self.assertEqual(response.coverage.unknown, 0)
        self.assertEqual(response.coverage.percentage, 100.0)
        self.assertTrue(response.coverage.sufficient)

    def test_partial_coverage(self) -> None:
        _, scan_id = self._seed()
        outcomes = {group.check_id: "unknown" for group in ALL_GROUPS[11:]}
        self._set_checks(scan_id, outcomes)
        response = self._assess(scan_id)
        self.assertEqual(response.coverage.evaluated, 11)
        self.assertEqual(response.coverage.unknown, 3)
        self.assertAlmostEqual(response.coverage.percentage, 78.6, places=1)

    def test_coverage_threshold_is_configurable(self) -> None:
        _, scan_id = self._seed()
        outcomes = {group.check_id: "unknown" for group in ALL_GROUPS[11:]}
        self._set_checks(scan_id, outcomes)
        config = RiskConfig(minimum_coverage_percent=70.0)
        response = self._assess(scan_id, config)
        self.assertTrue(response.coverage.sufficient)
        self.assertTrue(response.score_available)
        self.assertEqual(response.coverage.threshold_percent, 70.0)


class HistoricalScoreTests(RiskEngineTestBase):
    def test_assessment_is_persisted_and_not_recomputed(self) -> None:
        _, scan_id = self._seed()
        self._set_checks(scan_id)
        self._add_finding(scan_id, "CRIT", "critical")

        first = self._assess(scan_id)
        self.assertEqual(first.security_score, 75)

        # Add another critical finding after the first assessment.
        self._add_finding(scan_id, "CRIT_2", "critical")
        second = self._assess(scan_id)

        self.assertEqual(second.security_score, 75)
        self.assertEqual(len(second.deductions), 1)
        scan, _, _, assessment = self._get_scan(scan_id)
        self.assertEqual(scan.security_score, 75)
        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.security_score, 75)

    def test_pre_existing_score_is_preserved(self) -> None:
        _, scan_id = self._seed(security_score=42)
        self._set_checks(scan_id)
        self._add_finding(scan_id, "CRIT", "critical")

        response = self._assess(scan_id)

        self.assertEqual(response.security_score, 42)
        self.assertEqual(response.score_source, "stored")
        scan, _, _, _ = self._get_scan(scan_id)
        self.assertEqual(scan.security_score, 42)

    def test_score_change_between_scans(self) -> None:
        _, scan_id = self._seed(security_score=90)
        self._set_checks(scan_id)
        first = self._assess(scan_id)
        self.assertEqual(first.security_score, 90)

        _, scan_id_2 = self._seed(security_score=80)
        self._set_checks(scan_id_2)
        second = self._assess(scan_id_2)
        self.assertEqual(second.security_score, 80)


class RiskConfigTests(RiskEngineTestBase):
    def test_custom_weights_are_used(self) -> None:
        config = RiskConfig(
            penalty_critical=50,
            penalty_high=20,
            penalty_medium=10,
            penalty_low=5,
            penalty_info=0,
        )
        _, scan_id = self._seed()
        self._set_checks(scan_id)
        self._add_finding(scan_id, "CRIT", "critical")

        response = self._assess(scan_id, config)

        self.assertEqual(response.security_score, 50)
        self.assertEqual(response.score_weights.critical, 50)

    def test_config_clamps_negative_weights(self) -> None:
        config = RiskConfig(
            penalty_critical=-5,
            penalty_high=-1,
            penalty_medium=-1,
            penalty_low=-1,
            penalty_info=-1,
        )
        self.assertEqual(config.penalty_critical, 0)
        self.assertEqual(config.penalty_high, 0)
        self.assertEqual(config.penalty_info, 0)


class ClassificationTests(RiskEngineTestBase):
    def test_risk_level_follows_highest_severity(self) -> None:
        cases = [
            ("critical", "critical"),
            ("high", "high"),
            ("medium", "medium"),
            ("low", "low"),
            ("info", "minimal"),
        ]
        for severity, expected_level in cases:
            with self.subTest(severity=severity):
                _, scan_id = self._seed()
                self._set_checks(scan_id)
                self._add_finding(scan_id, "FINDING", severity)
                response = self._assess(scan_id)
                self.assertEqual(response.risk_level, expected_level)

    def test_grade_bands(self) -> None:
        # 100 -> A, 85 -> B, 75 -> C, 64 -> D, 49 -> F
        cases = [(100, "A"), (85, "B"), (75, "C"), (64, "D"), (49, "F")]
        for score, expected_grade in cases:
            with self.subTest(score=score):
                _, scan_id = self._seed()
                self._set_checks(scan_id)
                if score == 100:
                    pass
                elif score == 85:
                    self._add_finding(scan_id, "HIGH", "high")
                elif score == 75:
                    self._add_finding(scan_id, "CRIT", "critical")
                elif score == 64:
                    self._add_finding(scan_id, "CRIT", "critical")
                    self._add_finding(scan_id, "MED", "medium")
                    self._add_finding(scan_id, "LOW", "low")
                else:
                    self._add_finding(scan_id, "CRIT", "critical")
                    self._add_finding(scan_id, "HIGH", "high")
                    self._add_finding(scan_id, "MED", "medium")
                    self._add_finding(scan_id, "LOW", "low")
                response = self._assess(scan_id)
                self.assertEqual(response.security_score, score)
                self.assertEqual(response.grade, expected_grade)


class PriorityAndRecommendationTests(RiskEngineTestBase):
    def test_priority_order_and_recommendations(self) -> None:
        _, scan_id = self._seed()
        self._set_checks(scan_id)
        self._add_finding(
            scan_id, "CRIT", "critical", title="Expired certificate",
            recommendation="Renew the certificate",
        )
        self._add_finding(
            scan_id, "LOW", "low", title="Missing header",
            recommendation="Add the header",
        )
        self._add_finding(
            scan_id, "INFO", "info", title="Issuer",
            recommendation="Informational only",
        )

        response = self._assess(scan_id)

        self.assertEqual(len(response.highest_priority_issues), 2)
        self.assertEqual(response.highest_priority_issues[0].rank, 1)
        self.assertEqual(response.highest_priority_issues[0].severity, "critical")
        self.assertEqual(response.highest_priority_issues[1].rank, 2)
        self.assertEqual(response.highest_priority_issues[1].severity, "low")
        self.assertEqual(
            response.recommended_actions,
            ["Renew the certificate", "Add the header"],
        )


class ScanManagerIntegrationTests(RiskEngineTestBase):
    def test_scan_manager_persists_check_results_and_assessment(self) -> None:
        _, scan_id = self._seed(status="pending", completed=False)

        def tls(target, config):
            return [
                _finding("TLS_CONNECTION", "info"),
                _finding("TLS_CERT_ISSUER", "info"),
                _finding("TLS_CERT_VALID", "info"),
            ]

        def https(target, config):
            return [
                _finding("HTTPS_ACCESSIBLE", "info"),
                _finding("HTTP_TO_HTTPS_REDIRECT", "info"),
            ]

        def headers(target, config):
            return [_finding("HSTS_MISSING", "high")]

        def dns(domain, config):
            return [_finding("SPF_MISSING", "medium"), _finding("CAA_RECORD", "info")]

        scan_manager.run_scan(
            scan_id,
            session_factory=self.Session,
            resolver=PUBLIC_RESOLVER,
            tls_inspector=tls,
            https_inspector=https,
            header_inspector=headers,
            dns_inspector=dns,
        )

        scan, findings, checks, assessment = self._get_scan(scan_id)
        self.assertEqual(scan.status, "completed")
        self.assertEqual(len(checks), len(ALL_GROUPS))
        by_id = {check.check_id: check for check in checks}
        self.assertEqual(by_id["TLS_HANDSHAKE"].outcome, "passed")
        self.assertEqual(by_id["TLS_CERTIFICATE"].outcome, "passed")
        self.assertEqual(by_id["HSTS"].outcome, "failed")
        self.assertEqual(by_id["HSTS"].severity, "high")
        self.assertEqual(by_id["SPF"].outcome, "failed")
        self.assertEqual(by_id["DMARC"].outcome, "passed")
        self.assertEqual(by_id["CAA"].outcome, "passed")

        self.assertEqual(scan.security_score, 77)
        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.security_score, 77)
        self.assertEqual(assessment.coverage_percent, 100.0)

    def test_module_failure_marks_checks_unknown_and_blocks_score(self) -> None:
        _, scan_id = self._seed(status="pending", completed=False)

        def tls(target, config):
            raise RuntimeError("boom")

        def https(target, config):
            return [_finding("HTTPS_ACCESSIBLE", "info")]

        scan_manager.run_scan(
            scan_id,
            session_factory=self.Session,
            resolver=PUBLIC_RESOLVER,
            tls_inspector=tls,
            https_inspector=https,
            header_inspector=lambda t, c: [],
            dns_inspector=lambda d, c: [],
        )

        scan, _, checks, _ = self._get_scan(scan_id)
        self.assertEqual(scan.status, "completed")
        by_id = {check.check_id: check for check in checks}
        self.assertEqual(by_id["TLS_HANDSHAKE"].outcome, "unknown")
        self.assertEqual(by_id["TLS_CERTIFICATE"].outcome, "unknown")
        self.assertEqual(by_id["TLS_ISSUER"].outcome, "unknown")
        self.assertIn("RuntimeError", by_id["TLS_HANDSHAKE"].detail or "")
        self.assertIsNone(scan.security_score)

        response = self._assess(scan_id)
        self.assertFalse(response.score_available)
        self.assertAlmostEqual(response.coverage.percentage, 78.6, places=1)

    def test_rejected_target_scan_has_zero_coverage_and_no_score(self) -> None:
        _, scan_id = self._seed(status="pending", completed=False)

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

        scan, findings, checks, assessment = self._get_scan(scan_id)
        self.assertEqual(scan.status, "completed")
        self.assertIn("TARGET_SSRF_REJECTED", {finding.check_code for finding in findings})
        self.assertEqual(len(checks), len(ALL_GROUPS))
        self.assertTrue(all(check.outcome == "unknown" for check in checks))
        self.assertIsNone(scan.security_score)
        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.coverage_percent, 0.0)
        self.assertFalse(assessment.score_available)


if __name__ == "__main__":
    unittest.main()