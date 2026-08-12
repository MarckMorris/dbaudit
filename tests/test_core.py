"""Tests for the scoring engine and check registry."""

import pytest

from dbaudit.core import Check, Finding, Report, Severity, checks_for, run_checks


def make(severity: Severity, passed: bool, category: str = "security") -> Finding:
    return Finding(
        check_id=f"t.{severity.value}.{passed}",
        title="test",
        severity=severity,
        passed=passed,
        category=category,
    )


class TestSeverity:
    def test_ranks_are_ordered(self):
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_penalties_increase_with_severity(self):
        assert Severity.INFO.penalty == 0
        assert Severity.CRITICAL.penalty > Severity.HIGH.penalty


class TestReportScore:
    def test_clean_report_scores_100(self):
        report = Report(findings=[make(Severity.CRITICAL, True)])
        assert report.score == 100

    def test_failures_deduct_points(self):
        report = Report(findings=[make(Severity.MEDIUM, False)])
        assert report.score == 90

    def test_score_never_goes_below_zero(self):
        report = Report(findings=[make(Severity.CRITICAL, False) for _ in range(10)])
        assert report.score == 0

    def test_empty_report_scores_100(self):
        assert Report().score == 100


class TestReportThresholds:
    def test_worst_is_none_when_everything_passes(self):
        assert Report(findings=[make(Severity.HIGH, True)]).worst is None

    def test_worst_picks_highest_failure(self):
        report = Report(findings=[make(Severity.LOW, False), make(Severity.HIGH, False)])
        assert report.worst is Severity.HIGH

    def test_exceeds_is_true_at_threshold(self):
        report = Report(findings=[make(Severity.HIGH, False)])
        assert report.exceeds(Severity.HIGH)

    def test_exceeds_is_false_below_threshold(self):
        report = Report(findings=[make(Severity.LOW, False)])
        assert not report.exceeds(Severity.HIGH)


class TestGrouping:
    def test_findings_group_by_category(self):
        report = Report(
            findings=[
                make(Severity.LOW, True, "security"),
                make(Severity.LOW, False, "backups"),
            ]
        )
        grouped = report.by_category()
        assert set(grouped) == {"security", "backups"}

    def test_serialises_to_dict(self):
        report = Report(target="postgres://x", engine="postgres")
        report.add(make(Severity.HIGH, False))
        data = report.to_dict()
        assert data["engine"] == "postgres"
        assert data["failed"] == 1
        assert data["findings"][0]["severity"] == "high"


class TestRegistry:
    def test_engine_filter_matches_declared_engines(self):
        postgres_checks = checks_for("postgres")
        assert postgres_checks, "postgres checks should be registered"

    def test_a_failing_check_does_not_abort_the_run(self):
        class Boom(Check):
            id = "test.boom"
            title = "explodes"
            severity = Severity.HIGH
            engines = ("fake",)

            def run(self, conn):
                raise RuntimeError("kaboom")

        from dbaudit.core import REGISTRY

        REGISTRY.append(Boom)
        try:
            report = run_checks(conn=None, engine="fake")
            assert len(report) == 1
            assert report.findings[0].passed is True
            assert "kaboom" in report.findings[0].detail
        finally:
            REGISTRY.remove(Boom)
