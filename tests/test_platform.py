"""Platform detection and platform-aware reporting."""

import pytest

from dbaudit.checks import postgres as _postgres  # noqa: F401  registers checks
from dbaudit.core import run_checks
from dbaudit.platform import (
    NOT_APPLICABLE,
    REMEDIATION,
    Platform,
    detect_postgres,
    not_applicable_reason,
    remediation_for,
)
from tests import fakes


class TestDetection:
    @pytest.mark.parametrize(
        "factory,expected",
        [
            (fakes.healthy, Platform.SELF_HOSTED),
            (fakes.rds, Platform.RDS),
            (fakes.aurora, Platform.AURORA),
            (fakes.cloud_sql, Platform.CLOUD_SQL),
            (fakes.azure, Platform.AZURE),
        ],
    )
    def test_identifies_each_platform(self, factory, expected):
        assert detect_postgres(factory()) is expected

    def test_aurora_wins_over_rds(self):
        """Aurora also exposes the rds namespace, so order of checks matters."""
        conn = fakes.aurora()
        assert "rds" in conn.namespaces
        assert detect_postgres(conn) is Platform.AURORA

    def test_failed_probe_rolls_back_the_transaction(self):
        """A failed probe must not poison the session for the checks that follow."""
        conn = fakes.rds()
        detect_postgres(conn)
        assert conn.rollbacks >= 1

    def test_unreachable_server_is_unknown(self):
        class Dead:
            def cursor(self):
                raise RuntimeError("connection reset")

        assert detect_postgres(Dead()) is Platform.UNKNOWN


class TestRemediation:
    def test_managed_platforms_never_get_postgresql_conf_advice(self):
        """Editing postgresql.conf is impossible on a managed platform."""
        managed = [p for p in Platform if p.is_managed]
        for check_id in REMEDIATION:
            for platform in managed:
                text = remediation_for(check_id, platform)
                assert "postgresql.conf" not in text, f"{check_id} on {platform.value}"

    def test_falls_back_to_self_hosted_wording(self):
        text = remediation_for("pg.security.ssl", Platform.UNKNOWN)
        assert text == REMEDIATION["pg.security.ssl"][Platform.SELF_HOSTED]

    def test_unknown_check_returns_the_fallback(self):
        assert remediation_for("does.not.exist", Platform.RDS, "original") == "original"

    def test_every_remediation_entry_covers_every_managed_platform(self):
        for check_id, options in REMEDIATION.items():
            for platform in (p for p in Platform if p.is_managed):
                assert platform in options, f"{check_id} missing {platform.value}"


class TestApplicability:
    def test_pg_hba_is_not_applicable_on_managed_platforms(self):
        for platform in (p for p in Platform if p.is_managed):
            assert not_applicable_reason("pg.security.trust_auth", platform)

    def test_pg_hba_is_applicable_when_self_hosted(self):
        assert not_applicable_reason("pg.security.trust_auth", Platform.SELF_HOSTED) is None

    def test_every_not_applicable_check_exists_in_the_registry(self):
        from dbaudit.core import checks_for

        known = {c.id for c in checks_for("postgres")}
        assert set(NOT_APPLICABLE) <= known


class TestReportAdaptation:
    def test_rds_skips_pg_hba_instead_of_failing_on_it(self):
        conn = fakes.rds()
        report = run_checks(conn, "postgres", platform=Platform.RDS)
        finding = next(f for f in report if f.check_id == "pg.security.trust_auth")
        assert finding.applicable is False
        assert finding not in report.failures
        assert finding in report.skipped

    def test_a_skipped_check_does_not_reduce_the_score(self):
        """The same neglected server scores higher on RDS, because a control
        the provider does not expose should not be counted against it."""
        self_hosted = run_checks(
            fakes.trust_rule_only(), "postgres", platform=Platform.SELF_HOSTED
        )
        managed = run_checks(
            fakes.trust_rule_only(), "postgres", platform=Platform.RDS
        )

        assert "pg.security.trust_auth" in {f.check_id for f in self_hosted.failures}
        assert "pg.security.trust_auth" not in {f.check_id for f in managed.failures}
        assert managed.score > self_hosted.score

    def test_a_clean_managed_instance_scores_100(self):
        assert run_checks(fakes.rds(), "postgres", platform=Platform.RDS).score == 100

    def test_findings_carry_platform_specific_remediation(self):
        conn = fakes.neglected()
        report = run_checks(conn, "postgres", platform=Platform.CLOUD_SQL)
        ssl = next(f for f in report if f.check_id == "pg.security.ssl")
        assert "Cloud SQL" in ssl.remediation or "Require SSL" in ssl.remediation

    def test_report_records_the_platform(self):
        report = run_checks(fakes.aurora(), "postgres", platform=Platform.AURORA)
        assert report.platform == "aws-aurora"
        assert report.to_dict()["platform"] == "aws-aurora"

    def test_aurora_skips_both_wal_checks(self):
        report = run_checks(fakes.aurora(), "postgres", platform=Platform.AURORA)
        skipped = {f.check_id for f in report.skipped}
        assert {"pg.backup.wal_level", "pg.backup.archive_mode"} <= skipped
