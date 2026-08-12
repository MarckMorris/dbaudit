"""Each PostgreSQL check, at its pass boundary and its fail boundary."""

import pytest

from dbaudit.checks import postgres as pg
from dbaudit.core import Severity, checks_for
from tests import fakes


def result(check_cls, conn):
    return check_cls().run(conn)


class TestRegistry:
    def test_all_checks_are_registered_for_postgres(self):
        assert len(checks_for("postgres")) == 10

    def test_check_ids_are_unique(self):
        ids = [c.id for c in checks_for("postgres")]
        assert len(ids) == len(set(ids))

    def test_every_check_declares_its_metadata(self):
        for check in checks_for("postgres"):
            assert check.id and check.title and check.category
            assert isinstance(check.severity, Severity)
            assert check.cis, f"{check.id} has no benchmark reference"

    def test_ids_are_namespaced_by_engine(self):
        assert all(c.id.startswith("pg.") for c in checks_for("postgres"))

    def test_an_unknown_engine_has_no_checks(self):
        assert checks_for("cassandra") == []


class TestSsl:
    @pytest.mark.parametrize("value,passed", [("on", True), ("off", False)])
    def test_reads_the_ssl_setting(self, value, passed):
        conn = fakes.FakePostgres(settings={"ssl": value})
        assert result(pg.SslEnabled, conn).passed is passed

    def test_cleartext_is_critical(self):
        assert pg.SslEnabled.severity is Severity.CRITICAL


class TestTrustAuth:
    def test_passes_when_no_rule_uses_trust(self):
        assert result(pg.NoTrustAuth, fakes.healthy()).passed is True

    def test_fails_on_a_single_trust_rule(self):
        finding = result(pg.NoTrustAuth, fakes.trust_rule_only())
        assert finding.passed is False
        assert "1 rule" in finding.detail


class TestScram:
    @pytest.mark.parametrize(
        "value,passed",
        [("scram-sha-256", True), ("md5", False), ("", False)],
    )
    def test_only_scram_passes(self, value, passed):
        conn = fakes.FakePostgres(settings={"password_encryption": value})
        assert result(pg.ScramPasswords, conn).passed is passed


class TestSuperusers:
    @pytest.mark.parametrize("count,passed", [(1, True), (2, True), (3, False)])
    def test_threshold_is_two(self, count, passed):
        conn = fakes.FakePostgres(
            rows={
                "SELECT rolname FROM pg_roles WHERE rolsuper": [
                    (f"role{i}",) for i in range(count)
                ]
            }
        )
        assert result(pg.SuperuserCount, conn).passed is passed

    def test_names_the_offending_roles(self):
        conn = fakes.FakePostgres(
            rows={
                "SELECT rolname FROM pg_roles WHERE rolsuper": [
                    ("postgres",),
                    ("app",),
                    ("etl",),
                ]
            }
        )
        assert "etl" in result(pg.SuperuserCount, conn).detail


class TestWalLevel:
    @pytest.mark.parametrize(
        "value,passed",
        [("replica", True), ("logical", True), ("minimal", False)],
    )
    def test_replica_or_logical_is_required(self, value, passed):
        conn = fakes.FakePostgres(settings={"wal_level": value})
        assert result(pg.BackupWalLevel, conn).passed is passed


class TestArchiveMode:
    @pytest.mark.parametrize(
        "value,passed", [("on", True), ("always", True), ("off", False)]
    )
    def test_accepts_on_and_always(self, value, passed):
        conn = fakes.FakePostgres(settings={"archive_mode": value})
        assert result(pg.ArchiveMode, conn).passed is passed


class TestConnectionHeadroom:
    @pytest.mark.parametrize(
        "used,limit,passed",
        [(10, 100, True), (79, 100, True), (80, 100, False), (95, 100, False)],
    )
    def test_fails_at_eighty_percent(self, used, limit, passed):
        conn = fakes.FakePostgres(
            settings={"max_connections": str(limit)},
            rows={"SELECT count(*) FROM pg_stat_activity": [(used,)]},
        )
        assert result(pg.ConnectionHeadroom, conn).passed is passed

    def test_reports_the_percentage(self):
        conn = fakes.FakePostgres(
            settings={"max_connections": "200"},
            rows={"SELECT count(*) FROM pg_stat_activity": [(180,)]},
        )
        assert "90%" in result(pg.ConnectionHeadroom, conn).detail


class TestStatStatements:
    @pytest.mark.parametrize("count,passed", [(1, True), (0, False)])
    def test_looks_for_the_extension(self, count, passed):
        conn = fakes.FakePostgres(
            rows={"SELECT count(*) FROM pg_extension": [(count,)]}
        )
        assert result(pg.StatStatementsAvailable, conn).passed is passed


class TestSlowQueryLogging:
    @pytest.mark.parametrize(
        "value,passed", [("1000", True), ("0", True), ("-1", False)]
    )
    def test_minus_one_means_disabled(self, value, passed):
        conn = fakes.FakePostgres(settings={"log_min_duration_statement": value})
        assert result(pg.SlowQueryLogging, conn).passed is passed


class TestReplication:
    @pytest.mark.parametrize("count,passed", [(2, True), (1, True), (0, False)])
    def test_needs_at_least_one_replica(self, count, passed):
        conn = fakes.FakePostgres(
            rows={"SELECT count(*) FROM pg_stat_replication": [(count,)]}
        )
        assert result(pg.ReplicationConfigured, conn).passed is passed


class TestResilience:
    def test_a_check_that_raises_does_not_abort_the_audit(self):
        """A missing view on an exotic platform must not lose the other findings."""
        from dbaudit.core import run_checks

        class Broken(fakes.FakePostgres):
            def resolve(self, sql, params):
                if "pg_stat_replication" in sql:
                    raise RuntimeError("permission denied for view pg_stat_replication")
                return super().resolve(sql, params)

        report = run_checks(Broken(), "postgres")
        assert len(report) == 10
        broken = next(f for f in report if f.check_id == "pg.ha.replication")
        assert broken.applicable is False
        assert "permission denied" in broken.detail
