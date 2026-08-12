"""End-to-end behaviour of the command line, including exit codes."""

import json

import pytest

from dbaudit import cli
from dbaudit.platform import Platform
from tests import fakes


@pytest.fixture
def run(monkeypatch):
    """Invoke main() against a fake server instead of a real one."""

    def _run(conn, argv):
        monkeypatch.setattr(cli, "connect", lambda dsn, engine: conn)
        return cli.main(argv)

    return _run


DSN = "postgres://app:hunter2@db.internal:5432/orders"


class TestDsnParsing:
    @pytest.mark.parametrize(
        "dsn,engine",
        [
            ("postgres://h/db", "postgres"),
            ("postgresql://h/db", "postgres"),
            ("mysql://h/db", "mysql"),
            ("redis://h:6379", "redis"),
        ],
    )
    def test_recognises_supported_schemes(self, dsn, engine):
        assert cli.engine_from_dsn(dsn) == engine

    def test_rejects_an_unknown_scheme(self):
        with pytest.raises(SystemExit):
            cli.engine_from_dsn("mongodb://h/db")


class TestRedaction:
    def test_password_never_reaches_the_report(self):
        assert "hunter2" not in cli.redact(DSN)
        assert cli.redact(DSN) == "postgres://app:***@db.internal:5432/orders"

    def test_dsn_without_a_password_is_unchanged(self):
        assert cli.redact("postgres://db.internal/orders") == "postgres://db.internal/orders"


class TestBaselineFile:
    def test_no_path_means_nothing_is_waived(self):
        assert cli.load_baseline(None) == set()

    def test_reads_a_bare_json_list(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text(json.dumps(["pg.security.ssl", "pg.ha.replication"]))
        assert cli.load_baseline(str(path)) == {"pg.security.ssl", "pg.ha.replication"}

    def test_reads_the_generated_document(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text(
            json.dumps({"version": 1, "suppressed": [{"check_id": "pg.security.ssl"}]})
        )
        assert cli.load_baseline(str(path)) == {"pg.security.ssl"}

    def test_missing_file_fails_loudly(self, tmp_path):
        with pytest.raises(SystemExit):
            cli.load_baseline(str(tmp_path / "absent.json"))

    def test_malformed_json_fails_loudly(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text("{not json")
        with pytest.raises(SystemExit):
            cli.load_baseline(str(path))

    def test_round_trips_through_init_baseline(self, tmp_path, run, capsys):
        path = tmp_path / "baseline.json"
        assert run(fakes.neglected(), [DSN, "--init-baseline", str(path)]) == 0

        document = json.loads(path.read_text())
        assert document["version"] == cli.BASELINE_VERSION
        assert document["suppressed"]
        assert "hunter2" not in json.dumps(document)

        assert cli.load_baseline(str(path))
        assert (
            run(fakes.neglected(), [DSN, "--baseline", str(path), "--fail-on", "critical"])
            == 0
        )


class TestExitCodes:
    def test_clean_server_exits_zero(self, run):
        assert run(fakes.healthy(), [DSN, "--fail-on", "low"]) == 0

    def test_failing_server_exits_one(self, run):
        assert run(fakes.neglected(), [DSN, "--fail-on", "critical"]) == 1

    def test_without_fail_on_it_only_reports(self, run):
        assert run(fakes.neglected(), [DSN]) == 0

    def test_a_low_failure_does_not_trip_a_critical_gate(self):
        """--fail-on is a threshold, not a switch."""
        from dbaudit.core import Severity, run_checks

        report = run_checks(
            fakes.FakePostgres(settings={"log_min_duration_statement": "-1"}), "postgres"
        )
        assert report.exceeds(Severity.LOW)
        assert not report.exceeds(Severity.CRITICAL)

    def test_baseline_turns_a_failure_green(self, run, tmp_path):
        path = tmp_path / "b.json"
        path.write_text(json.dumps(["pg.security.ssl"]))
        assert run(fakes.FakePostgres(settings={"ssl": "off"}), [DSN, "--fail-on", "critical"]) == 1
        assert (
            run(
                fakes.FakePostgres(settings={"ssl": "off"}),
                [DSN, "--fail-on", "critical", "--baseline", str(path)],
            )
            == 0
        )


class TestOutput:
    def test_json_is_machine_readable(self, run, capsys):
        run(fakes.neglected(), [DSN, "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["engine"] == "postgres"
        assert payload["score"] == 0
        assert payload["findings"]

    def test_text_output_names_the_platform(self, run, capsys):
        run(fakes.rds(), [DSN])
        out = capsys.readouterr().out
        assert "aws-rds" in out
        assert "score" in out

    def test_text_output_marks_skipped_checks(self, run, capsys):
        run(fakes.rds(), [DSN])
        out = capsys.readouterr().out
        assert "SKIP" in out
        assert "not applicable" in out

    def test_no_password_in_any_output(self, run, capsys):
        run(fakes.neglected(), [DSN])
        assert "hunter2" not in capsys.readouterr().out

    def test_sarif_is_written_to_disk(self, run, tmp_path):
        path = tmp_path / "dbaudit.sarif"
        run(fakes.neglected(), [DSN, "--sarif", str(path)])
        doc = json.loads(path.read_text())
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"]


class TestPlatformOverride:
    def test_override_beats_detection(self, run, capsys):
        """A pooler or proxy can mask the real host, so the operator wins."""
        run(fakes.healthy(), [DSN, "--platform", "gcp-cloud-sql"])
        assert "gcp-cloud-sql" in capsys.readouterr().out

    def test_detection_is_used_by_default(self, run, capsys):
        run(fakes.aurora(), [DSN])
        assert "aws-aurora" in capsys.readouterr().out

    def test_every_platform_value_is_accepted(self):
        parser = cli.build_parser()
        for platform in Platform:
            args = parser.parse_args(["postgres://h/db", "--platform", platform.value])
            assert args.platform == platform.value

    def test_connection_is_always_closed(self, run):
        conn = fakes.healthy()
        run(conn, [DSN])
        assert conn.closed
