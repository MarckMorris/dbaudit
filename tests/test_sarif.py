"""SARIF output, validated against what GitHub code scanning requires."""

import json

from dbaudit.checks import postgres as _postgres  # noqa: F401  registers checks
from dbaudit.core import run_checks
from dbaudit.platform import Platform
from dbaudit.sarif import dumps, to_sarif
from tests import fakes


def neglected_report():
    return run_checks(
        fakes.neglected(),
        "postgres",
        target="postgres://app:***@db.internal:5432/orders",
        platform=Platform.SELF_HOSTED,
    )


class TestDocumentShape:
    def test_declares_version_and_schema(self):
        doc = to_sarif(neglected_report())
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-schema-2.1.0.json")

    def test_has_exactly_one_run(self):
        assert len(to_sarif(neglected_report())["runs"]) == 1

    def test_driver_identifies_the_tool(self):
        driver = to_sarif(neglected_report())["runs"][0]["tool"]["driver"]
        assert driver["name"] == "dbaudit"
        assert driver["informationUri"].startswith("https://")
        assert driver["version"]

    def test_serialises_to_valid_json(self):
        json.loads(dumps(neglected_report()))


class TestResults:
    def test_only_failures_are_reported(self):
        report = neglected_report()
        results = to_sarif(report)["runs"][0]["results"]
        reported = {r["ruleId"] for r in results}
        assert reported == {f.check_id for f in report.failures}

    def test_passing_checks_produce_no_results(self):
        report = run_checks(fakes.healthy(), "postgres", platform=Platform.SELF_HOSTED)
        assert to_sarif(report)["runs"][0]["results"] == []

    def test_not_applicable_checks_are_omitted(self):
        report = run_checks(fakes.neglected(), "postgres", platform=Platform.RDS)
        reported = {r["ruleId"] for r in to_sarif(report)["runs"][0]["results"]}
        assert "pg.security.trust_auth" not in reported

    def test_every_result_indexes_a_real_rule(self):
        doc = to_sarif(neglected_report())["runs"][0]
        rules = doc["tool"]["driver"]["rules"]
        for result in doc["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    def test_every_result_has_a_location(self):
        """GitHub silently drops results with no physical location."""
        for result in to_sarif(neglected_report(), location="db/orders")["runs"][0]["results"]:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert uri == "db/orders"

    def test_severity_maps_to_a_valid_sarif_level(self):
        allowed = {"error", "warning", "note", "none"}
        for result in to_sarif(neglected_report())["runs"][0]["results"]:
            assert result["level"] in allowed

    def test_security_severity_is_numeric_for_github_badges(self):
        for rule in to_sarif(neglected_report())["runs"][0]["tool"]["driver"]["rules"]:
            float(rule["properties"]["security-severity"])

    def test_message_carries_the_remediation(self):
        results = to_sarif(neglected_report())["runs"][0]["results"]
        ssl = next(r for r in results if r["ruleId"] == "pg.security.ssl")
        assert "Remediation:" in ssl["message"]["text"]


class TestFingerprints:
    def test_are_stable_across_runs(self):
        first = to_sarif(neglected_report())["runs"][0]["results"]
        second = to_sarif(neglected_report())["runs"][0]["results"]
        assert [r["partialFingerprints"] for r in first] == [
            r["partialFingerprints"] for r in second
        ]

    def test_differ_between_targets(self):
        a = run_checks(fakes.neglected(), "postgres", target="db-a")
        b = run_checks(fakes.neglected(), "postgres", target="db-b")
        fa = to_sarif(a)["runs"][0]["results"][0]["partialFingerprints"]
        fb = to_sarif(b)["runs"][0]["results"][0]["partialFingerprints"]
        assert fa != fb


class TestSuppression:
    def test_baselined_findings_are_marked_suppressed_not_hidden(self):
        """A waived finding stays in the file so it can still be audited."""
        report = run_checks(
            fakes.neglected(),
            "postgres",
            platform=Platform.SELF_HOSTED,
            baseline={"pg.security.ssl"},
        )
        results = to_sarif(report)["runs"][0]["results"]
        ssl = next(r for r in results if r["ruleId"] == "pg.security.ssl")
        assert ssl["suppressions"][0]["kind"] == "external"

        other = next(r for r in results if r["ruleId"] != "pg.security.ssl")
        assert "suppressions" not in other
