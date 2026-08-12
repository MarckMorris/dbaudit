"""SARIF 2.1.0 output for GitHub code scanning.

GitHub's Security tab ingests SARIF uploaded by `github/codeql-action/upload-sarif`.
Emitting SARIF turns a dbaudit run into tracked, deduplicated security alerts with
history and assignees, instead of a log line that scrolls past in CI output.

dbaudit inspects a live database rather than files in the repository, so every
result is anchored to a synthetic artifact path (`--sarif-location`, default
`database`) because GitHub requires a location to attach an alert to.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .core import Finding, Report, Severity

SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/MarckMorris/dbaudit"

# SARIF defines error/warning/note/none. GitHub renders all three visibly.
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub reads the numeric `security-severity` property to render its own
# Critical / High / Medium / Low badges. Values follow the CVSS 3.1 bands.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _version() -> str:
    try:
        from . import __version__

        return str(__version__)
    except Exception:  # pragma: no cover - packaging fallback
        return "0.0.0"


def _rule(finding: Finding) -> dict[str, Any]:
    """Describe a check once, in the SARIF rule catalogue."""
    help_text = finding.remediation or "No remediation recorded for this check."
    if finding.cis:
        help_text = f"{help_text}\n\nBenchmark reference: {finding.cis}"

    tags = ["database", "configuration", finding.category]
    if finding.cis:
        tags.append("cis-benchmark")

    return {
        "id": finding.check_id,
        "name": finding.check_id.replace(".", "_"),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.detail or finding.title},
        "help": {"text": help_text, "markdown": help_text},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "problem.severity": (
                "error" if finding.severity.rank >= Severity.HIGH.rank else "warning"
            ),
        },
    }


def _fingerprint(report: Report, finding: Finding) -> str:
    """Stable identity so GitHub tracks one alert across runs, not a new one each time."""
    seed = f"{report.engine}|{report.target}|{finding.check_id}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def _result(report: Report, finding: Finding, index: int, location: str) -> dict[str, Any]:
    message = finding.detail or finding.title
    if finding.remediation:
        message = f"{message} Remediation: {finding.remediation}"

    result: dict[str, Any] = {
        "ruleId": finding.check_id,
        "ruleIndex": index,
        "level": _LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {"dbauditCheck/v1": _fingerprint(report, finding)},
        "properties": {
            "engine": report.engine,
            "platform": report.platform.value,
            "category": finding.category,
        },
    }

    if finding.suppressed:
        # SARIF-native suppression: the alert stays visible in the file but
        # GitHub closes it, so a baselined finding does not silently vanish.
        result["suppressions"] = [
            {"kind": "external", "justification": "Suppressed by dbaudit baseline"}
        ]

    return result


def to_sarif(report: Report, location: str = "database") -> dict[str, Any]:
    """Render a report as a SARIF 2.1.0 document.

    Passing checks and checks marked not-applicable for the detected platform are
    omitted: an alert feed should contain problems, not an inventory.
    """
    reportable = [
        f for f in report.findings if not f.passed and f.applicable
    ]

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in reportable:
        if finding.check_id not in rule_index:
            rule_index[finding.check_id] = len(rules)
            rules.append(_rule(finding))
        results.append(
            _result(report, finding, rule_index[finding.check_id], location)
        )

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dbaudit",
                        "version": _version(),
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {
                    "id": f"dbaudit/{report.engine}/{report.platform.value}"
                },
                "results": results,
                "properties": {
                    "score": report.score,
                    "platform": report.platform.value,
                },
            }
        ],
    }


def dumps(report: Report, location: str = "database") -> str:
    """SARIF as a JSON string, ready to write to a file and upload."""
    return json.dumps(to_sarif(report, location=location), indent=2)
