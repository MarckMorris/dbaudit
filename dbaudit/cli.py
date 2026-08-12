"""Command line entry point for dbaudit."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from dbaudit import sarif as sarif_output
from dbaudit.core import Report, Severity, run_checks
from dbaudit.platform import Platform, detect_postgres
from dbaudit.checks import postgres as _postgres  # noqa: F401  registers checks

MARK = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP", "waived": "WAIVE"}

BASELINE_VERSION = 1


def engine_from_dsn(dsn: str) -> str:
    scheme = urlparse(dsn).scheme.lower()
    if scheme.startswith("postgres"):
        return "postgres"
    if scheme.startswith("mysql"):
        return "mysql"
    if scheme.startswith("redis"):
        return "redis"
    raise SystemExit(f"unsupported connection string: {scheme or dsn!r}")


def connect(dsn: str, engine: str):
    if engine == "postgres":
        try:
            import psycopg2
        except ImportError:  # pragma: no cover
            raise SystemExit("psycopg2-binary is required for PostgreSQL targets")
        return psycopg2.connect(dsn)
    raise SystemExit(f"{engine} support is not implemented yet")


def redact(dsn: str) -> str:
    """Hide the password so reports can be pasted into tickets."""
    parsed = urlparse(dsn)
    if parsed.password:
        return dsn.replace(f":{parsed.password}@", ":***@")
    return dsn


def resolve_platform(conn, engine: str, override: str | None) -> Platform:
    """Trust the operator over the probe, because a proxy can hide the real host."""
    if override:
        return Platform(override)
    if engine == "postgres":
        return detect_postgres(conn)
    return Platform.UNKNOWN


# --------------------------------------------------------------------------- #
# Baseline
# --------------------------------------------------------------------------- #


def load_baseline(path: str | None) -> set[str]:
    """Read waived check IDs.

    Accepts the file dbaudit writes with --init-baseline, or a bare JSON list
    for anyone who prefers to maintain it by hand.
    """
    if not path:
        return set()
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"baseline not found: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"baseline is not valid JSON: {path} ({exc})")

    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("suppressed", [])
    else:
        raise SystemExit(f"baseline must be a JSON object or list: {path}")

    waived: set[str] = set()
    for entry in entries:
        if isinstance(entry, str):
            waived.add(entry)
        elif isinstance(entry, dict) and entry.get("check_id"):
            waived.add(str(entry["check_id"]))
    return waived


def write_baseline(report: Report, path: str) -> int:
    """Freeze today's failures so CI only reports regressions from here on.

    This is what makes the tool adoptable on a database that already exists.
    Without it the first run is a wall of red and the job gets disabled.
    """
    suppressed = [
        {
            "check_id": f.check_id,
            "severity": f.severity.value,
            "title": f.title,
            "reason": "Accepted when the baseline was created. Replace with a real justification.",
        }
        for f in report.failures
    ]
    document = {
        "version": BASELINE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": report.target,
        "engine": report.engine,
        "platform": report.platform,
        "suppressed": suppressed,
    }
    Path(path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return len(suppressed)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _mark(finding) -> str:
    if not finding.applicable:
        return MARK["skip"]
    if finding.passed:
        return MARK["pass"]
    if finding.suppressed:
        return MARK["waived"]
    return MARK["fail"]


def render_text(report: Report) -> str:
    lines: list[str] = ["", f"  dbaudit  {report.engine}  {report.target}"]
    if report.platform and report.platform != Platform.UNKNOWN.value:
        lines.append(f"  platform  {report.platform}")
    lines.append("")

    for category, findings in sorted(report.by_category().items()):
        lines.append(f"  {category}")
        for f in findings:
            mark = _mark(f)
            sev = "" if f.passed or not f.applicable else f"  [{f.severity.value}]"
            lines.append(f"    {mark:<5}  {f.title}{sev}")
            if f.detail and (not f.passed or not f.applicable):
                lines.append(f"           {f.detail}")
            if not f.passed and f.applicable and f.remediation:
                lines.append(f"           fix: {f.remediation}")
            if not f.passed and f.applicable and f.cis:
                lines.append(f"           ref: {f.cis}")
        lines.append("")

    skipped = len(report.skipped)
    lines.append(f"  score {report.score}/100")
    summary = f"  {len(report.passes)} passed, {len(report.failures)} failed"
    if skipped:
        summary += f", {skipped} not applicable on this platform"
    lines.append(summary)
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dbaudit",
        description="Audit a live database for production readiness and CIS-aligned configuration.",
        epilog="Exit code 1 means a finding reached the --fail-on threshold.",
    )
    parser.add_argument(
        "dsn", help="connection string, e.g. postgres://user:pass@host:5432/db"
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default=None,
        help="exit non-zero when an unwaived failure reaches this severity",
    )
    parser.add_argument(
        "--platform",
        choices=[p.value for p in Platform],
        default=None,
        help="override platform detection (default: detect automatically)",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        default=None,
        help="waive the findings listed in FILE so CI only fails on regressions",
    )
    parser.add_argument(
        "--init-baseline",
        metavar="FILE",
        default=None,
        help="write current failures to FILE as an accepted baseline, then exit 0",
    )
    parser.add_argument(
        "--sarif",
        metavar="FILE",
        default=None,
        help="also write SARIF 2.1.0 to FILE for the GitHub Security tab",
    )
    parser.add_argument(
        "--sarif-location",
        metavar="PATH",
        default="database",
        help="artifact path GitHub attaches alerts to (default: database)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    engine = engine_from_dsn(args.dsn)
    baseline = load_baseline(args.baseline)

    conn = connect(args.dsn, engine)
    try:
        platform = resolve_platform(conn, engine, args.platform)
        report = run_checks(
            conn,
            engine,
            target=redact(args.dsn),
            platform=platform,
            baseline=baseline,
        )
    finally:
        conn.close()

    if args.init_baseline:
        count = write_baseline(report, args.init_baseline)
        print(
            f"wrote {count} accepted finding(s) to {args.init_baseline}. "
            "Review it, then pass --baseline to future runs."
        )
        return 0

    if args.sarif:
        Path(args.sarif).write_text(
            sarif_output.dumps(report, location=args.sarif_location) + "\n",
            encoding="utf-8",
        )

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_text(report))

    if args.fail_on and report.exceeds(Severity(args.fail_on)):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
