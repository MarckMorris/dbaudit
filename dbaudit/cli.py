"""Command line entry point for dbaudit."""

from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlparse

from dbaudit.core import Report, Severity, run_checks
from dbaudit.checks import postgres as _postgres  # noqa: F401  registers checks

ICON = {True: "PASS", False: "FAIL"}


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


def render_text(report: Report) -> str:
    lines: list[str] = []
    lines.append("")
    lines.append(f"  dbaudit  {report.engine}  {report.target}")
    lines.append("")
    for category, findings in sorted(report.by_category().items()):
        lines.append(f"  {category}")
        for f in findings:
            mark = ICON[f.passed]
            sev = "" if f.passed else f"  [{f.severity.value}]"
            lines.append(f"    {mark}  {f.title}{sev}")
            if not f.passed and f.detail:
                lines.append(f"          {f.detail}")
            if not f.passed and f.remediation:
                lines.append(f"          fix: {f.remediation}")
        lines.append("")
    lines.append(f"  score {report.score}/100")
    lines.append(f"  {len(report.passes)} passed, {len(report.failures)} failed")
    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dbaudit",
        description="Check a database for production readiness.",
    )
    parser.add_argument("dsn", help="connection string, e.g. postgres://user:pass@host:5432/db")
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
        help="exit non-zero when a failure reaches this severity",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    engine = engine_from_dsn(args.dsn)
    conn = connect(args.dsn, engine)
    try:
        report = run_checks(conn, engine, target=redact(args.dsn))
    finally:
        conn.close()

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_text(report))

    if args.fail_on and report.exceeds(Severity(args.fail_on)):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
