"""Production-readiness checks for PostgreSQL."""

from __future__ import annotations

from typing import Any

from dbaudit.core import Check, Finding, Severity, register

PG = ("postgres",)


def _scalar(conn: Any, sql: str, default: Any = None) -> Any:
    """Run a query and return the first column of the first row."""
    with conn.cursor() as cur:
        cur.execute(sql)
        row = cur.fetchone()
    return default if row is None else row[0]


def _rows(conn: Any, sql: str) -> list[tuple]:
    with conn.cursor() as cur:
        cur.execute(sql)
        return list(cur.fetchall())


@register
class SslEnabled(Check):
    id = "pg.security.ssl"
    title = "Connections are encrypted with TLS"
    severity = Severity.CRITICAL
    category = "security"
    engines = PG

    def run(self, conn: Any) -> Finding:
        on = str(_scalar(conn, "SHOW ssl", "off")).lower() == "on"
        return self._finding(
            passed=on,
            detail="ssl is on" if on else "ssl is off, traffic is in cleartext",
            remediation="Set ssl = on in postgresql.conf and provide a certificate.",
        )


@register
class NoTrustAuth(Check):
    id = "pg.security.trust_auth"
    title = "No host rule uses trust authentication"
    severity = Severity.CRITICAL
    category = "security"
    engines = PG

    def run(self, conn: Any) -> Finding:
        rows = _rows(
            conn,
            "SELECT type, database, user_name, address, auth_method "
            "FROM pg_hba_file_rules WHERE auth_method = 'trust'",
        )
        return self._finding(
            passed=not rows,
            detail=f"{len(rows)} rule(s) allow passwordless access" if rows else "no trust rules",
            remediation="Replace trust with scram-sha-256 in pg_hba.conf.",
        )


@register
class ScramPasswords(Check):
    id = "pg.security.scram"
    title = "Passwords are hashed with SCRAM-SHA-256"
    severity = Severity.HIGH
    category = "security"
    engines = PG

    def run(self, conn: Any) -> Finding:
        method = str(_scalar(conn, "SHOW password_encryption", "")).lower()
        ok = method == "scram-sha-256"
        return self._finding(
            passed=ok,
            detail=f"password_encryption is {method or 'unset'}",
            remediation="Set password_encryption = scram-sha-256 and reset user passwords.",
        )


@register
class SuperuserCount(Check):
    id = "pg.security.superusers"
    title = "Superuser accounts are limited"
    severity = Severity.HIGH
    category = "security"
    engines = PG

    MAX = 2

    def run(self, conn: Any) -> Finding:
        names = [r[0] for r in _rows(conn, "SELECT rolname FROM pg_roles WHERE rolsuper")]
        ok = len(names) <= self.MAX
        return self._finding(
            passed=ok,
            detail=f"{len(names)} superuser(s): {', '.join(names)}",
            remediation="Grant narrower roles instead of superuser to application accounts.",
        )


@register
class BackupWalLevel(Check):
    id = "pg.backup.wal_level"
    title = "WAL level supports point-in-time recovery"
    severity = Severity.HIGH
    category = "backups"
    engines = PG

    def run(self, conn: Any) -> Finding:
        level = str(_scalar(conn, "SHOW wal_level", "")).lower()
        ok = level in ("replica", "logical")
        return self._finding(
            passed=ok,
            detail=f"wal_level is {level or 'unset'}",
            remediation="Set wal_level = replica so base backups can be replayed.",
        )


@register
class ArchiveMode(Check):
    id = "pg.backup.archive_mode"
    title = "WAL archiving is enabled"
    severity = Severity.HIGH
    category = "backups"
    engines = PG

    def run(self, conn: Any) -> Finding:
        mode = str(_scalar(conn, "SHOW archive_mode", "off")).lower()
        ok = mode in ("on", "always")
        return self._finding(
            passed=ok,
            detail=f"archive_mode is {mode}",
            remediation="Enable archive_mode and set archive_command to ship WAL offsite.",
        )


@register
class ConnectionHeadroom(Check):
    id = "pg.capacity.connections"
    title = "Connection pool has headroom"
    severity = Severity.MEDIUM
    category = "capacity"
    engines = PG

    THRESHOLD = 0.8

    def run(self, conn: Any) -> Finding:
        used = int(_scalar(conn, "SELECT count(*) FROM pg_stat_activity", 0))
        limit = int(_scalar(conn, "SHOW max_connections", 100))
        ratio = used / limit if limit else 0.0
        ok = ratio < self.THRESHOLD
        return self._finding(
            passed=ok,
            detail=f"{used} of {limit} connections in use ({ratio:.0%})",
            remediation="Put PgBouncer in front of the database or raise max_connections.",
        )


@register
class StatStatementsAvailable(Check):
    id = "pg.observability.pg_stat_statements"
    title = "Query statistics are collected"
    severity = Severity.MEDIUM
    category = "observability"
    engines = PG

    def run(self, conn: Any) -> Finding:
        found = _scalar(
            conn,
            "SELECT count(*) FROM pg_extension WHERE extname = 'pg_stat_statements'",
            0,
        )
        ok = int(found) > 0
        return self._finding(
            passed=ok,
            detail="pg_stat_statements installed" if ok else "pg_stat_statements missing",
            remediation="CREATE EXTENSION pg_stat_statements and add it to shared_preload_libraries.",
        )


@register
class SlowQueryLogging(Check):
    id = "pg.observability.slow_queries"
    title = "Slow queries are logged"
    severity = Severity.LOW
    category = "observability"
    engines = PG

    def run(self, conn: Any) -> Finding:
        raw = str(_scalar(conn, "SHOW log_min_duration_statement", "-1"))
        try:
            value = int(raw.replace("ms", "").strip())
        except ValueError:
            value = -1
        ok = value >= 0
        return self._finding(
            passed=ok,
            detail=f"log_min_duration_statement is {raw}",
            remediation="Set log_min_duration_statement to 1000 to capture queries over a second.",
        )


@register
class ReplicationConfigured(Check):
    id = "pg.ha.replication"
    title = "At least one replica is streaming"
    severity = Severity.MEDIUM
    category = "high-availability"
    engines = PG

    def run(self, conn: Any) -> Finding:
        count = int(_scalar(conn, "SELECT count(*) FROM pg_stat_replication", 0))
        ok = count > 0
        return self._finding(
            passed=ok,
            detail=f"{count} replica(s) connected",
            remediation="Configure at least one streaming replica for failover.",
        )
