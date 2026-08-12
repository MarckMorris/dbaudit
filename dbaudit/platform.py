"""Detect which managed platform a database runs on.

Every existing PostgreSQL compliance tool needs shell access to the server,
which rules out RDS, Aurora, Cloud SQL and Azure Database. dbaudit works from
a connection string alone, so it has to work out where it is by asking the
database itself, and then give remediation advice that is actually possible on
that platform. Telling someone to edit postgresql.conf on RDS is useless.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class Platform(str, Enum):
    AURORA = "aws-aurora"
    RDS = "aws-rds"
    CLOUD_SQL = "gcp-cloud-sql"
    AZURE = "azure-database"
    SELF_HOSTED = "self-hosted"
    UNKNOWN = "unknown"

    @property
    def is_managed(self) -> bool:
        return self in (Platform.AURORA, Platform.RDS, Platform.CLOUD_SQL, Platform.AZURE)

    @property
    def label(self) -> str:
        return {
            Platform.AURORA: "Amazon Aurora",
            Platform.RDS: "Amazon RDS",
            Platform.CLOUD_SQL: "Google Cloud SQL",
            Platform.AZURE: "Azure Database",
            Platform.SELF_HOSTED: "self-hosted",
            Platform.UNKNOWN: "unknown",
        }[self]


def _query_ok(conn: Any, sql: str) -> bool:
    """True when a statement runs without raising."""
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            cur.fetchone()
        return True
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return False


def _has_settings_prefix(conn: Any, prefix: str) -> bool:
    """True when pg_settings contains any parameter under a namespace."""
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_settings WHERE name LIKE %s LIMIT 1", (prefix + ".%",))
            return cur.fetchone() is not None
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return False


def detect_postgres(conn: Any) -> Platform:
    """Work out the hosting platform of a PostgreSQL connection.

    Aurora is checked before RDS because Aurora instances also expose the rds
    namespace, so the more specific signal has to win.
    """
    if _query_ok(conn, "SELECT aurora_version()"):
        return Platform.AURORA
    if _has_settings_prefix(conn, "rds"):
        return Platform.RDS
    if _has_settings_prefix(conn, "cloudsql"):
        return Platform.CLOUD_SQL
    if _has_settings_prefix(conn, "azure"):
        return Platform.AZURE
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT version()")
            row = cur.fetchone()
        if row and "Visual C++" in str(row[0]):
            return Platform.SELF_HOSTED
        return Platform.SELF_HOSTED if row else Platform.UNKNOWN
    except Exception:
        return Platform.UNKNOWN


#: Remediation text per check, per platform. The self-hosted wording is the
#: fallback used when a platform has no specific entry.
REMEDIATION: dict[str, dict[Platform, str]] = {
    "pg.security.ssl": {
        Platform.SELF_HOSTED: "Set ssl = on in postgresql.conf, supply a certificate and reload.",
        Platform.RDS: "Set rds.force_ssl = 1 in the DB parameter group, then reboot the instance.",
        Platform.AURORA: "Set rds.force_ssl = 1 in the cluster parameter group, then reboot.",
        Platform.CLOUD_SQL: "Enable Require SSL under Connections on the instance, or set requireSsl in Terraform.",
        Platform.AZURE: "Set require_secure_transport = ON in server parameters.",
    },
    "pg.security.scram": {
        Platform.SELF_HOSTED: "Set password_encryption = scram-sha-256 in postgresql.conf and reset passwords.",
        Platform.RDS: "Set password_encryption = scram-sha-256 in the parameter group, then reset user passwords.",
        Platform.AURORA: "Set password_encryption = scram-sha-256 in the cluster parameter group, then reset passwords.",
        Platform.CLOUD_SQL: "Set the password_encryption database flag to scram-sha-256, then reset passwords.",
        Platform.AZURE: "Set password_encryption to scram-sha-256 in server parameters, then reset passwords.",
    },
    "pg.backup.archive_mode": {
        Platform.SELF_HOSTED: "Enable archive_mode and set archive_command to ship WAL to durable storage.",
        Platform.RDS: "RDS manages WAL archiving. Confirm the automated backup retention period is above zero.",
        Platform.AURORA: "Aurora manages storage-level backups. Confirm the backup retention period is above zero.",
        Platform.CLOUD_SQL: "Enable automated backups and point-in-time recovery on the instance.",
        Platform.AZURE: "Confirm backup retention is configured; Azure manages WAL archiving.",
    },
    "pg.backup.wal_level": {
        Platform.SELF_HOSTED: "Set wal_level = replica so base backups can be replayed.",
        Platform.RDS: "RDS sets wal_level automatically when backups are enabled. Check backup retention.",
        Platform.AURORA: "Aurora does not use conventional WAL archiving; storage handles durability.",
        Platform.CLOUD_SQL: "Enable point-in-time recovery, which sets wal_level for you.",
        Platform.AZURE: "Azure manages wal_level; confirm backups are enabled.",
    },
    "pg.observability.pg_stat_statements": {
        Platform.SELF_HOSTED: "Add pg_stat_statements to shared_preload_libraries, restart, then CREATE EXTENSION.",
        Platform.RDS: "Add pg_stat_statements to shared_preload_libraries in the parameter group, reboot, then CREATE EXTENSION.",
        Platform.AURORA: "Add pg_stat_statements to shared_preload_libraries in the cluster parameter group, reboot, then CREATE EXTENSION.",
        Platform.CLOUD_SQL: "Set the cloudsql.enable_pg_stat_statements flag, then CREATE EXTENSION.",
        Platform.AZURE: "Add pg_stat_statements to shared_preload_libraries in server parameters, then CREATE EXTENSION.",
    },
    "pg.observability.slow_queries": {
        Platform.SELF_HOSTED: "Set log_min_duration_statement = 1000 in postgresql.conf.",
        Platform.RDS: "Set log_min_duration_statement = 1000 in the parameter group and enable log exports to CloudWatch.",
        Platform.AURORA: "Set log_min_duration_statement = 1000 in the cluster parameter group.",
        Platform.CLOUD_SQL: "Set the log_min_duration_statement database flag to 1000.",
        Platform.AZURE: "Set log_min_duration_statement to 1000 in server parameters.",
    },
    "pg.ha.replication": {
        Platform.SELF_HOSTED: "Configure at least one streaming replica so a failover target exists.",
        Platform.RDS: "Enable Multi-AZ, or add a read replica.",
        Platform.AURORA: "Add at least one Aurora replica in a second availability zone.",
        Platform.CLOUD_SQL: "Enable high availability, which creates a standby in another zone.",
        Platform.AZURE: "Enable zone-redundant high availability on the server.",
    },
    "pg.capacity.connections": {
        Platform.SELF_HOSTED: "Put PgBouncer in front of the database or raise max_connections.",
        Platform.RDS: "Use RDS Proxy to pool connections, or move to a larger instance class.",
        Platform.AURORA: "Use RDS Proxy, or scale the writer instance class.",
        Platform.CLOUD_SQL: "Use the Cloud SQL Auth Proxy with pooling, or raise the max_connections flag.",
        Platform.AZURE: "Enable the built-in PgBouncer connection pooler.",
    },
    "pg.security.trust_auth": {
        Platform.SELF_HOSTED: "Replace trust with scram-sha-256 in pg_hba.conf and reload.",
        Platform.RDS: "RDS does not expose pg_hba.conf; control access with security groups and IAM authentication.",
        Platform.AURORA: "Aurora does not expose pg_hba.conf; control access with security groups and IAM authentication.",
        Platform.CLOUD_SQL: "Cloud SQL does not expose pg_hba.conf; use authorised networks and IAM database authentication.",
        Platform.AZURE: "Azure does not expose pg_hba.conf; use firewall rules and Entra ID authentication.",
    },
}


def remediation_for(check_id: str, platform: Platform, fallback: str = "") -> str:
    """The remediation for a check on a specific platform."""
    options = REMEDIATION.get(check_id)
    if not options:
        return fallback
    return options.get(platform) or options.get(Platform.SELF_HOSTED) or fallback


#: Checks that cannot be acted on at all for a given platform, with the reason.
#: These are reported as informational rather than counted as failures, because
#: penalising someone for a setting their provider does not expose is noise.
NOT_APPLICABLE: dict[str, dict[Platform, str]] = {
    "pg.security.trust_auth": {
        Platform.RDS: "RDS does not expose pg_hba.conf",
        Platform.AURORA: "Aurora does not expose pg_hba.conf",
        Platform.CLOUD_SQL: "Cloud SQL does not expose pg_hba.conf",
        Platform.AZURE: "Azure Database does not expose pg_hba.conf",
    },
    "pg.backup.archive_mode": {
        Platform.AURORA: "Aurora uses storage-level backups rather than WAL archiving",
    },
    "pg.backup.wal_level": {
        Platform.AURORA: "Aurora does not use conventional WAL archiving",
    },
}


def not_applicable_reason(check_id: str, platform: Platform) -> str | None:
    """Why a check does not apply on this platform, or None when it does."""
    return NOT_APPLICABLE.get(check_id, {}).get(platform)
