"""An in-memory PostgreSQL stand-in.

The checks only ever read configuration, so a dictionary of query prefixes to
results reproduces a real server faithfully enough to test the whole pipeline
without a container. Platform detection is driven by which queries are allowed
to succeed, which is exactly how it behaves against a real managed instance.
"""

from __future__ import annotations

from typing import Any


class FakeCursor:
    def __init__(self, conn: "FakePostgres") -> None:
        self._conn = conn
        self._result: list[tuple] = []

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def execute(self, sql: str, params: tuple | None = None) -> None:
        self._conn.executed.append(sql)
        self._result = self._conn.resolve(sql, params)

    def fetchone(self) -> tuple | None:
        return self._result[0] if self._result else None

    def fetchall(self) -> list[tuple]:
        return list(self._result)

    def close(self) -> None:
        pass


class UnsupportedQuery(Exception):
    """Raised for statements the simulated platform does not implement."""


class FakePostgres:
    """A connection whose answers are declared up front."""

    def __init__(
        self,
        settings: dict[str, str] | None = None,
        rows: dict[str, list[tuple]] | None = None,
        namespaces: tuple[str, ...] = (),
        aurora: bool = False,
        version: str = "PostgreSQL 16.2 on x86_64-pc-linux-gnu",
    ) -> None:
        self.settings = {
            "ssl": "on",
            "password_encryption": "scram-sha-256",
            "wal_level": "replica",
            "archive_mode": "on",
            "max_connections": "100",
            "log_min_duration_statement": "1000",
            **(settings or {}),
        }
        self.rows = {
            "SELECT rolname FROM pg_roles WHERE rolsuper": [("postgres",)],
            "SELECT type, database": [],
            "SELECT count(*) FROM pg_stat_activity": [(10,)],
            "SELECT count(*) FROM pg_extension": [(1,)],
            "SELECT count(*) FROM pg_stat_replication": [(1,)],
            **(rows or {}),
        }
        self.namespaces = namespaces
        self.aurora = aurora
        self.version = version
        self.executed: list[str] = []
        self.closed = False
        self.rollbacks = 0

    # -- connection protocol -------------------------------------------------

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True

    # -- query routing -------------------------------------------------------

    def resolve(self, sql: str, params: tuple | None) -> list[tuple]:
        stripped = sql.strip()

        if stripped.startswith("SHOW "):
            name = stripped[5:].strip().rstrip(";")
            if name not in self.settings:
                raise UnsupportedQuery(f'unrecognized configuration parameter "{name}"')
            return [(self.settings[name],)]

        if stripped.startswith("SELECT aurora_version()"):
            if not self.aurora:
                raise UnsupportedQuery("function aurora_version() does not exist")
            return [("3.04.0",)]

        if stripped.startswith("SELECT version()"):
            return [(self.version,)]

        if "FROM pg_settings WHERE name LIKE" in stripped:
            prefix = (params or ("",))[0].split(".")[0]
            return [(1,)] if prefix in self.namespaces else []

        for key, value in self.rows.items():
            if stripped.startswith(key):
                return list(value)

        raise UnsupportedQuery(f"unhandled statement: {stripped[:60]}")


def healthy() -> FakePostgres:
    """A self-hosted server that passes every check."""
    return FakePostgres()


def neglected() -> FakePostgres:
    """A self-hosted server that fails every check it can fail."""
    return FakePostgres(
        settings={
            "ssl": "off",
            "password_encryption": "md5",
            "wal_level": "minimal",
            "archive_mode": "off",
            "max_connections": "100",
            "log_min_duration_statement": "-1",
        },
        rows={
            "SELECT rolname FROM pg_roles WHERE rolsuper": [
                ("postgres",),
                ("app",),
                ("etl",),
                ("analytics",),
            ],
            "SELECT type, database": [("host", "all", "all", "0.0.0.0/0", "trust")],
            "SELECT count(*) FROM pg_stat_activity": [(95,)],
            "SELECT count(*) FROM pg_extension": [(0,)],
            "SELECT count(*) FROM pg_stat_replication": [(0,)],
        },
    )


def rds() -> FakePostgres:
    """An RDS instance: rds namespace present, no pg_hba_file_rules view."""
    conn = FakePostgres(namespaces=("rds",))
    conn.rows["SELECT type, database"] = []
    return conn


def aurora() -> FakePostgres:
    """Aurora exposes both aurora_version() and the rds namespace."""
    return FakePostgres(namespaces=("rds",), aurora=True)


def cloud_sql() -> FakePostgres:
    return FakePostgres(namespaces=("cloudsql",))


def azure() -> FakePostgres:
    return FakePostgres(namespaces=("azure",))


def trust_rule_only() -> FakePostgres:
    """Healthy apart from one passwordless host rule in pg_hba.conf."""
    return FakePostgres(
        rows={"SELECT type, database": [("host", "all", "all", "0.0.0.0/0", "trust")]}
    )
