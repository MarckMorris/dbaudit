# dbaudit

Check whether a database is ready for production, and fail your pipeline when it is not.

[![CI](https://github.com/MarckMorris/dbaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/MarckMorris/dbaudit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Everyone knows the checklist: TLS on, WAL archiving on, no `trust` rules in `pg_hba.conf`, a replica somewhere, slow queries logged. Nobody runs it, because running it means twenty `SHOW` statements and remembering what good looks like.

`dbaudit` runs it for you and gives you a score.

## Try it in thirty seconds

```bash
pip install "dbaudit[postgres] @ git+https://github.com/MarckMorris/dbaudit"
docker run -d --name pg -e POSTGRES_PASSWORD=secret -p 5432:5432 postgres:16
dbaudit postgres://postgres:secret@localhost:5432/postgres
```

A default Postgres container scores badly, which is the point:

```
  dbaudit  postgres  postgres://postgres:***@localhost:5432/postgres

  backups
    FAIL  WAL archiving is enabled  [high]
          archive_mode is off
          fix: Enable archive_mode and set archive_command to ship WAL offsite.
    PASS  WAL level supports point-in-time recovery

  capacity
    PASS  Connection pool has headroom

  high-availability
    FAIL  At least one replica is streaming  [medium]
          0 replica(s) connected
          fix: Configure at least one streaming replica for failover.

  observability
    FAIL  Query statistics are collected  [medium]
          pg_stat_statements missing
          fix: CREATE EXTENSION pg_stat_statements and add it to shared_preload_libraries.
    FAIL  Slow queries are logged  [low]
          log_min_duration_statement is -1
          fix: Set log_min_duration_statement to 1000 to capture queries over a second.

  security
    FAIL  Connections are encrypted with TLS  [critical]
          ssl is off, traffic is in cleartext
          fix: Set ssl = on in postgresql.conf and provide a certificate.
    PASS  Passwords are hashed with SCRAM-SHA-256
    PASS  Superuser accounts are limited
    PASS  No host rule uses trust authentication

  score 17/100
  4 passed, 6 failed
```

## Use it in CI

The reason this exists. Exit code 1 when anything at or above the threshold fails:

```yaml
- name: Audit the database
  run: dbaudit "$DATABASE_URL" --fail-on high
```

```bash
dbaudit "$DATABASE_URL" --format json | jq .score
```

## Scoring

Every audit starts at 100 and deducts per failed check, weighted by severity.

| Severity | Deduction |
| --- | --- |
| critical | 40 |
| high | 20 |
| medium | 10 |
| low | 3 |
| info | 0 |

The score is a summary, not the point. The failures and their fixes are the point.

## Checks

| Category | Check | Severity |
| --- | --- | --- |
| security | Connections are encrypted with TLS | critical |
| security | No host rule uses trust authentication | critical |
| security | Passwords are hashed with SCRAM-SHA-256 | high |
| security | Superuser accounts are limited | high |
| backups | WAL level supports point-in-time recovery | high |
| backups | WAL archiving is enabled | high |
| capacity | Connection pool has headroom | medium |
| observability | Query statistics are collected | medium |
| observability | Slow queries are logged | low |
| high-availability | At least one replica is streaming | medium |

## Writing a check

A check is one class. Register it and it runs.

```python
from dbaudit.core import Check, Finding, Severity, register


@register
class StatementTimeout(Check):
    id = "pg.capacity.statement_timeout"
    title = "Statements have a timeout"
    severity = Severity.MEDIUM
    category = "capacity"
    engines = ("postgres",)

    def run(self, conn) -> Finding:
        with conn.cursor() as cur:
            cur.execute("SHOW statement_timeout")
            value = cur.fetchone()[0]
        return self._finding(
            passed=value not in ("0", "0ms"),
            detail=f"statement_timeout is {value}",
            remediation="Set statement_timeout so a runaway query cannot pin a connection.",
        )
```

A check that raises is reported and skipped. One broken check never aborts an audit.

## Roadmap

- MySQL and Redis connectors
- HTML report output
- Baseline files, so a known deviation can be accepted and stops failing the build
- Publish to PyPI

Contributions welcome, particularly new checks. Open an issue with the `SHOW` or query you would run and what good looks like.

## Development

```bash
git clone https://github.com/MarckMorris/dbaudit.git
cd dbaudit
pip install -e ".[dev]"
pytest
```

CI runs the test suite on Python 3.10, 3.11 and 3.12, then audits a live PostgreSQL 16 container to prove the tool still connects and reports.

## License

MIT, see [LICENSE](LICENSE).

## Author

**Marcos Morris**, Cloud Infrastructure Engineer, Bentonville, AR

[LinkedIn](https://www.linkedin.com/in/marck-morris/) · [Portfolio](https://marckmorris.github.io/)
