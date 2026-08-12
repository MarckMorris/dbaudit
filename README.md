# dbaudit

**Configuration auditing for PostgreSQL that works on managed databases, from a connection string alone.**

[![CI](https://github.com/MarckMorris/dbaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/MarckMorris/dbaudit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Every open-source PostgreSQL hardening tool reads \`postgresql.conf\` and \`pg_hba.conf\` off the server's
filesystem. That assumption breaks on RDS, Aurora, Cloud SQL and Azure Database — which is where most
production PostgreSQL now runs. You cannot SSH into a managed instance, so the tooling that would tell
you whether it is configured correctly cannot run at all.

dbaudit connects the way an application does: a connection string and nothing else. It works out which
platform it landed on, runs its checks through SQL, and reports each finding with remediation that is
actually possible on that platform.

## What it looks like

```
$ dbaudit "postgres://app:***@orders.abc123.us-east-1.rds.amazonaws.com:5432/orders" --fail-on high

  dbaudit  postgres  postgres://app:***@orders.abc123.us-east-1.rds.amazonaws.com:5432/orders
  platform  aws-rds

  backups
    PASS   WAL level supports point-in-time recovery
    PASS   WAL archiving is enabled

  capacity
    PASS   Connection pool has headroom

  high-availability
    PASS   At least one replica is streaming

  observability
    PASS   Query statistics are collected
    FAIL   Slow queries are logged  [low]
           log_min_duration_statement is -1
           fix: Set log_min_duration_statement = 1000 in the parameter group and enable log exports to CloudWatch.
           ref: CIS PostgreSQL: logging of statement duration

  security
    FAIL   Connections are encrypted with TLS  [critical]
           ssl is off, traffic is in cleartext
           fix: Set rds.force_ssl = 1 in the DB parameter group, then reboot the instance.
           ref: CIS PostgreSQL: connection settings, TLS in transit
    SKIP   No host rule uses trust authentication
           RDS does not expose pg_hba.conf
    PASS   Passwords are hashed with SCRAM-SHA-256
    FAIL   Superuser accounts are limited  [high]
           4 superuser(s): postgres, app, etl, bi
           fix: Grant narrower roles instead of superuser to application accounts.
           ref: CIS PostgreSQL: least privilege for roles

  score 37/100
  7 passed, 3 failed, 1 not applicable on this platform

$ echo $?
1
```

Three things there do not appear in other tools:

**\`platform  aws-rds\`** — detected from the server, not configured by hand.

**\`fix: Set rds.force_ssl = 1 in the DB parameter group\`** — not "edit postgresql.conf", which is
impossible on RDS. Remediation that cannot be followed is the same as no remediation.

**\`SKIP — RDS does not expose pg_hba.conf\`** — a control the provider does not expose is reported as
not applicable rather than counted as a failure. Scoring a managed database against controls it cannot
implement produces a number nobody acts on.

## Install

```bash
pip install "dbaudit[postgres] @ git+https://github.com/MarckMorris/dbaudit"
```

From a clone:

```bash
git clone https://github.com/MarckMorris/dbaudit.git
cd dbaudit
pip install -e ".[postgres]"
```

## Use

```bash
# Human-readable report
dbaudit "postgres://user:pass@host:5432/db"

# Gate a pipeline: exit 1 when anything reaches high or critical
dbaudit "postgres://user:pass@host:5432/db" --fail-on high

# Machine-readable
dbaudit "postgres://user:pass@host:5432/db" --format json

# GitHub Security tab
dbaudit "postgres://user:pass@host:5432/db" --sarif dbaudit.sarif

# Override detection when a proxy or pooler hides the real host
dbaudit "postgres://user:pass@host:5432/db" --platform gcp-cloud-sql
```

The password is stripped from every form of output, so a report can be pasted into a ticket.

### Adopting it on a database that already exists

The first run on a live database is a wall of red, and the usual outcome is that the job gets disabled.
A baseline fixes that: freeze today's findings, then fail only on regressions.

```bash
dbaudit "postgres://..." --init-baseline dbaudit-baseline.json
git add dbaudit-baseline.json

# From now on, only new problems break the build
dbaudit "postgres://..." --baseline dbaudit-baseline.json --fail-on high
```

Waived findings are not hidden. They stay in the JSON and, in SARIF, are emitted with a
\`suppressions\` entry, so the debt remains visible and auditable instead of disappearing.

### In GitHub Actions

```yaml
- name: Audit the production database
  run: |
    pip install "dbaudit[postgres] @ git+https://github.com/MarckMorris/dbaudit"
    dbaudit "${{ secrets.DATABASE_URL }}" \
      --baseline dbaudit-baseline.json \
      --fail-on high \
      --sarif dbaudit.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: dbaudit.sarif
    category: dbaudit
```

This repository's own CI does exactly that against a live \`postgres:16\` container on every push.

## Checks

Ten checks today, all read-only. Nothing is written to the database and no query blocks.

| Check | Severity | Category | Benchmark topic |
| --- | --- | --- | --- |
| Connections are encrypted with TLS | critical | security | Connection settings, TLS in transit |
| No host rule uses trust authentication | critical | security | Host-based authentication methods |
| Passwords are hashed with SCRAM-SHA-256 | high | security | Password storage and hashing |
| Superuser accounts are limited | high | security | Least privilege for roles |
| WAL level supports point-in-time recovery | high | backups | Write-ahead log configuration |
| WAL archiving is enabled | high | backups | WAL archiving and recovery |
| Connection pool has headroom | medium | capacity | Connection limits |
| Query statistics are collected | medium | observability | Query statistics collection |
| At least one replica is streaming | medium | high-availability | Replication configuration |
| Slow queries are logged | low | observability | Logging of statement duration |

Checks map to CIS PostgreSQL Benchmark topics by name rather than by control number. The benchmark is
distributed under a licence that does not permit republishing its control identifiers, and a wrong
number is worse than none, so the reference names the area and leaves the lookup to the reader.

The score starts at 100 and subtracts a penalty per failure — 40 critical, 20 high, 10 medium, 3 low.
It is a triage signal, not a compliance certificate.

## Platform support

| Platform | Detected by | Remediation | pg_hba.conf checks |
| --- | --- | --- | --- |
| Amazon Aurora | \`aurora_version()\` | Cluster parameter group | Not applicable |
| Amazon RDS | \`rds.*\` in \`pg_settings\` | DB parameter group | Not applicable |
| Google Cloud SQL | \`cloudsql.*\` in \`pg_settings\` | Database flags | Not applicable |
| Azure Database | \`azure.*\` in \`pg_settings\` | Server parameters | Not applicable |
| Self-hosted | Fallback | \`postgresql.conf\` | Checked |

Aurora is probed before RDS, because an Aurora cluster also exposes the \`rds\` namespace and the more
specific signal has to win. A failed probe rolls the transaction back before the next one runs, so a
detection attempt never poisons the session for the checks that follow.

## Design notes

**Read-only, always.** Every check is a \`SELECT\` or a \`SHOW\`. The tool is safe to point at production,
which is the only place the answers are interesting.

**A broken check never aborts the audit.** If a view is missing or a role lacks permission, that check is
recorded as not applicable with the error attached, and the remaining nine still report.

**Platform logic lives in one module.** Checks describe what good looks like; \`platform.py\` owns what to
do about it where. Adding a provider means adding entries to two dictionaries, not editing ten checks.

**Adding a check is a class.** Subclass \`Check\`, declare \`id\`, \`title\`, \`severity\`, \`category\` and
\`cis\`, implement \`run\`, decorate with \`@register\`. The registry picks it up by engine.

## Scope

dbaudit checks **configuration**, once, on demand. It is deliberately not a monitoring agent, not a query
analyser, and not an activity auditor — pgAudit and your APM already do those, and they run continuously.
This runs in a pipeline in under a second and answers one question: is this database configured the way a
production database should be, given where it is hosted?

## Roadmap

- MySQL and Redis connectors, using the same registry
- Per-check waivers with expiry dates, so a baseline entry cannot live forever
- Terraform drift comparison: audit what is deployed against what the module declared

## Development

```bash
pip install -e ".[dev]"
pytest --cov=dbaudit
```

114 tests, 97% line coverage. The suite runs without a database: \`tests/fakes.py\` provides an in-memory
PostgreSQL whose query responses are declared per scenario, including which statements each managed
platform refuses to answer. CI additionally audits a real \`postgres:16\` container on Python 3.10, 3.11
and 3.12.

## License

MIT — see [LICENSE](LICENSE).

## Author

**Marcos Morris** — Cloud Infrastructure Engineer, Bentonville, AR

[LinkedIn](https://www.linkedin.com/in/marck-morris/) · [Portfolio](https://marckmorris.github.io/) · marck.morris.pro@gmail.com
