# Sentriq

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)


A lightweight, self-hosted security operations alert tracker built with FastAPI. Designed for SOC teams that need role-based alert management, an auditable trail, and no vendor lock-in.

## Quick start (local Python demo)

Create a virtual environment and install the app:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Set `APP_SECRET_KEY` in `.env` to a random value of at least 32 characters, then start the app bound to this computer:

```bash
.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8080
```

On first startup, database migrations run automatically. In another terminal, create the first administrator:

```bash
.venv/bin/python -m sentriq.manage create-admin admin_l3
```

The command prompts you to choose a password. Open `http://127.0.0.1:8080` and sign in as `admin_l3`. A fresh install has no default users or demo tickets; create L1/L2 users from the Users page, then optionally seed synthetic review tickets:

```bash
.venv/bin/python -m sentriq.manage seed-demo
```

The seed command is disabled when `APP_ENV=production`. New users have **Require password change at next login** enabled by default; the admin can turn it off in the create-user form. Any signed-in user can later change their own password from **Change password** in the sidebar. Stop the server with `Ctrl+C`.

### Local review accounts

The current local review database has these demo accounts. They are not automatically created on fresh installs.

| Username | Role | Password |
|---|---|---|
| `l1` | L1 Analyst | `SocReview2026!` |
| `l2` | L2 Analyst | `SocReview2026!` |
| `admin_l3` | L3 Admin | `SocReview2026!` |

Change the shared demo password after signing in. Do not use it outside this localhost demo.

### One command, Postgres included

`scripts/demo_local.py` starts a local Postgres, migrates it, copies the demo
tickets in, takes a snapshot and starts the app with four workers:

```bash
pip install -r requirements-dev.txt   # adds pgserver, a bundled Postgres
.venv/bin/python scripts/demo_local.py start
.venv/bin/python scripts/demo_local.py status
.venv/bin/python scripts/demo_local.py stop
```

It prints the URL and the review accounts when it is ready, and everything it
creates lives in `~/.local/share/sentriq-demo` (override with
`DEMO_STATE_DIR`), so stopping and starting keeps the tickets. The Postgres
there is a development bundle, not a server to run in production; it is only
there so the demo exercises the same SQL as production. Postgres refuses to
initialise a cluster on a Windows drvfs mount such as `/mnt/d` under WSL, which
is why the state directory is outside the repository.

## Quick start (Docker)

```bash
git clone https://github.com/ethanx01-H/Sentriq.git
cd Sentriq
cp .env.example .env
# Edit .env before the first start: APP_SECRET_KEY (openssl rand -hex 32),
# ALLOWED_HOSTS (your domain), POSTGRES_PASSWORD, and DATABASE_URL to match it.
docker compose up --build
```

The compose file now describes a **production deployment**: it refuses to start
without a real signing key, without `ALLOWED_HOSTS`, and with non-Secure cookies.
That is deliberate — the defaults you get by doing nothing are the safe ones.

The stack also starts a `retention` service: once a day it archives and removes
closed tickets older than `RETENTION_DAYS` (730 by default). If you are not ready
to enforce that window, `docker compose stop retention` until you are. See
[Data storage and retention](#data-storage-and-retention).

To try it on this machine first, over plain HTTP, use the review values instead:

```bash
# .env, for a localhost review only
APP_ENV=review
COOKIE_SECURE=0
ALLOWED_HOSTS=localhost,127.0.0.1
PUBLIC_BASE_URL=http://localhost:8080
```

Then `docker compose up --build` listens on `http://127.0.0.1:8080` and creates no
default users or sample incidents. Create the first administrator in a second
terminal:

```bash
docker compose exec sentriq python -m sentriq.manage create-admin admin_l3
```

The command prompts for the password twice. Create L1/L2 users from the administrator page and optionally add five synthetic review tickets with `docker compose exec sentriq python -m sentriq.manage seed-demo`. The seed command refuses to run in production. New users are required to change their password by default; the admin can disable this when creating the account. Each user can change their own password from the **Change password** link in the sidebar.

### Deploying on a domain

The app is designed to sit behind a reverse proxy on a name, not on an IP. In a
bank network an IP address is neither stable nor verifiable, and a bare IP cannot
carry a certificate a browser will trust.

1. **DNS**: point a name at the host, e.g. `sentriq.example.com`.
2. **Certificate**: `certbot --nginx -d sentriq.example.com`, or install the bank's
   internal CA certificate.
3. **Proxy**: start from [nginx.conf](nginx.conf). It redirects HTTP to HTTPS,
   forwards `Host`, `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Proto`, hides
   the origin's `Server` header, and rate-limits `/login/`.
4. **App environment**, in `.env`:

   ```
   APP_ENV=production
   COOKIE_SECURE=1
   ALLOWED_HOSTS=sentriq.example.com
   PUBLIC_BASE_URL=https://sentriq.example.com
   ```

5. **Keep the app off the network.** Compose binds it to `127.0.0.1:8080`, so only
   the proxy on that host can reach it. Do not publish 8080 on the LAN, and do not
   put the app port in a load-balancer pool that bypasses the proxy.

What the domain settings buy you:

- `ALLOWED_HOSTS` is enforced by `TrustedHostMiddleware`. A request arriving with
  any other `Host` header is refused with 400 before it reaches a route, so a
  lookalike name cannot be used to poison links or the audit trail.
- The session, CSRF and flash cookies are named `__Host-…` once `COOKIE_SECURE=1`.
  That prefix requires `Secure`, `Path=/` and no `Domain` attribute, and it stops
  a sibling subdomain (or a compromised host on the same parent domain) from
  overwriting this app's cookies.
- `PUBLIC_BASE_URL` is what notification e-mails and Teams cards link to, so they
  point at the name rather than at whatever the app guessed.
- `TRUSTED_PROXIES` must be the address the proxy connects from. Anything on that
  list may claim any client address, which is how per-IP limits and the audit
  source IP are keyed — do not list a range wider than the proxy itself.

`/metrics` behind a proxy is never a loopback request, so set `METRICS_TOKEN` and
scrape with `Authorization: Bearer <token>`.

### Where the data lives, and how to update safely

The compose file bind-mounts host directories instead of using Docker volumes:

- `./data` → `/app/data` — uploaded `evidence/`
- `./pgdata` → the Postgres data directory (override with `SENTRIQ_PGDATA_DIR`)
- `./backups` → `/app/backups` — `pg_dump` snapshots (override with `SENTRIQ_BACKUP_DIR`)

Because those are host directories, `docker compose down -v`, `docker volume rm`,
`docker volume prune` and `docker system prune --volumes` cannot delete the alerts or the
evidence. Those commands only remove Docker-managed volumes, and this stack no longer has
any.

Every container start writes a snapshot before the app serves traffic (newest 20 kept, at
most one every five minutes). `scripts/backup-postgres.sh` runs `pg_dump --format=custom`,
checks the result with `pg_restore --list`, and only then renames it into place, so a failed
dump never looks like a usable snapshot. To restore one into a fresh database:

```bash
docker compose exec -T postgres createdb -U sentriq sentriq_restore
pg_restore --no-owner --no-privileges -d "postgresql://sentriq:***@localhost:5432/sentriq_restore" backups/sentriq-pg-YYYYmmdd-HHMMSS.dump
```

For a nightly snapshot while the stack is running, use the host scheduler. Linux or WSL
(`crontab -e`), 02:00 daily, keep 30, no minimum interval:

```cron
0 2 * * * cd /path/to/Sentriq && docker compose exec -T sentriq sh scripts/backup-postgres.sh /app/backups 30 0 >> /var/log/sentriq-backup.log 2>&1
```

On Windows, create a daily Task Scheduler job that runs:

```powershell
powershell -Command "cd D:\IT\automation_script\Sentriq; docker compose exec -T sentriq sh scripts/backup-postgres.sh /app/backups 30 0"
```

Test the restore path, not just the backup: restore a snapshot into a scratch database at
least once a quarter and compare row counts. A backup nobody has restored is a guess.

Updating is then just a rebuild — but see [Upgrading and patching a CVE](#upgrading-and-patching-a-cve),
which recommends pulling a published image instead of building on the host that holds the
database.

```bash
docker compose down
docker compose up -d --build
```

Moving data out of the old named volume, only if you ran an earlier compose file:

```powershell
docker compose down
docker run --rm -v sentriq_sentriq_data:/from -v "${PWD}\data:/to" alpine sh -c "cp -a /from/. /to/"
docker compose up -d --build
```

```bash
# same thing from WSL or Linux
docker run --rm -v sentriq_sentriq_data:/from -v "$PWD/data:/to" alpine sh -c "cp -a /from/. /to/"
```

Confirm the tickets are there, then remove the old volume with `docker volume rm
sentriq_sentriq_data`. On a Linux host the container runs as uid 1000, so make the
directory writable: `chown -R 1000:1000 data backups`.

### Data storage and retention

Alert, account, event, and audit records live in Postgres; uploaded evidence lives in `data/evidence/`. In Docker the evidence directory is bind-mounted from `./data` and the database files sit in `./pgdata` (see above). Alert deletion is disabled; tickets leave the database only through the retention job below, which archives them first. Losing the host can still destroy the data — the `pg_dump` snapshots in `./backups` are the recovery point, and a database host your DBA backs up is better still.

**Postgres is required.** `DATABASE_URL` has no default: the app refuses to start
without it, and refuses a `sqlite://` URL with an explanation. Both `postgres://`
and `postgresql://` are rewritten to `psycopg://` internally, so a URL copied from
a DBA works unchanged:

```bash
DATABASE_URL=postgresql://sentriq:***@db:5432/sentriq
```

**Shared limiter counters.** Rate limits and login lockouts live in process memory by default, which is correct for one worker and wrong for several: each worker counts only its own traffic, so N workers allow N times the limit, and a lockout applies only to the worker that saw the failed attempt. Set `REDIS_URL` to share both counters across workers. Without Redis, either keep `WEB_CONCURRENCY=1` or accept the multiplied limit.

**Retention (730 days, daily).** The `retention` compose service runs one pass at startup and then every 24 hours. It archives and removes closed tickets whose closure date is more than 730 days old; the web app does not depend on it. Pause it with `docker compose stop retention`.

A pass processes the backlog in batches (`RETENTION_BATCH_SIZE`, default 500), one transaction per batch, and holds a Postgres advisory lock so a cron job and the service cannot run at the same time. For each batch it writes a gzipped JSON Lines archive (ticket, timeline, evidence metadata with SHA-256, SLA breaches) into `data/archive/`, reads it back to prove it opens and holds the expected number of tickets, commits the row deletions, and only then removes the evidence files. A failed commit leaves both rows and files in place, so the next pass can retry; an unlink failure is recorded in the audit trail and logged.

Only *closed* tickets are eligible, and the clock starts at closure — a ticket opened three years ago and closed last week keeps its full window. For a dry run or a one-off:

```bash
python -m sentriq.manage retention --days 730           # dry run, changes nothing
python -m sentriq.manage retention --days 730 --apply   # archive, then remove
python -m sentriq.manage retention-daily                # one daily pass, batched
```

If you do not run the compose service, schedule the same pass from cron:

```cron
# Docker
0 3 * * * cd /path/to/Sentriq && docker compose exec -T sentriq python -m sentriq.manage retention-daily >> /var/log/sentriq-retention.log 2>&1

# Bare Python (no Docker)
0 3 * * * cd /path/to/Sentriq && .venv/bin/python -m sentriq.manage retention-daily >> /var/log/sentriq-retention.log 2>&1
```

Retention removes the live ticket, timeline, evidence files and SLA breach rows. It does **not** delete the append-only audit trail or the archives in `data/archive/` — those are the record of what was removed. If your policy also expires the archives, prune `data/archive/` on its own schedule and keep the audit export off-host.

**Immutable audit export.** The audit trail is hash-chained on export: each record carries the hash of the one before it, so a deleted or edited row breaks the chain and verification names the record.

```bash
python -m sentriq.manage audit-export                 # all records
python -m sentriq.manage audit-export --from 2026-01-01 --to 2026-04-01
python -m sentriq.manage audit-verify data/audit-exports/audit-20260401T000000Z.jsonl
```

Exports are written read-only with a manifest holding the head hash. Copy the head hash somewhere off this host (a change ticket, an external log): that anchor is what proves later that the export was not rewritten. Read-only is not immutable — for the bank's requirement, land the export in object-lock or WORM storage.

**The trail is append-only.** A database trigger refuses `UPDATE`, `DELETE` and
`TRUNCATE` on `fastapi_audit_logs` for every role, including the one the
application connects as, so a bug or a careless psql session cannot rewrite
history. Check what is actually in place:

```bash
python -m sentriq.manage audit-guard            # report only
python -m sentriq.manage audit-guard --install  # create the trigger if missing
```

The report also says when the application's own role owns the table, because a
trigger can be disabled by its owner. The durable form of this control is
ownership plus privileges, and both are one command for a DBA:

```sql
ALTER TABLE fastapi_audit_logs OWNER TO <dba_role>;
```
```bash
python -m sentriq.manage audit-guard --app-role <app_role>   # run as the owner
```

That leaves the application able to `INSERT` and `SELECT` only, which is what an
append-only trail means. Neither layer survives a superuser, so the application
must not connect as one — the report tells you if it does.

**Scheduled off-host export.** `scripts/audit-export-offhost.sh` exports the
window, copies the file and manifest to `AUDIT_OFFHOST_DIR`, verifies the copy
from the destination, and writes a one-line `.head` anchor beside it. It exits
non-zero when anything fails, so cron can alert on it.

```cron
15 1 * * * cd /path/to/Sentriq && docker compose exec -T sentriq sh scripts/audit-export-offhost.sh 1 >> /var/log/sentriq-audit-export.log 2>&1
```

`AUDIT_OFFHOST_DIR` must be somewhere this host cannot rewrite — a mounted share
with append-only permissions, an SFTP drop, or object storage with a retention
lock. A copy on the same disk is not an anchor.

**Monitoring.** `/healthz` reports database health and the age of the newest snapshot, and answers `degraded` when the snapshot is older than `BACKUP_MAX_AGE_HOURS` (default 36) without failing the check — restarting the app would not fix a dead backup job. `/metrics` serves Prometheus text: request counts and latency, tickets by status and severity, unassigned backlog, SLA breaches, evidence volume, audit row count, backup age and staleness, and which limiter store is in use. Without `METRICS_TOKEN` it answers on loopback only; with a token it requires `Authorization: Bearer <token>`.

```bash
python -m sentriq.manage backup-status   # newest snapshot and its age
python -m sentriq.manage sla-sweep       # record newly missed SLAs
```

Retention runs as the `retention` compose service; schedule the audit export and the SLA sweep from cron (or Windows Task Scheduler), and alert on `soc_backup_stale`, `soc_backup_age_seconds` and `soc_sla_breaches{state="open"}`. Set `TRUSTED_PROXIES` to the addresses of your reverse proxy so lockouts, rate limits, and audit rows key on the real client address rather than the proxy.

## Upgrading and patching a CVE

Three ways to update this deployment, best first. The difference matters most on the day a
CVE lands and the change window is short.

### 1. Pull a published image (recommended)

CI builds and scans; production only pulls. Nothing is compiled on the host that holds the
database, so a patch does not depend on PyPI or Docker Hub being reachable from it.

```bash
# .env on the host, once
SENTRIQ_IMAGE=registry.example.com/sentriq:1.4.3
```

```bash
docker compose pull
docker compose up -d --no-build    # entrypoint: snapshot -> alembic upgrade head -> gunicorn
docker compose logs -f sentriq     # watch the migration, then Ctrl-C
curl -fsS http://127.0.0.1:8080/healthz
```

Rolling back is the same two commands with the previous tag in `SENTRIQ_IMAGE`. The old image
is still on the host, so a rollback takes seconds and does not need a network.

Publishing is triggered by a tag:

```bash
git tag -a v1.4.3 -m "Sentriq 1.4.3"
git push origin v1.4.3
```

`.github/workflows/release.yml` builds it, refuses to publish if Trivy finds HIGH or CRITICAL,
pushes it, and attaches a CycloneDX SBOM to the run. Point it at your registry with the
repository variable `SENTRIQ_IMAGE` (defaults to `ghcr.io/<owner>/<repo>`) and, for anything
other than ghcr.io, the secrets `REGISTRY_USERNAME` / `REGISTRY_PASSWORD`.

### 2. Carry an image across an air gap

When the production network cannot reach a registry at all:

```bash
./scripts/save-image.sh sentriq:1.4.3 /media/transfer    # on a host that can build or pull

# on the production host
sha256sum -c sentriq_1.4.3.tar.gz.sha256
gunzip -c sentriq_1.4.3.tar.gz | docker load
SENTRIQ_IMAGE=sentriq:1.4.3 docker compose up -d --no-build
```

The checksum is not decoration: an image carried on removable media and loaded without one is
an unverified binary running as the SOC's system of record.

### 3. Build on the host from git (last resort)

```bash
git fetch --tags && git pull --ff-only
docker compose build && docker compose up -d
```

This needs PyPI and Docker Hub from the production host. Acceptable on a lab machine, wrong on
a database server, and the first thing to fail in a restricted network.

### When a CVE lands

Almost everything a scanner finds in this image is in the Alpine base or a pinned Python
package, not in Sentriq's own code — the 16 HIGH findings from the first image build were all
`krb5-libs` from the base image. So the patch is usually a rebuild, not a code change:

1. **Confirm exposure.** The CI workflow also runs weekly (`schedule` in `ci.yml`) with no code
   change, rebuilding from the current base image. A base-image CVE therefore turns the build
   red before it becomes an incident. Check the SBOM attached to the running release to see
   whether the affected package is even present.
2. **Bump the pin.** Either the base image line in the `Dockerfile` or the affected package in
   `requirements.txt`. `apk upgrade` in the Dockerfile picks up base-image fixes on every build.
3. **Let CI decide.** Push to `main`; the scan gates the build.
4. **Tag and deploy.** `v1.4.4`, then `docker compose pull && docker compose up -d --no-build`.

Do not skip step 1 by rebuilding the same commit and calling it patched: if the pin did not
move, the bytes did not change.

### What not to do

- **Do not deploy `main`.** Deploy tags. Otherwise the next `git pull` ships whatever was
  merged last, including work that has nothing to do with the patch.
- **Do not edit tracked files on the host** (`docker-compose.yml`, `nginx.conf`, `alembic.ini`).
  The next pull refuses to overwrite them. Put host-specific settings in `.env` or an untracked
  `docker-compose.override.yml`.
- **Do not take a snapshot for granted.** The entrypoint skips a backup newer than five minutes
  (`BACKUP_MIN_INTERVAL`), so run `pg_dump` yourself before a migration you are unsure about.
- **Do not rely on `alembic downgrade` alone.** All eleven migrations have a real `downgrade()`,
  but it drops the columns the newer version added. The pre-upgrade dump is the guarantee; the
  downgrade is the fast path.

## Database

Postgres, and nothing else. There is no SQLite fallback: the app refuses to start
without a Postgres `DATABASE_URL`, and refuses a `sqlite://` URL with a message
that says so. Two reasons. The SQL differs between engines — the SLA due date is
`created_at + interval '8 hours'` here — so a SQLite demo would never exercise the
query production runs, and the first Postgres run would be the production one. And
a single file cannot be shared by two app hosts or backed up by a DBA.

- **Docker**: `docker compose up --build` starts `postgres:16-alpine` beside the
  app and points `DATABASE_URL` at it. Its files live in `./pgdata`, a host
  directory, so `docker compose down -v` cannot delete the database.
- **Without Docker**: install Postgres 14 or newer and set
  `DATABASE_URL=postgresql://user:***@host:5432/sentriq`. Migrations run at
  startup.
- **Coming from an older install**: `python -m sentriq.manage import-sqlite
  data/fastapi.sqlite3` copies every table into the configured Postgres database,
  ids included, and refuses if the target already has tickets.

Measured on 5,000 tickets, four workers, ten concurrent page loads: Postgres p95
125 ms for the dashboard and 62 ms for the queue.

### Backing up Postgres

`scripts/backup-postgres.sh` writes `backups/sentriq-pg-<stamp>.dump` with
`pg_dump --format=custom`, keeps the newest 20, and checks each dump with
`pg_restore --list` before renaming it into place, so a failed dump never looks
like a usable snapshot. The container runs it at startup; for a schedule you can
point at, use cron on the host:

```cron
0 2 * * * cd /path/to/Sentriq && docker compose exec -T sentriq sh scripts/backup-postgres.sh /app/backups 30 0 >> /var/log/sentriq-backup.log 2>&1
```

Restore into a fresh database:

```bash
pg_restore --no-owner --no-privileges -d "$DATABASE_URL" backups/sentriq-pg-YYYYmmdd-HHMMSS.dump
```

`/healthz` and `/metrics` report the newest `sentriq-pg-*.dump` and go degraded when
there is none or the newest is older than `BACKUP_MAX_AGE_HOURS`.
If `pg_dump` is not installed, the startup log says so plainly rather than
pretending the database is being backed up.

## Screenshots

### Login

![Login page](docs/screenshots/login.png)

### Dashboard

SOC dashboard with alert counts, charts, and filtered alert queue.

![Dashboard](docs/screenshots/dashboard.png)

### Alert detail

Full alert view with assignment, IOCs, investigation notes, evidence uploads, and activity log.

![Alert detail](docs/screenshots/alert-detail.png)

### User administration

Create users, manage roles (L1/L2/L3), and reset passwords.

![Users admin](docs/screenshots/users-admin.png)

## Features

### Alert management
- SOC dashboard with source/analyst/tactic pie charts and alert counts
- Create, edit, escalate, assign, and close alerts with resolution summaries
- Sequential ticket numbers (`#1`, `#2`, ...) that remain stable after migration
- Severity scale: `0 - Critical`, `1 - High`, `2 - Medium`, `3 - Low`, `4 - Informational`
- Ticket workflow: Open when unassigned, Pending while awaiting analysis, WIP during active analysis, and Closed after resolution; analysts can assign open tickets to themselves
- L1, L2, and L3 users can assign unassigned Open tickets to themselves
- Optional IOCs when creating tickets; close summaries have no application-level word-count limit
- Filter by severity, status, search terms; CSV export of filtered results
- Dashboard date ranges (24 hours, 7, 30, 90 days, all time) applied to the counts, charts and queue
- One ticket at a time: status changes, assignment and closing happen on the ticket itself, so every change carries a name and a reason in its timeline
- Duplicate handling: tickets filed within 24 hours with the same title or asset are listed on the ticket, and L2/L3 can merge one into another — the timeline and evidence move to the surviving ticket, and the duplicate closes pointing at it
- SLA breach history: a sweep records each missed due date and, on closure, how late the ticket actually was; the totals are exposed on `/metrics` and by `python -m sentriq.manage sla-sweep`
- Search matches ticket number, title, description, asset, source, analyst and IOC, and filters apply in place without reloading the page or losing your scroll position
- Notifications by email and Microsoft Teams on new high-severity tickets, assignment and escalation — each channel stays inert until it is configured
- Evidence is attached when the ticket is created; there is no later upload, so a ticket's evidence is exactly what the analyst filed with it
- Every file is stored with its SHA-256 recorded; PNG and JPEG appear as small thumbnails (four per row) that open a full-size popup, everything else is listed as a normal row that downloads. Every download and preview is written to the audit trail with the reader, the file name and its hash — chain of custody, not just a list of uploads
- Evidence uploads accept `.xlsx`, `.csv`, `.jpg`, `.jpeg`, `.png`, `.txt`, `.log`, `.json`, `.pdf`, `.pcap`, `.pcapng`, up to 6 MB each; a rejected file cancels the whole create, so no half-made ticket is left behind
- Investigation notes and activity-log timeline per alert

### Role-based access control

One matrix decides every action, in `sentriq/permissions.py`; the routes ask it
rather than re-implementing the rule. "Own" means the ticket is assigned to that
analyst.

| Capability            | L1 Analyst   | L2 Analyst | L3 Admin |
|-----------------------|:------------:|:----------:|:--------:|
| View, create, take    | Yes          | Yes        | Yes      |
| Edit a ticket         | Own only     | Any open   | Any open |
| Close a ticket        | Own only     | Any open   | Any open |
| Change status         | Own only     | Any open   | Any open |
| Escalate              | Yes          | Yes        | No       |
| Assign to analysts    | No           | L1 only    | L1 + L2  |
| Merge duplicates      | No           | Yes        | Yes      |
| Export the queue      | Yes (audited)| Yes (audited)| Yes (audited) |
| Delete a ticket       | No           | No         | No       |
| Manage users          | No           | No         | Yes      |
| Read the audit trail  | No           | No         | Yes      |

Closed tickets are read-only for everyone: they are the record, not the working
set. An unassigned ticket is nobody's until someone takes it, which is what puts
a name in the timeline — an L1 has to take a ticket before editing or closing it.
Deleting a ticket is refused for every role, because it would take the timeline
and the evidence with it.

Every CSV export writes an audit row naming the analyst, the number of rows and
the filter that produced them.

### Account lifecycle

Admins create users on the **Users** page and can deactivate, reactivate or delete them from the same row. A deactivated account cannot sign in (the login form gives the same "invalid username or password" answer, so it does not confirm which accounts exist), and any session it already holds stops working on the next request. Deactivation is reversible and keeps the account, its tickets and its audit trail; nothing is deleted.

**Delete** removes the row permanently, but only for an account with no history — no tickets, timeline events, evidence or audit entries. If anything references the account the delete is refused, and the message states how many records would lose their attribution. That refusal is deliberate: the database would refuse the delete anyway, but a raw foreign-key error is a poor thing to show an administrator, so the check explains which records would lose their attribution. For a leaver who touched tickets, deactivate instead — access ends immediately and the record stays intact.

Two guards apply to both actions: you cannot act on your own account, and the last active administrator cannot be removed.

**Sessions.** A signed-in session ends at whichever comes first: 8 hours after
sign-in (`SESSION_TTL_SECONDS`), or 30 minutes without a request
(`SESSION_IDLE_SECONDS`). The idle clock moves with each request; the absolute one
does not, so a session left open all day still ends.

Signing out revokes the session on the server, not just in the browser: the
account's `session_epoch` is bumped and every cookie issued before that moment is
refused, including a copy taken from a stolen laptop. The same bump happens on a
password change, a password reset, a role change and a deactivation. The **Sign
out** button on the Users page does it to another account without changing its
password — that is the control to reach for when a device is lost.

Timestamps are stored in UTC and rendered in the configured zone (`DISPLAY_TIMEZONE`, default `Asia/Yangon`) with the zone labelled above the activity log and the audit table.

### Evidence handling

Evidence is the part of a ticket that ends up in front of an auditor, so it is
treated as evidence rather than as a file:

- **Integrity.** The SHA-256 recorded at upload is checked on every read. A file
  that no longer matches is refused with 409 and the refusal is written to the
  audit trail as `evidence.integrity_failed` — silent tampering is worse than a
  visible failure.
- **Type.** Downloads answer with the type derived from the extension on disk,
  never the `Content-Type` the uploader claimed (that claim is still recorded, as
  part of what was filed). Responses also carry `Content-Security-Policy:
  sandbox`, `X-Download-Options: noopen` and `nosniff`.
- **Malware.** Set `EVIDENCE_SCAN_COMMAND` (ClamAV by convention, `{}` is
  replaced by the temporary file) and every upload is scanned before the bytes
  are stored. `EVIDENCE_SCAN_REQUIRED=1` makes a scanner that cannot run block
  the upload instead of letting an unscanned file through:

  ```
  EVIDENCE_SCAN_COMMAND=clamdscan --no-summary --stdout {}
  EVIDENCE_SCAN_REQUIRED=1
  ```

- **At rest.** Set `EVIDENCE_ENCRYPTION_KEY` (32 bytes, hex or base64) and files
  are written as AES-256-GCM, bound to their stored name so one file cannot be
  swapped for another. Files written before the key existed still open; encrypt
  them in place with:

  ```bash
  python -m sentriq.manage encrypt-evidence           # dry run
  python -m sentriq.manage encrypt-evidence --apply
  ```

  Be clear about what this buys: it protects a stolen backup, a copied data
  directory or a decommissioned disk. It does not protect a compromised host,
  where the key is in the process environment. Full-disk encryption (LUKS,
  BitLocker) and a key held in a KMS cover the rest.

### Hardening and operations

**CI** (`.github/workflows/ci.yml`) runs on every push: the test suite against
Postgres, `pip-audit` over `requirements.txt`, a compose-file resolution check,
an image build, a Trivy scan of the image and of the repository configuration
(HIGH/CRITICAL, unfixed excluded), and a smoke test that the built image can
import the worker and the crypto library.

**Image scan locally**, with the same two scans:

```bash
scripts/scan-image.sh sentriq:local
```

**Restore verification.** A backup nobody restored is a guess. This restores the
newest snapshot into a throwaway database, compares the row count of every table
against the live database, and drops the scratch database again. It is safe to
run against production — nothing is written to the live database:

```bash
docker compose exec -T sentriq sh scripts/verify-restore.sh /app/backups
```

```cron
30 3 * * 0 cd /path/to/Sentriq && docker compose exec -T sentriq sh scripts/verify-restore.sh /app/backups >> /var/log/sentriq-restore.log 2>&1
```

It exits non-zero when the snapshot does not restore, when a table is missing
from the restored copy, or when a table is empty there but not in the live
database. A restored copy can legitimately be a few rows behind; it can never be
ahead.

**Trusted proxy.** `TRUSTED_PROXIES` is required in production and must be the
single address the proxy connects from, not a range: anything on that list may
claim any client address, which is what the per-IP rate limits and the audit
source IP are keyed on. Find the Docker bridge gateway with:

```bash
docker network inspect sentriq_default -f '{{ (index .IPAM.Config 0).Gateway }}'
```

## Configuration

All settings are controlled via environment variables. See `.env.example` for the full list.

| Variable                 | Required | Default                | Description                              |
|--------------------------|----------|------------------------|------------------------------------------|
| `APP_SECRET_KEY`         | Yes*     | auto-generated         | Cookie signing key (must persist)        |
| `COOKIE_SECURE`          | No       | `0`                    | Set to `1` for HTTPS-only cookies        |
| `RATE_LIMIT_REQUESTS`    | No       | `120`                  | Max requests per window                  |
| `RATE_LIMIT_WINDOW`      | No       | `60`                   | Rate limit window in seconds             |
| `LOGIN_LOCKOUT_THRESHOLD`| No       | `5`                    | Failed attempts per address+username     |
| `LOGIN_ACCOUNT_LOCKOUT_THRESHOLD` | No | `10`                 | Failed attempts per account, any address |
| `LOGIN_LOCKOUT_SECONDS`  | No       | `300`                  | Lockout duration in seconds              |
| `TRUSTED_PROXIES`        | No       | `127.0.0.1/32,::1/128` | Peers allowed to set `X-Forwarded-For`   |
| `DISPLAY_TIMEZONE`       | No       | `Asia/Yangon`          | Zone used to render stored UTC times     |
| `DATABASE_URL`           | **Yes**  | —                      | Postgres URL; the app will not start without it |
| `WEB_CONCURRENCY`        | No       | `4`                    | Worker processes; see Performance        |
| `REDIS_URL`              | No       | unset                  | Shared limiter and lockout counters      |
| `RETENTION_DAYS`         | No       | `730`                  | Archive window for closed tickets        |
| `RETENTION_BATCH_SIZE`   | No       | `500`                  | Tickets per transaction in a daily pass  |
| `METRICS_TOKEN`          | No       | unset                  | Bearer token for `/metrics`              |
| `BACKUP_MAX_AGE_HOURS`   | No       | `36`                   | Snapshot age that marks `/healthz` stale |
| `SMTP_HOST`              | No       | unset                  | Email notifications                      |
| `NOTIFY_EMAIL_TO`        | No       | unset                  | Comma-separated recipients               |
| `NOTIFY_TEAMS_WEBHOOK`   | No       | unset                  | Teams incoming webhook                   |

`TRUSTED_PROXIES` matters behind nginx or a Docker port mapping: the app resolves
the client address from `X-Forwarded-For` only when the direct peer is in this
list, and uses that address for rate limiting, login lockout, and every audit
row. Leave it at loopback for a direct deployment. `docker-compose.yml` widens it
to the Docker bridge range so the host proxy is trusted; never widen it to a
range that can reach the app port directly, or clients can choose their own
identity. `/healthz` and `/static/` are exempt from the request limiter so the
container healthcheck cannot throttle itself.

Production startup fails unless both secrets are explicitly supplied and at least 32 characters long. Keep them stable and private.

## Performance

The dashboard, the queue and the CSV export are all built from one filter
(`alert_query` in `sentriq/services/alert_service.py`), and the database
answers it: tiles and pie panels are `COUNT` and `GROUP BY`, and the queue pages
with `LIMIT`/`OFFSET`. Nothing loads the whole table to count it.

Measured on a 5,000-ticket database, one host, SQLite (the engine in use when the query layer was rewritten; the Postgres figures are in [Database](#database)):

| page                     | before        | after, 1 worker | after, 4 workers |
|--------------------------|---------------|-----------------|------------------|
| dashboard, one analyst   | 1,300 ms      | 29 ms           | 29 ms            |
| queue, one analyst       | 110 ms        | 14 ms           | 16 ms            |
| dashboard, 10 at once    | ~70,000 ms    | 942 ms          | 78 ms            |
| queue, 10 at once        | ~17,000 ms    | 551 ms          | 38 ms            |

Ten concurrent analysts is the target, so `WEB_CONCURRENCY` now defaults to 4.
Workers are separate processes, which is what turns the queue into parallel work.
The rate limiter and login lockout counters live inside each worker, so four
workers allow four times the per-client limit.
Set `REDIS_URL` to share those counters, and move to Postgres (`DATABASE_URL`)
when several analysts write at the same time or the database must live off this
host.

The SLA sweep runs at most once every two minutes per worker instead of on every
page load, and reads the open tickets in one query rather than one query per
ticket. `python -m sentriq.manage sla-sweep` does the same work from cron if
you would rather schedule it.

## Development

For local development without Docker:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload --port 8080
```

The `--reload` flag auto-restarts on code changes. Do not use `--reload` in production.

## Tech stack

- **Backend:** FastAPI + SQLAlchemy + Alembic (Postgres 14+)
- **Frontend:** Jinja2 server-rendered HTML, vanilla CSS (light/dark)
- **Auth:** Cookie-based sessions with PBKDF2-SHA256 password hashing
- **Security:** CSRF protection, rate limiting, login lockout, security headers, audit logging
- **Deployment:** Docker with gunicorn + uvicorn workers
- **Testing:** pytest with 103 automated tests

## Testing

Run the test suite:

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

The runtime image installs `requirements.txt` only, so test tooling never ships. Check the dependency tree for advisories before a release:

```bash
pip-audit -r requirements.txt
```

Test coverage includes:
- Authentication and RBAC permissions (41 tests)
- Alert service business logic (19 tests)
- Retention archival and audit-export chain verification
- SLA breach history, backup freshness, and the metrics endpoint
- Limiter counters in memory and through Redis (`fakeredis`), including the Redis-outage fallback
- A guard that no request handler is declared `async def`, so blocking database and PBKDF2 work stays off the event loop

The suite runs on Postgres. It starts a bundled Postgres server for the session
(`pgserver`, a development dependency) and gives every test its own database
cloned from a migrated template, so tests stay isolated without a shared fixture
database. Nothing else to start:

```bash
pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

`tests/test_postgres.py` still exists as a separate check that drops and recreates
the `public` schema and runs the real migrations to head, which is closer to a
fresh deployment than the template clone is:

```bash
TEST_DATABASE_URL=postgresql://user:***@host/scratch_db pytest tests/test_postgres.py
```

It drops and recreates the `public` schema, runs the real migrations to head, and drives a ticket round trip, a close with audit rows, and import deduplication. Point it at a scratch database only.

## Future improvements

- ~~Automated tests for alert workflows, role permissions, and imports~~ ✅ Done
- ~~Dashboard date-range filters~~ ✅ Done (trend charts still open)
- ~~SLA tracking with breach history~~ ✅ Done
- ~~External integrations for notifications~~ ✅ Done (email and Teams)
- Trend charts for weekly and monthly reporting
- Evidence tagging and per-evidence retention
- API documentation page with example payloads for inbound ingest
- OpenTelemetry traces for slow dashboard queries at scale

## Contributing

Community contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for suggested areas, pull request guidance, and security notes.

## License

[MIT](LICENSE)
