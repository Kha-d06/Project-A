# Operations runbook

How to run SENTINEL day to day: starting it, backups, upgrades, monitoring,
secrets, and what to do when something breaks.

## Start and stop

```bash
./scripts/up.sh                 # first run creates .env with random secrets
docker compose ps               # every service should be "running" or "healthy"
docker compose logs -f api      # follow one service
docker compose down             # stop (data volumes are kept)
```

| Service | Role | Database access |
| --- | --- | --- |
| `caddy` | HTTPS and routing; the only published service | none |
| `web` | Next.js site and API gateway | none |
| `api` | REST API | full |
| `worker` | Runs scans of untrusted content (queue `scans`) | restricted role only |
| `tasks` | Feeds, retention, webhooks, bot and email replies, summaries (queue `tasks`) | full |
| `scheduler` | Celery beat: hourly feeds and retention, weekly summaries and breach checks | none |
| `postgres`, `redis` | Data and queues | — |

Scale scan capacity with `docker compose up -d --scale worker=3`.

## Backups

```bash
./scripts/backup.sh             # backups/sentinel-YYYYmmdd-HHMMSS.sql.gz, keeps 14
KEEP=30 ./scripts/backup.sh
```

**Automatic daily backups:** add `backups` to `COMPOSE_PROFILES` in `.env` (for
example `COMPOSE_PROFILES=backups`) and run `docker compose up -d`. The `backup`
service writes a checked dump to `./backups` every 24 hours and keeps
`BACKUP_DAYS` days (default 14). Or run the script below from cron.

**Run it daily from cron.** Copy `backups/` to storage on a different machine:
a backup on the same disk does not survive the disk. The script checks that
each dump is complete before it rotates old ones out.

**What is in a backup:**
- included: accounts, scan history, reports, groups, settings and the threat-indicator store;
- not included: uploaded samples, which only exist while a scan runs;
- not included: Redis, which holds rate-limit counters, the queue and caches, all of which rebuild themselves.

**The secrets are not in the backup.** Store `.env` separately and securely. Without `SENTINEL_SECRET_KEY`:
- two-step sign-in secrets cannot be decrypted, so those users must be reset;
- webhook signing secrets are lost;
- extension access tokens stop working.

**Restore** (replaces everything):

```bash
./scripts/restore.sh backups/sentinel-20261117-020000.sql.gz
```

It stops the API and workers, restores, reapplies the scan worker's restricted
grants and starts them again.

**Practise a restore every quarter** on a scratch database:

```bash
DATABASE_URL=postgresql://…/scratch CONFIRM=yes ./scripts/restore.sh <file>
```

Compare the account and scan counts, and check that `alembic_version` matches the original.

## Upgrades

1. Take a backup.
2. Run `git pull`, then `docker compose build`.
3. Run `docker compose up -d`. The `migrate` service applies database migrations before the API starts.
4. Check `docker compose ps` and `curl -fsS https://<site>/api/v1/system/health`.

Every migration can be downgraded (`alembic downgrade <revision>`), but
restoring the pre-upgrade backup is the safer rollback.

## Monitoring and alerts

Start Prometheus with `docker compose --profile monitoring up -d`; it needs
`SENTINEL_METRICS_TOKEN` in `.env`. The rules in
`infrastructure/monitoring/alerts.yml` fire for the situations below.
The profile also starts Alertmanager, which sends firing and resolved alerts to
SENTINEL; SENTINEL emails every administrator using its own mail settings
(`SENTINEL_SMTP_*`), so email must be configured. You can also point an uptime
service at `/api/v1/system/health` to learn if the whole server is down.

| Alert | What to do |
| --- | --- |
| `SentinelDown` | Check `docker compose ps` and `logs api`. Check that PostgreSQL is healthy. |
| `ThreatFeedStale` | Check `logs tasks` for download errors. Check outbound HTTPS to abuse.ch. Run `docker compose exec api python -m app.cli sync-feeds`. |
| `ScansStuck`, `ScanQueueBacklog` | Check that `worker` is running, then scale it. Stuck scans are failed automatically after 15 minutes. |
| `TaskQueueBacklog` | Check that `tasks` is running. Webhooks to slow endpoints can pile up. |
| `RedisUnreachable` | The API refuses requests (rate limiting fails closed). Restart `redis` and check memory. |
| `ScansFailing` | Check `logs worker` for analyzer errors. Remember that one bad upload can fail on purpose. |
| `ReportsWaiting` | Ask moderators to review. The admin dashboard shows the workload by age. |
| `WebhooksFailing` | Usually the receivers are down. If many fail, check outbound network from `tasks`. |

## Releases and app downloads

1. Tag a version: `git tag v0.2.0 && git push origin v0.2.0`. The **Release**
   workflow builds the Windows installer, macOS disk image, Linux AppImage/.deb/.rpm
   and the Android APK, and attaches them to a GitHub release with `SHA256SUMS.txt`.
2. Download the release files and run `./scripts/publish-downloads.sh <folder>`.
   They are then served at `<site>/downloads/`, listed on `<site>/download`, and
   the desktop apps update themselves from there.

**Signing.** Without certificates the builds are unsigned: Windows shows a
SmartScreen warning, macOS asks users to right-click → Open and cannot update
itself, and Android asks to allow "install unknown apps". To sign, add the
repository secrets listed at the top of `.github/workflows/release.yml`.

**Email for development.** `scripts/demo.sh` turns on `COMPOSE_PROFILES=devmail`,
which sends every email to a local Mailpit inbox at `http://localhost:8025`.
For real delivery set `SENTINEL_EMAIL_BACKEND=smtp` and your provider's
`SENTINEL_SMTP_*` settings, and remove `devmail` from `COMPOSE_PROFILES`.

## Load and capacity

`services/api/scripts/loadtest.py` drives the browser-extension check endpoint,
which is the busiest one. Run it against a private copy started with
`SENTINEL_RATE_LIMIT_MULTIPLIER=1000`; production refuses that setting.

One development machine (4 API workers, local PostgreSQL and Redis, 32
simulated browsers), measured in November 2026:

| | Requests per second | p50 | p95 |
| --- | --- | --- | --- |
| Before caching | 142 | 211 ms | 376 ms |
| With the shared check cache | 474 | 20 ms | 202 ms |

The cache keeps answers for up to two minutes. It is keyed by a digest of the
address, and it is invalidated, after commit, whenever threat data changes (a
feed sync or a moderator decision), so a new listing takes effect immediately.
These figures are a starting point, not a capacity guarantee: measure your own
hardware.

## Secrets and keys

| Secret | Rotate how | Effect |
| --- | --- | --- |
| `SENTINEL_SECRET_KEY` | Avoid. If it leaked, set a new value and restart | Signs everyone out. Users with two-step sign-in must set it up again. Webhook secrets must be recreated. Extensions re-enroll by themselves. |
| `POSTGRES_PASSWORD`, `WORKER_DB_PASSWORD` | Change in PostgreSQL and `.env`, then restart | None for users. |
| `WORKER_SECRET_KEY` | Set a new value, restart `worker` | None for users. |
| `SENTINEL_METRICS_TOKEN` | Change in `.env` and in the Prometheus token file | Monitoring only. |
| Third-party keys (Web Risk, VirusTotal, HIBP, Telegram, WhatsApp, SMTP, VAPID) | At the provider, then in `.env` | Changing the VAPID keys drops every browser-notification subscription. |

## Incidents

1. **Decide whether it is a security incident** (for example a leaked secret, an unexpected admin account, or data showing up elsewhere). If so, rotate the affected secrets first and keep the logs.
2. **The audit log** (Admin → Audit log) records sign-ins, security changes and staff actions with IP addresses for 180 days.
3. **To take the service offline** while investigating: `docker compose stop caddy`. Nothing else is published.
4. **Write down** what happened, when it was noticed, what was affected and what changed. Tell affected users if their data was involved.
