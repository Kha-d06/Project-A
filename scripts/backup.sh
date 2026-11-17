#!/usr/bin/env bash
# Back up SENTINEL's database (accounts, scan history, reports, settings).
#   ./scripts/backup.sh                  via Docker Compose
#   DATABASE_URL=postgresql://… ./scripts/backup.sh   directly with pg_dump
# Writes backups/sentinel-YYYYmmdd-HHMMSS.sql.gz and keeps the newest KEEP (default 14).
# Uploaded samples are never backed up: they only exist while a scan runs.
set -euo pipefail
cd "$(dirname "$0")/.."
KEEP="${KEEP:-14}"
mkdir -p backups
chmod 700 backups
target="backups/sentinel-$(date -u +%Y%m%d-%H%M%S).sql.gz"
umask 077
if [ -n "${DATABASE_URL:-}" ]; then
  pg_dump --no-owner --no-privileges "$DATABASE_URL" | gzip -9 > "$target"
else
  docker compose exec -T postgres pg_dump --no-owner --no-privileges -U sentinel sentinel | gzip -9 > "$target"
fi
# A dump that is empty or cut off is worse than none: check it before rotating.
gzip -t "$target"
if ! zcat "$target" | grep -q "PostgreSQL database dump complete"; then
  echo "Backup looks incomplete: $target" >&2
  exit 1
fi
ls -1t backups/sentinel-*.sql.gz | tail -n +"$((KEEP + 1))" | xargs -r rm --
echo "Backup written: $target ($(du -h "$target" | cut -f1))"
