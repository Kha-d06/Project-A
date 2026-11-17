#!/usr/bin/env bash
# Restore a backup made by backup.sh. This REPLACES all current data.
#   ./scripts/restore.sh backups/sentinel-….sql.gz
#   DATABASE_URL=postgresql://… ./scripts/restore.sh backups/…   directly with psql
set -euo pipefail
cd "$(dirname "$0")/.."
file="${1:?Usage: restore.sh <backup.sql.gz>}"
gzip -t "$file"
if [ "${CONFIRM:-}" != "yes" ]; then
  read -r -p "This replaces every account, scan and report with the backup. Type 'restore' to continue: " answer
  [ "$answer" = "restore" ] || { echo "Cancelled."; exit 1; }
fi
reset_sql="DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
if [ -n "${DATABASE_URL:-}" ]; then
  psql -v ON_ERROR_STOP=1 -q "$DATABASE_URL" -c "$reset_sql"
  zcat "$file" | psql -v ON_ERROR_STOP=1 -q "$DATABASE_URL"
else
  docker compose stop api worker tasks scheduler
  docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -q -U sentinel sentinel -c "$reset_sql"
  zcat "$file" | docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -q -U sentinel sentinel
  # The restricted worker role's grants live on the tables, so apply them again.
  docker compose run --rm worker-role
  docker compose start api worker tasks scheduler
fi
echo "Restored from $file."
