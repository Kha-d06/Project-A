#!/bin/sh
# Runs inside the "backup" Compose service (COMPOSE_PROFILES=backups): a daily
# pg_dump of the database into /backups, checked for completeness, keeping
# backups for BACKUP_DAYS days (default 14). Copy ./backups to another machine:
# a backup on the same disk does not survive the disk.
set -u
umask 077
DAYS="${BACKUP_DAYS:-14}"
DIR="${BACKUP_DIR:-/backups}"
while true; do
  stamp="$(date -u +%Y%m%d-%H%M%S)"
  file="$DIR/sentinel-$stamp.sql.gz"
  partial="$DIR/.sentinel-$stamp.partial"
  # Connection settings come from PGHOST, PGUSER, PGDATABASE and PGPASSWORD.
  if pg_dump --no-owner --no-privileges | gzip -9 > "$partial" \
    && zcat "$partial" | grep -q "PostgreSQL database dump complete"; then
    mv "$partial" "$file"
    echo "backup written: $file"
    # Only finished backups older than the retention period are removed.
    find "$DIR" -maxdepth 1 -type f -name 'sentinel-*.sql.gz' -mtime +"$DAYS" -delete
  else
    echo "BACKUP FAILED at $stamp; the previous backups are kept" >&2
    find "$DIR" -maxdepth 1 -type f -name '.sentinel-*.partial' -delete
  fi
  [ "${BACKUP_ONCE:-}" = "1" ] && exit 0
  sleep 86400
done
