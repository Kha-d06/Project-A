#!/usr/bin/env bash
# One command to run SENTINEL locally with Docker Compose.
#   ./scripts/up.sh            build and start everything on http://localhost:8080
#   ./scripts/up.sh --fixtures also load the development test indicators
# Creates .env with fresh random secrets the first time.
set -euo pipefail
cd "$(dirname "$0")/.."

secret() { python3 -c "import secrets; print(secrets.token_urlsafe(48))"; }

if [ ! -f .env ]; then
  cp .env.example .env
  for name in SENTINEL_SECRET_KEY POSTGRES_PASSWORD WORKER_DB_PASSWORD WORKER_SECRET_KEY SENTINEL_VPN_SYNC_TOKEN; do
    value="$(secret)"
    sed -i.bak "s|^${name}=.*|${name}=${value}|" .env
  done
  rm -f .env.bak
  echo "Created .env with new random secrets."
fi

docker compose up -d --build

echo "Waiting for SENTINEL to answer…"
for _ in $(seq 1 90); do
  if curl -fsS http://localhost:8080/api/v1/system/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS http://localhost:8080/api/v1/system/health >/dev/null || { docker compose ps; docker compose logs --tail=50 api; exit 1; }

if [ "${1:-}" = "--fixtures" ]; then
  docker compose exec -T api python -m app.cli load-test-fixtures
fi

echo "SENTINEL is running at http://localhost:8080"
