#!/usr/bin/env bash
# Bring SENTINEL up locally and create an administrator account, ready to test.
#
#   ./scripts/demo.sh                     # admin@sentinel.local / password printed at the end
#   ./scripts/demo.sh you@example.com     # choose the admin email (password is generated)
#   ADMIN_PASSWORD='my-strong-pass' ./scripts/demo.sh you@example.com   # choose both
#
# Needs Docker Desktop (or Docker Engine + the compose plugin) running.
set -euo pipefail
cd "$(dirname "$0")/.."

ADMIN_EMAIL="${1:-admin@sentinel.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(python3 -c 'import secrets; print("Sentinel-" + secrets.token_urlsafe(9))')}"

echo "==> Building and starting SENTINEL (first run can take a few minutes)…"
./scripts/up.sh --fixtures

echo "==> Creating the administrator account…"
docker compose exec -T api python -m app.cli create-admin "$ADMIN_EMAIL" "$ADMIN_PASSWORD"

cat <<SUMMARY

────────────────────────────────────────────────────────────
 SENTINEL is running:  http://localhost:8080
 Sign in at:           http://localhost:8080/sign-in

 Administrator account
   Email:     $ADMIN_EMAIL
   Password:  $ADMIN_PASSWORD

 This admin can reach every feature, including:
   • Admin console        http://localhost:8080/dashboard/admin
   • Site assessment      http://localhost:8080/dashboard/assessment
   • Devices, Passwords, VPN, Family & teams, scanners…

 Stop it with:   docker compose down        (your data is kept)
 Start again:    docker compose up -d
────────────────────────────────────────────────────────────
SUMMARY
