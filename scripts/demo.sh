#!/usr/bin/env bash
# Bring SENTINEL up locally and create an administrator account, ready to test.
#
#   ./scripts/demo.sh                     # admin@example.com / password printed at the end
#   ./scripts/demo.sh you@example.com     # choose the admin email (password is generated)
#   ADMIN_PASSWORD='my-strong-pass' ./scripts/demo.sh you@example.com   # choose both
#
# Needs Docker Desktop (or Docker Engine + the compose plugin) running.
set -euo pipefail
cd "$(dirname "$0")/.."

ADMIN_EMAIL="${1:-admin@example.com}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(python3 -c 'import secrets; print("Sentinel-" + secrets.token_urlsafe(9))')}"

echo "==> Building and starting SENTINEL (first run can take a few minutes)…"
./scripts/up.sh --fixtures

# Local-testing settings, written into .env only where you have not set your own:
# emails go to a local inbox (Mailpit) instead of being sent, and daily database
# backups land in ./backups.
python3 - <<'PY'
import re
path = ".env"
text = open(path).read()
defaults = {
    "COMPOSE_PROFILES": "devmail,backups",
    "SENTINEL_EMAIL_BACKEND": "smtp",
    "SENTINEL_EMAIL_FROM": "\"SENTINEL <no-reply@example.com>\"",
    "SENTINEL_SMTP_HOST": "mailpit",
    "SENTINEL_SMTP_PORT": "1025",
    "SENTINEL_SMTP_STARTTLS": "false",
}
def current(key):
    match = re.search(rf"^{key}=(.*)$", text, re.M)
    return None if match is None else match.group(1).strip()

# If you configured your own mail server, leave every mail setting alone.
own_mail = (current("SENTINEL_SMTP_HOST") or "mailpit") != "mailpit"
for key, value in defaults.items():
    is_mail = key.startswith(("SENTINEL_SMTP", "SENTINEL_EMAIL"))
    if is_mail and own_mail:
        continue
    existing = current(key)
    if existing is None:
        text += f"\n{key}={value}"
    elif key == "COMPOSE_PROFILES" and existing:
        continue  # you chose your own profiles
    elif is_mail and existing in ("", "disabled", "587", "true") or key == "SENTINEL_EMAIL_FROM":
        text = re.sub(rf"^{key}=.*$", f"{key}={value}", text, count=1, flags=re.M)
open(path, "w").write(text.rstrip("\n") + "\n")
PY
docker compose up -d

echo "==> Creating the administrator account…"
docker compose exec -T api python -m app.cli create-admin "$ADMIN_EMAIL" "$ADMIN_PASSWORD"

echo "==> Downloading real threat data (needs internet; refreshed hourly after this)…"
docker compose exec -T api python -m app.cli sync-feeds || echo "    Could not reach the threat feeds now; the scheduler will retry every hour."

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

 Emails SENTINEL sends (sign-up, password reset, alerts) arrive in
 a local test inbox:  http://localhost:8025
 Database backups:    ./backups (daily)
 Desktop & Android apps:  http://localhost:8080/download

 Stop it with:   docker compose down        (your data is kept)
 Start again:    docker compose up -d
────────────────────────────────────────────────────────────
SUMMARY
