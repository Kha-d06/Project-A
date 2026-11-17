#!/bin/sh
# Every few seconds: report this server's public key and each device's last
# handshake and traffic to SENTINEL, receive the devices allowed to connect,
# and apply them without dropping existing sessions (wg syncconf).
# If SENTINEL cannot be reached, the current devices are kept.
set -u

API="${SENTINEL_API_URL%/}/api/v1/vpn/sync"
INTERVAL="${VPN_SYNC_INTERVAL:-10}"
PORT="${VPN_PORT:-51820}"
WG="${WG:-wg}"
KEY_FILE="${VPN_KEY_FILE:-/data/server.key}"
WORK="${VPN_WORK_DIR:-/tmp}"

umask 077
PUBLIC_KEY="$("$WG" pubkey < "$KEY_FILE")"
# The token goes in a header file, not on the command line where `ps` would show it.
printf 'Authorization: Bearer %s\n' "$VPN_SYNC_TOKEN" > "$WORK/auth-header"

sync_once() {
  stats="$("$WG" show wg0 dump | awk 'NR > 1 {
    printf "%s{\"public_key\":\"%s\",\"latest_handshake\":%d,\"received_bytes\":%d,\"sent_bytes\":%d}", (n++ ? "," : ""), $1, $5, $6, $7
  }')"
  body="{\"public_key\":\"$PUBLIC_KEY\",\"peers\":[$stats]}"
  if ! peers="$(curl -fsS --max-time 10 -H @"$WORK/auth-header" -H 'Content-Type: application/json' --data "$body" "$API")"; then
    echo "Could not reach SENTINEL; keeping the current devices." >&2
    return 1
  fi
  {
    printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n' "$(cat "$KEY_FILE")" "$PORT"
    # Only well-formed keys and IPv4 addresses are written, so nothing else can reach the config.
    printf '%s' "$peers" | jq -r '.[]
      | select((.public_key | test("^[A-Za-z0-9+/]{43}=$")) and (.address | test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")))
      | "\n[Peer]\nPublicKey = \(.public_key)\nAllowedIPs = \(.address)/32"'
  } > "$WORK/wg0.conf"
  "$WG" syncconf wg0 "$WORK/wg0.conf"
}

if [ "${1:-}" = "--once" ]; then
  sync_once
  exit $?
fi
while :; do
  sync_once || true
  sleep "$INTERVAL"
done
