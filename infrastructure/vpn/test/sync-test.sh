#!/bin/sh
# Tests sync.sh without WireGuard: a stand-in `wg` and a stand-in Qalaa API.
#   sh infrastructure/vpn/test/sync-test.sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'kill "$SERVER" 2>/dev/null; rm -rf "$WORK"' EXIT

cat > "$WORK/wg" <<'WG'
#!/bin/sh
case "$1" in
  pubkey) echo "U2VydmVyUHVibGljS2V5U2VydmVyUHVibGljS2V5MDA=" ;;
  show) printf 'privkey\tpubkey\t51820\toff\n' ; printf 'UGhvbmVQdWJsaWNLZXlQaG9uZVB1YmxpY0tleTAwMDA=\t(none)\t203.0.113.9:4500\t10.13.13.2/32\t1763380000\t5000\t900\toff\n' ;;
  syncconf) cp "$3" "$WORK_DIR/applied.conf" ;;
esac
WG
chmod +x "$WORK/wg"
echo "c2VydmVyLXByaXZhdGUta2V5LWZvci10ZXN0cy0wMDA=" > "$WORK/server.key"

cat > "$WORK/api.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with open(sys.argv[2], "w") as f:
            json.dump({"auth": self.headers.get("Authorization"), "body": body}, f)
        peers = [
            {"public_key": "UGhvbmVQdWJsaWNLZXlQaG9uZVB1YmxpY0tleTAwMDA=", "address": "10.13.13.2"},
            {"public_key": "evil\n[Peer]\nPublicKey = x", "address": "10.13.13.9"},
            {"public_key": "TGFwdG9wUHVibGljS2V5TGFwdG9wUHVibGljS2V5MDA=", "address": "0.0.0.0/0\nEndpoint = 1.2.3.4"},
        ]
        data = json.dumps(peers).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(data)
    def log_message(self, *args): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
python3 "$WORK/api.py" 18765 "$WORK/request.json" & SERVER=$!
sleep 1

WG="$WORK/wg" WORK_DIR="$WORK" VPN_WORK_DIR="$WORK" VPN_KEY_FILE="$WORK/server.key" \
  VPN_SYNC_TOKEN="test-token-0123456789-0123456789-abc" SENTINEL_API_URL="http://127.0.0.1:18765" \
  sh "$HERE/../sync.sh" --once

fail() { echo "FAIL: $1" >&2; exit 1; }
jq -e '.auth == "Bearer test-token-0123456789-0123456789-abc"' "$WORK/request.json" >/dev/null || fail "token not sent"
jq -e '.body.public_key == "U2VydmVyUHVibGljS2V5U2VydmVyUHVibGljS2V5MDA="' "$WORK/request.json" >/dev/null || fail "server key not sent"
jq -e '.body.peers[0] == {"public_key":"UGhvbmVQdWJsaWNLZXlQaG9uZVB1YmxpY0tleTAwMDA=","latest_handshake":1763380000,"received_bytes":5000,"sent_bytes":900}' "$WORK/request.json" >/dev/null || fail "stats wrong"
grep -q "^PrivateKey = c2VydmVyLXByaXZhdGUta2V5LWZvci10ZXN0cy0wMDA=$" "$WORK/applied.conf" || fail "interface missing"
[ "$(grep -c '^\[Peer\]' "$WORK/applied.conf")" = 1 ] || fail "malformed peers were not dropped"
grep -q "^AllowedIPs = 10.13.13.2/32$" "$WORK/applied.conf" || fail "peer address missing"
! grep -q "Endpoint\|evil\|0.0.0.0" "$WORK/applied.conf" || fail "injected text reached the config"
[ "$(stat -c %a "$WORK/wg0.conf" 2>/dev/null || stat -f %Lp "$WORK/wg0.conf")" = 600 ] || fail "config readable by others"
! ps -ef 2>/dev/null | grep -v grep | grep -q "test-token-0123" || fail "token visible in process list"
echo "sync.sh: all checks passed"
