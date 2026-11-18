"""End-to-end VPN check against the running Compose stack (used in CI).

Registers an account, adds a VPN device with a key made here, brings up a real
WireGuard interface on this machine pointed at the server, and checks that a
handshake happens and that Qalaa then reports the device as connected.
Needs: the stack running with --profile vpn, wireguard-tools, and sudo.

    python3 infrastructure/vpn/test/stack-test.py http://localhost:8080
"""

import http.cookiejar
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

SITE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ""


def call(method: str, path: str, body: object | None = None) -> dict:
    request = urllib.request.Request(
        f"{SITE}/api/v1{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"content-type": "application/json", "x-csrf-token": csrf},
    )
    with opener.open(request, timeout=15) as response:
        return json.loads(response.read() or b"{}")


def healthy() -> bool:
    try:
        with urllib.request.urlopen(f"{SITE}/api/v1/system/health", timeout=5) as response:
            return response.status == 200
    except OSError:
        return False


def run(*args: str, stdin: str | None = None) -> str:
    done = subprocess.run(args, input=stdin, capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"✗ {' '.join(args)} failed ({done.returncode}): {done.stderr.strip()}")
    return done.stdout.strip()


def wait(what: str, check, seconds: int = 60) -> None:
    last_error = ""
    for _ in range(seconds):
        try:
            if check():
                print(f"✓ {what}")
                return
        except urllib.error.HTTPError as error:  # e.g. 502 while a container restarts
            last_error = f"HTTP {error.code}: {error.read()[:300]!r}"
        except (OSError, subprocess.CalledProcessError) as error:
            last_error = str(error)
        time.sleep(1)
    raise SystemExit(f"✗ {what}: timed out {last_error}")


# The API container was just recreated; wait until it answers through Caddy.
wait("API is up", healthy, 90)


session = call("POST", "/auth/register", {"email": f"vpn-{int(time.time())}@example.com", "password": "a-strong-password-123"})
csrf = session["csrf_token"]
wait("VPN server checked in with Qalaa", lambda: call("GET", "/vpn")["server_online"])

private_key = run("wg", "genkey")
public_key = run("wg", "pubkey", stdin=private_key)
config = call("POST", "/vpn/devices", {"name": "CI runner", "public_key": public_key})
assert config["allowed_ips"] == "0.0.0.0/0, ::/0", config
print(f"✓ device added at {config['address']}")

server_address = config["address"].rsplit(".", 1)[0] + ".1"
# Only the server's address goes through the tunnel here, so the runner keeps its own network.
for command in (
    ["ip", "link", "add", "wgci", "type", "wireguard"],
    ["wg", "set", "wgci", "private-key", "/dev/stdin", "peer", config["server_public_key"],
     "endpoint", "127.0.0.1:51820", "allowed-ips", f"{server_address}/32", "persistent-keepalive", "5"],
    ["ip", "address", "add", config["address"], "dev", "wgci"],
    ["ip", "link", "set", "wgci", "up"],
):
    # The private key goes in on standard input, never into a file.
    run("sudo", *command, stdin=private_key if "private-key" in command else None)
# The server drops everything addressed to itself, but the attempt starts the handshake.
subprocess.run(["ping", "-c", "3", "-W", "1", server_address], capture_output=True)

wait("WireGuard handshake with the server", lambda: run("sudo", "wg", "show", "wgci", "latest-handshakes").split()[-1] != "0", 30)
wait(
    "Qalaa shows the device as connected",
    lambda: any(d["connected"] for d in call("GET", "/vpn")["devices"]),
    40,
)
run("sudo", "ip", "link", "del", "wgci")
print("VPN end to end: all checks passed")
