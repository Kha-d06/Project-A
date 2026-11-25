# ruff: noqa: E501, S108, S603 - runs inside the sandbox, where /tmp is its own tmpfs.
"""Runs inside the detonation sandbox (gVisor, no network): a fake DNS and HTTP
service on loopback, then the sample.

Every DNS name the sample looks up is answered with 127.0.0.1 and recorded,
and every HTTP request that follows is answered with an empty 200 and
recorded, so a downloader shows where it would have gone without reaching
anything. One JSON document goes to stdout at the end.

Standard library only: it runs on the sandbox's own read-only Python.
"""

from __future__ import annotations

import contextlib
import json
import os
import resource
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

MAX_EVENTS = 200
events: list[dict[str, object]] = []
lock = threading.Lock()


def record(kind: str, **fields: object) -> None:
    with lock:
        if len(events) < MAX_EVENTS:
            events.append({"kind": kind, **fields})


def parse_dns_query(packet: bytes) -> tuple[int, str, int, int] | None:
    """(id, name, qtype, end of question) for a one-question query."""
    if len(packet) < 12:
        return None
    qid, _flags, qd = struct.unpack("!HHH", packet[:6])
    if qd < 1:
        return None
    labels: list[str] = []
    i = 12
    while i < len(packet):
        n = packet[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 or i + 1 + n > len(packet) or len(labels) > 64:
            return None
        labels.append(packet[i + 1 : i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    if i + 4 > len(packet):
        return None
    qtype = struct.unpack("!H", packet[i : i + 2])[0]
    return qid, ".".join(labels).lower(), qtype, i + 4


def dns_answer(packet: bytes) -> bytes | None:
    parsed = parse_dns_query(packet)
    if parsed is None:
        return None
    qid, _name, qtype, end = parsed
    question = packet[12:end]
    if qtype != 1:  # only A records get an address; others an empty answer
        return struct.pack("!HHHHHH", qid, 0x8180, 1, 0, 0, 0) + question
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + answer


def dns_server(sock: socket.socket) -> None:
    while True:
        try:
            data, addr = sock.recvfrom(512)
        except OSError:
            return
        parsed = parse_dns_query(data)
        if parsed:
            record("dns", name=parsed[1][:253], qtype=parsed[2])
        reply = dns_answer(data)
        if reply:
            sock.sendto(reply, addr)


def parse_http_head(head: bytes) -> dict[str, str] | None:
    try:
        text = head.decode("latin-1")
    except UnicodeDecodeError:
        return None
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2 or not parts[0].isalpha():
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()[:200]
    return {
        "method": parts[0][:10],
        "path": parts[1][:300],
        "host": headers.get("host", ""),
        "user_agent": headers.get("user-agent", ""),
    }


def http_conn(conn: socket.socket, port: int) -> None:
    conn.settimeout(3)
    try:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 16384:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        req = parse_http_head(data.split(b"\r\n\r\n", 1)[0])
        if req:
            record("http", port=port, **req)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        else:
            record("tcp", port=port, first_bytes=len(data))
    except OSError:
        pass
    finally:
        conn.close()


def tcp_server(sock: socket.socket, port: int) -> None:
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        threading.Thread(target=http_conn, args=(conn, port), daemon=True).start()


def start_sinks() -> None:
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 53))
        threading.Thread(target=dns_server, args=(udp,), daemon=True).start()
    except OSError as exc:
        record("sink_error", service="dns", error=str(exc))
    for port in (80, 443, 8080):
        try:
            tcp = socket.socket()
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind(("127.0.0.1", port))
            tcp.listen(16)
            threading.Thread(target=tcp_server, args=(tcp, port), daemon=True).start()
        except OSError as exc:
            record("sink_error", service=f"tcp/{port}", error=str(exc))


def main(argv: list[str]) -> int:
    seconds = float(argv[0])
    memory_mb = int(argv[1])
    command = argv[2:]
    start_sinks()
    started = time.monotonic()
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp/home", "LANG": "C.UTF-8"}
    os.makedirs("/tmp/home", exist_ok=True)
    status: dict[str, object]
    try:
        # Its own process group, so everything it starts is stopped with it at the time limit.
        proc = subprocess.Popen(
            command,
            env=env,
            cwd="/tmp",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            # The sample's own memory cap: an allocation past it fails with ENOMEM
            # instead of the whole sandbox being killed (preexec runs in the child).
            preexec_fn=lambda: resource.setrlimit(
                resource.RLIMIT_AS, (memory_mb << 20, memory_mb << 20)
            ),  # noqa: PLW1509
        )
        try:
            out, err = proc.communicate(timeout=seconds)
            status = {
                "exit": proc.returncode,
                "stdout_bytes": len(out),
                "stderr_tail": err[-300:].decode("utf-8", "replace"),
            }
        except subprocess.TimeoutExpired:
            status = {"exit": None, "timed_out": True}
        finally:
            with contextlib.suppress(OSError):  # already gone
                os.killpg(proc.pid, signal.SIGKILL)
            # Children that left the group can still hold the pipes; don't wait on them.
            for stream in (proc.stdout, proc.stderr):
                if stream:
                    stream.close()
            proc.wait()
    except OSError as exc:
        status = {"exit": None, "error": str(exc)}
    time.sleep(0.2)  # let the last request be recorded
    with lock:
        sys.stdout.write(
            json.dumps(
                {
                    "status": status,
                    "seconds": round(time.monotonic() - started, 2),
                    "events": events,
                }
            )
            + "\n"
        )
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
