#!/usr/bin/env python3
"""Qalaa on-access scanning helper (Linux, fanotify).

This is the small privileged half of Qalaa's on-access protection. It uses the
kernel's fanotify interface — a user-space API, NOT a kernel module — to receive
a permission event every time a file is opened under the watched paths. For each
event it asks the user's Qalaa app for a verdict over a local socket and then
tells the kernel to allow or deny the open.

It never scans, quarantines or deletes anything itself: all it does is relay a
path to Qalaa and enforce the answer. If Qalaa is not running, or is slow, it
ALLOWS the open (fails open) so the machine can never freeze.

Run as root (normally via the systemd unit Qalaa installs):
    qalaa-onaccessd.py --socket /run/qalaa/onaccess.sock --user alice --mark /home

Stdlib only; no third-party packages.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import socket
import struct
import sys
import time

# fanotify_init flags
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_CLASS_CONTENT = 0x00000004
# fanotify_mark flags
FAN_MARK_ADD = 0x00000001
FAN_MARK_MOUNT = 0x00000010
# events
FAN_OPEN_PERM = 0x00010000
# responses
FAN_ALLOW = 0x01
FAN_DENY = 0x02
# open flags for the event fds
O_RDONLY = 0x00000000
O_LARGEFILE = 0x00008000

METADATA_VERSION = 3
# struct fanotify_event_metadata: __u32 event_len, __u8 vers, __u8 reserved,
# __u16 metadata_len, __aligned_u64 mask, __s32 fd, __s32 pid
METADATA_FMT = "<IBBHQii"
METADATA_LEN = struct.calcsize(METADATA_FMT)  # 24
# struct fanotify_response: __s32 fd, __u32 response
RESPONSE_FMT = "<iI"


class Event:
    __slots__ = ("event_len", "vers", "mask", "fd", "pid")

    def __init__(self, event_len: int, vers: int, mask: int, fd: int, pid: int) -> None:
        self.event_len = event_len
        self.vers = vers
        self.mask = mask
        self.fd = fd
        self.pid = pid


def parse_event(buf: bytes) -> Event | None:
    """Parse one fanotify_event_metadata from the front of buf."""
    if len(buf) < METADATA_LEN:
        return None
    event_len, vers, _reserved, _meta_len, mask, fd, pid = struct.unpack(METADATA_FMT, buf[:METADATA_LEN])
    return Event(event_len, vers, mask, fd, pid)


def response_bytes(fd: int, allow: bool) -> bytes:
    return struct.pack(RESPONSE_FMT, fd, FAN_ALLOW if allow else FAN_DENY)


class VerdictCache:
    """Remembers a verdict per (path, mtime) for a short while, to avoid asking
    Qalaa about the same unchanged file over and over."""

    def __init__(self, ttl: float = 30.0) -> None:
        self.ttl = ttl
        self._store: dict[tuple[str, int], tuple[bool, float]] = {}

    def get(self, path: str, mtime: int, now: float | None = None) -> bool | None:
        now = time.time() if now is None else now
        hit = self._store.get((path, mtime))
        if hit and now - hit[1] < self.ttl:
            return hit[0]
        return None

    def put(self, path: str, mtime: int, allow: bool, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._store[(path, mtime)] = (allow, now)


def ask_qalaa(sock_path: str, path: str, request_id: int, timeout: float = 4.0) -> bool:
    """Ask the Qalaa app for a verdict. Returns True to allow. Fails open."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(sock_path)
            client.sendall((f'{{"id":{request_id},"path":{_json_str(path)}}}\n').encode("utf-8"))
            data = b""
            while b"\n" not in data:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
            line = data.split(b"\n", 1)[0].decode("utf-8", "replace")
            return '"verdict":"deny"' not in line  # anything but an explicit deny allows
    except (OSError, socket.timeout):
        return True  # Qalaa not reachable: never block


def _json_str(value: str) -> str:
    # Minimal JSON string escaping (stdlib json would also work; kept explicit).
    out = value.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{out}"'


def _load_libc() -> ctypes.CDLL:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    return libc


def run(socket_path: str, user: str, marks: list[str]) -> int:
    if os.geteuid() != 0:
        sys.stderr.write("qalaa-onaccessd must run as root to use fanotify.\n")
        return 2
    libc = _load_libc()
    fan_fd = libc.fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE)
    if fan_fd < 0:
        err = ctypes.get_errno()
        sys.stderr.write(f"fanotify_init failed: {os.strerror(err)}\n")
        return 3
    for mark in marks:
        rc = libc.fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN_PERM, -100, mark.encode())
        if rc < 0:
            err = ctypes.get_errno()
            sys.stderr.write(f"fanotify_mark({mark}) failed: {os.strerror(err)}\n")
    cache = VerdictCache()
    poll = __import__("select").poll()
    poll.register(fan_fd, __import__("select").POLLIN)
    sys.stderr.write(f"qalaa-onaccessd watching {', '.join(marks)} for user {user}\n")
    while True:
        if not poll.poll(1000):
            continue
        try:
            buf = os.read(fan_fd, 4096)
        except BlockingIOError:
            continue
        except OSError:
            break
        offset = 0
        while offset + METADATA_LEN <= len(buf):
            event = parse_event(buf[offset:])
            if event is None or event.vers != METADATA_VERSION:
                break
            offset += event.event_len
            if event.fd < 0:
                continue
            try:
                path = os.readlink(f"/proc/self/fd/{event.fd}")
                try:
                    mtime = int(os.fstat(event.fd).st_mtime)
                except OSError:
                    mtime = 0
                allow = cache.get(path, mtime)
                if allow is None:
                    allow = ask_qalaa(socket_path, path, event.fd)
                    cache.put(path, mtime, allow)
                os.write(fan_fd, response_bytes(event.fd, allow))
            finally:
                try:
                    os.close(event.fd)
                except OSError:
                    pass
    return 0


def selftest() -> int:
    """Exercise the pure logic without needing root or fanotify, for CI."""
    # Round-trip an event through the metadata struct.
    raw = struct.pack(METADATA_FMT, METADATA_LEN, METADATA_VERSION, 0, METADATA_LEN, FAN_OPEN_PERM, 7, 123)
    event = parse_event(raw)
    assert event is not None and event.fd == 7 and event.pid == 123 and event.vers == METADATA_VERSION
    assert parse_event(b"\x00") is None
    # Responses.
    assert response_bytes(7, True) == struct.pack(RESPONSE_FMT, 7, FAN_ALLOW)
    assert response_bytes(7, False) == struct.pack(RESPONSE_FMT, 7, FAN_DENY)
    # Verdict cache honours TTL and the mtime key.
    cache = VerdictCache(ttl=10)
    cache.put("/x", 100, False, now=1000.0)
    assert cache.get("/x", 100, now=1005.0) is False
    assert cache.get("/x", 100, now=1020.0) is None  # expired
    assert cache.get("/x", 101, now=1005.0) is None  # file changed
    # JSON string escaping.
    assert _json_str('a"b\\c') == '"a\\"b\\\\c"'
    print("selftest ok")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Qalaa on-access scanning helper")
    parser.add_argument("--socket", default="/run/qalaa/onaccess.sock")
    parser.add_argument("--user", default="")
    parser.add_argument("--mark", action="append", default=[], dest="marks")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()
    marks = args.marks or ["/home"]
    return run(args.socket, args.user, marks)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
