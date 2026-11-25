#!/usr/bin/env python3
"""Qalaa process-start helper (Linux, root).

Subscribes to the kernel's process connector (netlink, NETLINK_CONNECTOR /
CN_IDX_PROC), so every program start is seen however short it runs, and
streams each one to the person's Qalaa service as one JSON line:

    {"pid": 123, "ppid": 45, "image": "/usr/bin/curl", "commandLine": "curl ...",
     "parentImage": "/usr/bin/bash", "parentCommandLine": "bash"}

Run as a systemd service, installed once with pkexec:

    qalaa-procwatchd.py --socket /run/user/1000/qalaa/proc.sock

It only reports. It never blocks, pauses or changes anything, and if the
service isn't listening, events are dropped (nothing waits on them). Program
paths and command lines are what /proc already shows every user on most
systems; the helper adds only that it sees every start. At most
MAX_EVENTS_PER_SECOND are forwarded.

Netlink layout (linux/connector.h, linux/cn_proc.h): nlmsghdr (16 bytes),
cn_msg (20 bytes), then proc_event: what, cpu, timestamp, and for an exec
event the pid and tgid. Pure Python, no dependencies.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import time

NETLINK_CONNECTOR = 11
CN_IDX_PROC = 1
CN_VAL_PROC = 1
PROC_CN_MCAST_LISTEN = 1
PROC_EVENT_EXEC = 0x00000002
NLMSG_DONE = 3

NLMSGHDR = struct.Struct("=IHHII")  # len, type, flags, seq, pid
CN_MSG = struct.Struct("=IIIIHH")  # idx, val, seq, ack, len, flags
PROC_EVENT_HEAD = struct.Struct("=IIQ")  # what, cpu, timestamp_ns
EXEC_EVENT = struct.Struct("=II")  # process_pid, process_tgid

MAX_EVENTS_PER_SECOND = 500
MAX_CMDLINE = 4096


def subscribe_message(pid: int) -> bytes:
    op = struct.pack("=I", PROC_CN_MCAST_LISTEN)
    cn = CN_MSG.pack(CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(op), 0) + op
    return NLMSGHDR.pack(NLMSGHDR.size + len(cn), NLMSG_DONE, 0, 0, pid) + cn


def exec_tgids(datagram: bytes) -> list[int]:
    """The process ids (tgid) of exec events in one netlink datagram."""
    out: list[int] = []
    offset = 0
    while offset + NLMSGHDR.size <= len(datagram):
        length, _type, _flags, _seq, _pid = NLMSGHDR.unpack_from(datagram, offset)
        if length < NLMSGHDR.size or offset + length > len(datagram):
            break
        body = offset + NLMSGHDR.size
        if body + CN_MSG.size + PROC_EVENT_HEAD.size <= offset + length:
            idx, val, *_rest = CN_MSG.unpack_from(datagram, body)
            ev = body + CN_MSG.size
            what, _cpu, _ts = PROC_EVENT_HEAD.unpack_from(datagram, ev)
            data = ev + PROC_EVENT_HEAD.size
            if (idx, val) == (CN_IDX_PROC, CN_VAL_PROC) and what == PROC_EVENT_EXEC and data + EXEC_EVENT.size <= offset + length:
                _pid, tgid = EXEC_EVENT.unpack_from(datagram, data)
                out.append(tgid)
        offset += (length + 3) & ~3  # NLMSG_ALIGN
    return out


def read_process(pid: int, proc: str = "/proc") -> dict[str, object] | None:
    try:
        with open(f"{proc}/{pid}/cmdline", "rb") as f:
            argv = [a.decode("utf-8", "replace") for a in f.read(MAX_CMDLINE).split(b"\0") if a]
        with open(f"{proc}/{pid}/stat", "rb") as f:
            stat = f.read().decode("utf-8", "replace")
    except OSError:
        return None  # already gone
    close = stat.rfind(")")
    fields = stat[close + 2 :].split(" ") if close >= 0 else []
    ppid = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else 0
    try:
        image = os.readlink(f"{proc}/{pid}/exe").removesuffix(" (deleted)")
    except OSError:
        image = argv[0] if argv else ""
    return {"pid": pid, "ppid": ppid, "image": image, "commandLine": " ".join(argv)}


def event_for(pid: int, proc: str = "/proc") -> dict[str, object] | None:
    child = read_process(pid, proc)
    if child is None or not child["commandLine"]:
        return None
    parent = read_process(int(child["ppid"]), proc) if child["ppid"] else None
    child["parentImage"] = parent["image"] if parent else ""
    child["parentCommandLine"] = parent["commandLine"] if parent else ""
    return child


class Forwarder:
    """Keeps one connection to the service; drops events while it's away."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.sock: socket.socket | None = None
        self.retry_at = 0.0
        self.window = int(time.monotonic())
        self.sent = 0

    def send(self, event: dict[str, object]) -> bool:
        now = time.monotonic()
        if int(now) != self.window:
            self.window, self.sent = int(now), 0
        if self.sent >= MAX_EVENTS_PER_SECOND:
            return False
        if self.sock is None:
            if now < self.retry_at:
                return False
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect(self.path)
                self.sock = s
            except OSError:
                self.retry_at = now + 5
                return False
        try:
            self.sock.sendall((json.dumps(event, separators=(",", ":")) + "\n").encode())
            self.sent += 1
            return True
        except OSError:
            self.sock.close()
            self.sock = None
            return False


def run(socket_path: str) -> int:
    if os.geteuid() != 0:
        sys.stderr.write("qalaa-procwatchd must run as root to use the process connector.\n")
        return 1
    nl = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
    nl.bind((os.getpid(), CN_IDX_PROC))
    nl.send(subscribe_message(os.getpid()))
    sys.stderr.write("qalaa-procwatchd: watching program starts\n")
    out = Forwarder(socket_path)
    while True:
        try:
            datagram = nl.recv(65536)
        except InterruptedError:
            continue
        for tgid in exec_tgids(datagram):
            event = event_for(tgid)
            if event is not None and event["pid"] != os.getpid():
                out.send(event)


def selftest() -> int:
    """The pure parts, without root or netlink, for CI."""
    sub = subscribe_message(42)
    length, kind, _f, _s, pid = NLMSGHDR.unpack_from(sub)
    assert length == len(sub) == 16 + 20 + 4 and kind == NLMSG_DONE and pid == 42
    idx, val, _seq, _ack, op_len, _fl = CN_MSG.unpack_from(sub, 16)
    assert (idx, val, op_len) == (CN_IDX_PROC, CN_VAL_PROC, 4)

    def message(what: int, tgid: int) -> bytes:
        ev = PROC_EVENT_HEAD.pack(what, 0, 123) + EXEC_EVENT.pack(tgid, tgid)
        cn = CN_MSG.pack(CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(ev), 0) + ev
        raw = NLMSGHDR.pack(16 + len(cn), NLMSG_DONE, 0, 0, 0) + cn
        return raw + b"\0" * (((len(raw) + 3) & ~3) - len(raw))

    assert exec_tgids(message(PROC_EVENT_EXEC, 1234) + message(0x1, 99) + message(PROC_EVENT_EXEC, 77)) == [1234, 77]
    assert exec_tgids(b"\x05") == []
    assert exec_tgids(NLMSGHDR.pack(9999, 0, 0, 0, 0)) == []  # claims more than it has
    me = event_for(os.getpid())
    assert me is not None and me["pid"] == os.getpid() and "selftest" in str(me["commandLine"])
    assert event_for(2**22 + 12345) is None
    print("selftest ok")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Qalaa process-start helper")
    parser.add_argument("--socket", default="/run/qalaa/proc.sock")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    return selftest() if args.selftest else run(args.socket)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
