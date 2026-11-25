# ruff: noqa: E501, S108, S603 - /tmp here is the sandbox's own tmpfs; long lines are user-facing sentences.
"""Runs an uploaded Linux program or script in gVisor and reports what it did.

Only on request (the person ticks "run it in the sandbox") and only for Linux
ELF programs and shell, Python and Perl scripts. Windows programs aren't run
(no Windows sandbox, by design).

The sandbox (runsc, gVisor's user-space kernel):
* `--network=none`: only loopback exists. Inside, a fake DNS server answers
  every name with 127.0.0.1 and a fake web server answers every request, so
  a downloader shows where it would go without reaching anything (sink.py).
* a read-only root file system; only /tmp is writable (a small tmpfs);
* memory, process-count and CPU limits from the OCI config, plus a hard wall
  clock timeout after which the sandbox is killed;
* gVisor's own syscall trace (`--strace`, written outside the sandbox) shows
  programs started, files opened for writing, connections and deletions.

What runs isn't trusted with anything: no secrets, no network, no host files
beyond the read-only root. Findings are behaviours seen, never "known
malware" on their own.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analyzers.types import Check, FindingData, Outcome

logger = logging.getLogger(__name__)
SOURCE = "Qalaa sandbox run (gVisor)"
SINK = Path(__file__).with_name("sink.py")
TRACED = "execve,execveat,openat,connect,unlinkat,unlink,ptrace,chmod,fchmodat"

INTERPRETERS: dict[str, list[str]] = {
    "elf": [],
    "sh": ["/bin/sh"],
    "python": ["/usr/bin/python3"],
    "perl": ["/usr/bin/perl"],
}


@dataclass(frozen=True)
class DetonationLimits:
    seconds: int = 30
    memory_mb: int = 256
    pids: int = 64
    tmp_mb: int = 32


@dataclass
class Trace:
    executed: list[dict[str, Any]] = field(default_factory=list)
    writes: list[dict[str, Any]] = field(default_factory=list)
    connects: list[dict[str, Any]] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    ptrace_self: bool = False
    chmod_exec: list[str] = field(default_factory=list)


@dataclass
class DetonationResult:
    ok: bool
    reason: str | None = None
    trace: Trace = field(default_factory=Trace)
    sink: dict[str, Any] = field(default_factory=dict)


def kind_for(detected_key: str, filename: str, head: bytes) -> str | None:
    """Which interpreter runs the sample, or None when it isn't run here."""
    if detected_key == "elf":
        return "elf"
    first = head.split(b"\n", 1)[0]
    lower = filename.lower()
    if first.startswith(b"#!"):
        if b"python" in first:
            return "python"
        if b"perl" in first:
            return "perl"
        if re.search(rb"\b(ba|da|z)?sh\b", first):
            return "sh"
    if lower.endswith(".sh"):
        return "sh"
    if lower.endswith(".py"):
        return "python"
    if lower.endswith(".pl"):
        return "perl"
    return None


def oci_config(kind: str, limits: DetonationLimits, rootfs: str, bundle: Path) -> dict[str, Any]:
    args = [
        "/usr/bin/python3",
        "-I",
        "-S",
        "/qalaa/sink.py",
        str(limits.seconds),
        *INTERPRETERS[kind],
        "/sample/run",
    ]
    ro_bind = ["bind", "ro", "nosuid", "nodev"]
    return {
        "ociVersion": "1.0.0",
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0},
            "args": args,
            "env": ["PATH=/usr/local/bin:/usr/bin:/bin"],
            "cwd": "/tmp",
            "noNewPrivileges": True,
            "rlimits": [
                {"type": "RLIMIT_NOFILE", "hard": 256, "soft": 256},
                {"type": "RLIMIT_CORE", "hard": 0, "soft": 0},
            ],
        },
        "root": {"path": rootfs, "readonly": True},
        "hostname": "workstation",
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "mode=755", "size=1m"],
            },
            {
                "destination": "/tmp",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "nodev", f"size={limits.tmp_mb}m", "mode=1777"],
            },
            {
                "destination": "/sample",
                "type": "bind",
                "source": str(bundle / "sample"),
                "options": ro_bind,
            },
            {
                "destination": "/qalaa",
                "type": "bind",
                "source": str(bundle / "qalaa"),
                "options": ro_bind,
            },
            {
                "destination": "/etc/resolv.conf",
                "type": "bind",
                "source": str(bundle / "resolv.conf"),
                "options": ro_bind,
            },
            {
                "destination": "/etc/hosts",
                "type": "bind",
                "source": str(bundle / "hosts"),
                "options": ro_bind,
            },
        ],
        "linux": {
            "namespaces": [{"type": t} for t in ("pid", "network", "ipc", "uts", "mount")],
            "resources": {
                "memory": {"limit": limits.memory_mb * 1024 * 1024},
                "pids": {"limit": limits.pids},
                "cpu": {"quota": 100000, "period": 100000},
            },
        },
    }


def prepare_bundle(
    work: Path, sample: Path, kind: str, limits: DetonationLimits, rootfs: str
) -> Path:
    bundle = work / "bundle"
    (bundle / "sample").mkdir(parents=True)
    (bundle / "qalaa").mkdir()
    target = bundle / "sample" / "run"
    shutil.copyfile(sample, target)
    target.chmod(0o755)
    shutil.copyfile(SINK, bundle / "qalaa" / "sink.py")
    (bundle / "resolv.conf").write_text("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
    (bundle / "hosts").write_text("127.0.0.1 localhost workstation\n")
    (bundle / "config.json").write_text(json.dumps(oci_config(kind, limits, rootfs, bundle)))
    return bundle


def runsc_argv(
    runsc: str, bundle: Path, logs: Path, container: str, platform: str = "systrap"
) -> list[str]:
    return [
        runsc,
        "--network=none",
        f"--platform={platform}",
        "--strace",
        f"--strace-syscalls={TRACED}",
        "--strace-log-size=512",
        f"--debug-log={logs}/",
        "run",
        "--bundle",
        str(bundle),
        container,
    ]


# --- gVisor strace lines -------------------------------------------------------------
# I1125 13:53:28.665532  1 strace.go:606] [   2:   2] sh X execve(0x55.. /usr/bin/cat, 0x55.. ["cat", "/etc/hostname"], ...) = 0 (0x0) (5µs)
_LINE = re.compile(r"\]\s+\[\s*(\d+):\s*(\d+)\]\s+(\S+)\s+X\s+(\w+)\((.*)\)\s+=\s+(-?\d+)")
_PATH_ARG = re.compile(r"0x[0-9a-f]+ ([^,\s)]+)")
_ARGV = re.compile(r'\[((?:"(?:[^"\\]|\\.)*",?\s*)*)\]')
_INET = re.compile(r"Addr: ([0-9a-fA-F.:]+), Port: (\d+)")
_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")


def parse_strace(text: str, limit: int = 300) -> Trace:
    trace = Trace()
    for line in text.splitlines():
        m = _LINE.search(line)
        if not m:
            continue
        _tid, _pid, comm, call, args, ret = m.groups()
        ok = int(ret) >= 0
        if call in ("execve", "execveat") and len(trace.executed) < limit:
            path = _PATH_ARG.search(args)
            argv_m = _ARGV.search(args)
            argv = re.findall(r'"((?:[^"\\]|\\.)*)"', argv_m.group(1)) if argv_m else []
            trace.executed.append(
                {"path": path.group(1) if path else "", "argv": argv[:12], "ok": ok, "by": comm}
            )
        elif (
            call == "openat" and any(f in args for f in _WRITE_FLAGS) and len(trace.writes) < limit
        ):
            path = _PATH_ARG.search(args.split(",", 1)[1] if "," in args else args)
            trace.writes.append({"path": path.group(1) if path else "", "ok": ok, "by": comm})
        elif call == "connect" and len(trace.connects) < limit:
            inet = _INET.search(args)
            if inet:
                trace.connects.append(
                    {"addr": inet.group(1), "port": int(inet.group(2)), "ok": ok, "by": comm}
                )
        elif call in ("unlinkat", "unlink"):
            path = _PATH_ARG.search(
                args.split(",", 1)[1] if call == "unlinkat" and "," in args else args
            )
            if path and len(trace.deleted) < limit:
                trace.deleted.append(path.group(1))
        elif call == "ptrace" and "PTRACE_TRACEME" in args:
            trace.ptrace_self = True
        elif call in ("chmod", "fchmodat") and re.search(r"0o[0-7]*[1357]\b", args):
            path = _PATH_ARG.search(args)
            if path:
                trace.chmod_exec.append(path.group(1))
    return trace


def run_detonation(
    sample: Path,
    kind: str,
    runsc: str,
    rootfs: str,
    limits: DetonationLimits | None = None,
    platform: str = "systrap",
) -> DetonationResult:
    limits = limits or DetonationLimits()
    container = f"qalaa-{uuid.uuid4().hex[:16]}"
    with tempfile.TemporaryDirectory(prefix="qalaa-detonate-") as tmp:
        work = Path(tmp)
        bundle = prepare_bundle(work, sample, kind, limits, rootfs)
        logs = work / "logs"
        logs.mkdir()
        argv = runsc_argv(runsc, bundle, logs, container, platform)
        try:
            proc = subprocess.run(
                argv, capture_output=True, timeout=limits.seconds + 20, check=False
            )  # noqa: S603
        except subprocess.TimeoutExpired:
            subprocess.run(
                [runsc, "delete", "--force", container],
                capture_output=True,
                timeout=20,
                check=False,
            )  # noqa: S603
            return DetonationResult(False, "the sandbox didn't stop in time and was killed")
        finally:
            subprocess.run(
                [runsc, "delete", "--force", container],
                capture_output=True,
                timeout=20,
                check=False,
            )  # noqa: S603
        strace = "\n".join(p.read_text(errors="replace") for p in logs.glob("*boot*"))
        trace = parse_strace(strace)
        sink: dict[str, Any] = {}
        for line in proc.stdout.decode("utf-8", "replace").splitlines()[::-1]:
            if line.startswith("{"):
                try:
                    sink = json.loads(line)
                    break
                except ValueError:
                    continue
        if not sink:
            tail = proc.stderr.decode("utf-8", "replace")[-300:]
            return DetonationResult(
                False, f"the sandbox didn't start ({tail.strip() or proc.returncode})", trace
            )
        return DetonationResult(True, None, trace, sink)


# --- What it means ---------------------------------------------------------------------

_DOWNLOADERS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ftp", "tftp", "busybox"}
_PERSISTENCE_CMDS = {
    "crontab",
    "systemctl",
    "useradd",
    "usermod",
    "chattr",
    "update-rc.d",
    "insmod",
    "modprobe",
}
_PERSISTENCE_PATHS = (
    "/etc/cron",
    "/var/spool/cron",
    "/etc/systemd/",
    "/lib/systemd/",
    "/etc/init.d/",
    "/etc/rc.local",
    "/etc/profile",
    "/etc/ld.so.preload",
    ".bashrc",
    ".profile",
    ".bash_profile",
    ".zshrc",
    "authorized_keys",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
)


def _name(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def findings_for(result: DetonationResult) -> list[FindingData]:
    out: list[FindingData] = []
    t, events = result.trace, result.sink.get("events", [])
    names = sorted({str(e["name"]) for e in events if e.get("kind") == "dns" and e.get("name")})[
        :20
    ]
    if names:
        out.append(
            FindingData(
                "medium",
                "network",
                "Tries to reach internet addresses",
                "While it ran it looked up these names. Nothing was reached: the sandbox has no internet and a stand-in answered.",
                SOURCE,
                {"names": names},
            )
        )
    http = [e for e in events if e.get("kind") == "http"][:20]
    if http:
        fetches = [f"{e.get('method')} {e.get('host')}{e.get('path')}" for e in http]
        code = any(
            re.search(r"\.(sh|bin|elf|py|pl|x86|arm\w*|mips\w*)(\?|$)", str(e.get("path", "")))
            for e in http
        )
        out.append(
            FindingData(
                "high" if code else "medium",
                "network",
                "Downloads more code from the internet"
                if code
                else "Sends or fetches data over the web",
                "It made these web requests; a stand-in server answered with nothing. Downloading further programs is how droppers and botnets install themselves.",
                SOURCE,
                {"requests": fetches},
            )
        )
    direct = sorted(
        {
            f"{c['addr']}:{c['port']}"
            for c in t.connects
            if not str(c["addr"]).startswith(("127.", "::1", "0.0.0.0"))  # noqa: S104 - a filter, not a bind
        }
    )[:20]
    if direct:
        out.append(
            FindingData(
                "medium",
                "network",
                "Connects straight to IP addresses",
                "It tried to connect to addresses without looking up a name first, as command-and-control malware often does. The sandbox had no network, so nothing was reached.",
                SOURCE,
                {"addresses": direct},
            )
        )
    started = [e for e in t.executed[1:] if e["path"] and not e["path"].endswith("/sample/run")]
    tools = sorted({_name(e["path"]) for e in started if _name(e["path"]) in _DOWNLOADERS})
    if tools:
        out.append(
            FindingData(
                "medium",
                "capability",
                "Starts download or network tools",
                "It ran tools that fetch files or open network connections.",
                SOURCE,
                {"programs": tools},
            )
        )
    persist_cmds = sorted(
        {_name(e["path"]) for e in started if _name(e["path"]) in _PERSISTENCE_CMDS}
    )
    persist_files = sorted(
        {w["path"] for w in t.writes if any(p in w["path"] for p in _PERSISTENCE_PATHS)}
    )[:10]
    if persist_cmds or persist_files:
        out.append(
            FindingData(
                "high",
                "persistence",
                "Tries to make itself start again or keep access",
                "It tried to change start-up, scheduled-task, account or SSH-key settings. The sandbox's system files are read-only, so the change didn't happen.",
                SOURCE,
                {"programs": persist_cmds, "files": persist_files},
            )
        )
    if any(d.endswith("/sample/run") for d in t.deleted):
        out.append(
            FindingData(
                "medium",
                "evasion",
                "Deletes itself after it runs",
                "Removing its own file after starting is a common way to hide from later inspection.",
                SOURCE,
            )
        )
    if t.ptrace_self:
        out.append(
            FindingData(
                "low",
                "evasion",
                "Checks whether it is being watched",
                "It used ptrace on itself, a common check for debuggers. Some legitimate software does this too.",
                SOURCE,
            )
        )
    dropped = sorted({p for p in t.chmod_exec if p.startswith("/tmp/")})[:10]
    if dropped:
        out.append(
            FindingData(
                "medium",
                "capability",
                "Writes a program to disk and makes it runnable",
                "It created a file in a temporary folder and marked it executable, the usual first step of a dropper.",
                SOURCE,
                {"files": dropped},
            )
        )
    return out


def merge_detonation(outcome: Outcome, result: DetonationResult, limits: DetonationLimits) -> None:
    label = "Run in an isolated sandbox"
    if not result.ok:
        outcome.checks.append(
            Check(
                "detonation",
                label,
                SOURCE,
                "failed",
                f"The sandbox run didn't complete: {result.reason}.",
            )
        )
        return
    status = result.sink.get("status", {})
    ran = (
        "stopped after the time limit"
        if status.get("timed_out")
        else f"ran for {result.sink.get('seconds', '?')} s"
    )
    outcome.findings += findings_for(result)
    outcome.details["detonation"] = {
        "programs_started": len(result.trace.executed),
        "files_written": len(result.trace.writes),
        "network_events": len(result.sink.get("events", [])),
        "exit": status.get("exit"),
        "timed_out": bool(status.get("timed_out")),
    }
    outcome.checks.append(
        Check(
            "detonation",
            label,
            SOURCE,
            "completed",
            f"The file {ran} in a gVisor sandbox with no internet, a read-only system and "
            f"{limits.memory_mb} MB of memory; what it tried to do is listed above.",
        )
    )
    outcome.limitations.append(
        f"The sandbox run lasted at most {limits.seconds} seconds with no real internet. Malware that waits, "
        "checks for a real network or user, or targets Windows can stay quiet here, so a clean run isn't proof."
    )
