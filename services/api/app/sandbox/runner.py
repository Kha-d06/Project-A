"""Runs a file's static inspection in a separate, jailed process.

Two layers, so a parser exploit (pefile, oletools, yara, zip or PDF code
meeting a crafted file) lands somewhere useless:

* always: a fresh child process with no secrets in its environment, no
  inherited file descriptors (so no database or Redis connection), rlimits
  and a seccomp allowlist (policy.py): no network, no new process, no writes;
* `SENTINEL_SANDBOX=nsjail` (hosts that allow namespaces): the same child
  inside nsjail, in its own network, user, PID, IPC, UTS and mount namespaces
  with only read-only binds, a private /tmp and cgroup memory and PID caps.
  The default worker container drops every capability, which nsjail's
  namespaces need, so there the first layer is the one that applies.
"""

import json
import logging
import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.analyzers.types import Check, FindingData, Outcome
from app.core.config import get_settings
from app.sandbox.policy import read_only_roots

logger = logging.getLogger(__name__)

SOURCE = "Qalaa static file inspection"
MEMORY_MB = 512
CPU_SECONDS = 60
WALL_SECONDS = 90
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
EXIT_MEMORY = 3
SAMPLE_IN_JAIL = "/sample"


@dataclass(frozen=True)
class JailResult:
    ok: bool
    outcome: Outcome
    reason: str | None = None


def child_env() -> dict[str, str]:
    """Only what the child needs; never the database URL, secret key or API tokens."""
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
    rules = get_settings().yara_rules_dir
    if rules:
        env["SENTINEL_YARA_RULES_DIR"] = str(rules)
    return env


def child_argv(sample: str, filename: str) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-B",
        "-m",
        "app.sandbox.child",
        sample,
        filename,
        str(MEMORY_MB),
        str(CPU_SECONDS),
    ]


def _read_only_roots() -> list[str]:
    rules = get_settings().yara_rules_dir
    return read_only_roots([str(rules)] if rules else [])


CGROUP_ROOT = Path("/sys/fs/cgroup")


def cgroups_delegated(root: Path = CGROUP_ROOT) -> bool:
    """nsjail can place the child in its own cgroup v2 group only where one is delegated to us."""
    control = root / "cgroup.subtree_control"
    return control.is_file() and os.access(control, os.R_OK | os.W_OK) and os.access(root, os.W_OK)


def nsjail_argv(binary: str, sample: Path, filename: str, cgroups: bool | None = None) -> list[str]:
    # Inside the jail the parser is "nobody"; outside it maps to nobody when root
    # starts nsjail, or to the caller's own (unprivileged) id otherwise.
    outside_uid = 65534 if os.getuid() == 0 else os.getuid()
    outside_gid = 65534 if os.getgid() == 0 else os.getgid()
    argv = [
        binary, "--mode", "o", "--quiet",
        "--user", f"65534:{outside_uid}", "--group", f"65534:{outside_gid}",
        "--hostname", "jail",
        "--time_limit", str(WALL_SECONDS),
        "--rlimit_as", str(MEMORY_MB), "--rlimit_cpu", str(CPU_SECONDS),
        "--rlimit_fsize", "0", "--rlimit_nofile", "64", "--rlimit_nproc", "soft",
        "--disable_proc",
        "--iface_no_lo",
        "--tmpfsmount", "/tmp",  # noqa: S108 - a private, empty tmpfs inside the jail
        "--bindmount_ro", f"{sample}:{SAMPLE_IN_JAIL}",
    ]  # fmt: skip
    if cgroups if cgroups is not None else cgroups_delegated():
        argv += [
            "--use_cgroupv2",
            "--cgroup_mem_max", str(MEMORY_MB * 1024 * 1024),
            "--cgroup_pids_max", "32",
            "--cgroup_cpu_ms_per_sec", "1000",
        ]  # fmt: skip
    else:
        logger.info("No delegated cgroup v2: nsjail relies on rlimits and seccomp for limits")
    for root in _read_only_roots():
        argv += ["--bindmount_ro", root]
    for key, value in child_env().items():
        argv += ["--env", f"{key}={value}"]
    return [*argv, "--", *child_argv(SAMPLE_IN_JAIL, filename)]


def _deserialize(data: dict[str, Any]) -> Outcome:
    outcome = Outcome()
    outcome.findings = [FindingData(**f) for f in data.get("findings", [])]
    for c in data.get("checks", []):
        finished = c.pop("finished_at", None)
        check = Check(**c)
        if finished:
            check.finished_at = datetime.fromisoformat(finished)
        outcome.checks.append(check)
    outcome.details = dict(data.get("details", {}))
    outcome.limitations = list(data.get("limitations", []))
    return outcome


def _reason(returncode: int) -> str:
    if returncode == -signal.SIGSYS:
        return (
            "it tried something the sandbox does not allow (network, new programs or writing files)"
        )
    if returncode in (-signal.SIGKILL, -signal.SIGXCPU):
        return f"it reached the {CPU_SECONDS}-second processing limit"
    if returncode == EXIT_MEMORY:
        return f"it needed more than {MEMORY_MB} MB of memory"
    return f"the inspection stopped unexpectedly (code {returncode})"


def run_static_inspection(path: Path, filename: str) -> JailResult:
    mode = os.environ.get("SENTINEL_SANDBOX", "seccomp")
    binary = shutil.which("nsjail") if mode == "nsjail" else None
    if mode == "nsjail" and not binary:
        logger.warning(
            "SENTINEL_SANDBOX=nsjail but nsjail is not installed; using the seccomp jail"
        )
    argv = nsjail_argv(binary, path, filename) if binary else child_argv(str(path), filename)
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            env=child_env(),
            close_fds=True,
            cwd="/",
            timeout=WALL_SECONDS + 10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return JailResult(False, Outcome(), f"it took longer than {WALL_SECONDS} seconds")
    if proc.returncode != 0 or len(proc.stdout) > MAX_OUTPUT_BYTES:
        reason = _reason(proc.returncode)
        logger.warning(
            "Static inspection jail stopped: %s (stderr: %s)", reason, proc.stderr[-500:]
        )
        return JailResult(False, Outcome(), reason)
    if b"Landlock unavailable" in proc.stderr:
        logger.warning("Parser jail ran without Landlock: other uploads are readable to it")
    try:
        return JailResult(True, _deserialize(json.loads(proc.stdout)))
    except (ValueError, TypeError) as exc:
        return JailResult(False, Outcome(), f"its result could not be read ({exc})")


def merge_into(outcome: Outcome, result: JailResult) -> None:
    if result.ok:
        outcome.findings += result.outcome.findings
        outcome.checks += result.outcome.checks
        outcome.details.update(result.outcome.details)
        outcome.limitations += result.outcome.limitations
        return
    outcome.checks.append(
        Check(
            "static_inspection",
            "Structure and embedded content",
            SOURCE,
            "failed",
            f"The isolated inspection was stopped: {result.reason}. No result from it is shown.",
        )
    )
    outcome.limitations.append(
        "The file's structure could not be inspected, so this result relies on its fingerprint "
        "and name only."
    )
