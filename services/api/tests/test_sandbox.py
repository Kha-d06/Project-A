"""The parser jail: what a hostile file's parser can and can't do (P0-3).

Each probe runs tests/sandbox_probe.py in a fresh interpreter, enters the same
jail the file inspection uses, then tries one thing.
"""

import ctypes
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from app.analyzers.types import Outcome
from app.sandbox import runner
from app.sandbox.policy import landlock_abi

PROBE = Path(__file__).with_name("sandbox_probe.py")
KILLED_BY_SECCOMP = -signal.SIGSYS
DENIED = 4
OUT_OF_MEMORY = 3

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux jail")


def probe(action: str, tmp_path: Path, cpu: int = 60, memory_mb: int = 512) -> int:
    sample = tmp_path / "sample.bin"
    other = tmp_path / "someone-elses-upload.bin"
    sample.write_bytes(b"MZ sample")
    other.write_bytes(b"private")
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            "-B",
            str(PROBE),
            action,
            str(cpu),
            str(memory_mb),
            str(sample),
            str(other),
        ],
        capture_output=True,
        timeout=60,
        cwd="/",
        check=False,
    )
    return result.returncode


@pytest.mark.parametrize("action", ["read", "read_sample", "thread"])
def test_what_a_parser_needs_still_works(action: str, tmp_path: Path) -> None:
    assert probe(action, tmp_path) == 0


@pytest.mark.parametrize("action", ["socket", "unix", "fork", "exec", "subprocess", "write"])
def test_network_new_processes_and_writes_are_fatal(action: str, tmp_path: Path) -> None:
    assert probe(action, tmp_path) == KILLED_BY_SECCOMP


def test_memory_is_capped(tmp_path: Path) -> None:
    assert probe("memory", tmp_path, memory_mb=256) == OUT_OF_MEMORY


def test_cpu_time_is_capped(tmp_path: Path) -> None:
    assert probe("cpu", tmp_path, cpu=1) in (-signal.SIGKILL, -signal.SIGXCPU)


@pytest.mark.skipif(landlock_abi() == 0, reason="this kernel has no Landlock")
def test_other_uploads_and_the_workers_environment_are_unreadable(tmp_path: Path) -> None:
    assert probe("landlock", tmp_path) == 0
    assert probe("read_other", tmp_path) == DENIED
    assert probe("parent_environ", tmp_path) == DENIED


def test_the_child_gets_no_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "SENTINEL_SECRET_KEY",
        "SENTINEL_DATABASE_URL",
        "SENTINEL_VIRUSTOTAL_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
    ):
        monkeypatch.setenv(name, "do-not-leak")
    env = runner.child_env()
    assert "do-not-leak" not in "".join(env.values())
    assert set(env) <= {"PATH", "LANG", "PYTHONDONTWRITEBYTECODE", "SENTINEL_YARA_RULES_DIR"}


def test_a_real_inspection_runs_in_the_jail(tmp_path: Path) -> None:
    sample = tmp_path / "eicar.txt"
    sample.write_bytes(rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    result = runner.run_static_inspection(sample, "eicar.txt")
    assert result.ok, result.reason
    assert any(f.category == "known_signature" for f in result.outcome.findings)
    assert {c.key for c in result.outcome.checks} >= {"static_inspection", "yara"}


def test_a_stopped_inspection_is_reported_not_trusted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sample = tmp_path / "x.bin"
    sample.write_bytes(b"x")
    # Stand in a "parser" that opens a socket: the jail must stop it and the scan must say so.
    monkeypatch.setattr(
        runner,
        "child_argv",
        lambda s, f: [sys.executable, "-I", "-B", str(PROBE), "socket", "60", "512", s, s],
    )
    result = runner.run_static_inspection(sample, "x.bin")
    assert not result.ok
    assert result.reason and "sandbox does not allow" in result.reason
    outcome = Outcome()
    runner.merge_into(outcome, result)
    check = next(c for c in outcome.checks if c.key == "static_inspection")
    assert check.status == "failed"
    assert outcome.findings == []
    assert outcome.limitations


def test_nsjail_command_isolates_everything(tmp_path: Path) -> None:
    argv = runner.nsjail_argv("/usr/bin/nsjail", tmp_path / "sample.bin", "a.exe", cgroups=True)
    joined = " ".join(argv)
    assert argv[0] == "/usr/bin/nsjail"
    # Its own network namespace is nsjail's default: nothing must turn it off.
    assert "--disable_clone_newnet" not in argv and "-N" not in argv
    outside = 65534 if os.getuid() == 0 else os.getuid()
    assert f"--user 65534:{outside}" in joined, "never mapped to root outside the jail"
    assert f"--bindmount_ro {tmp_path / 'sample.bin'}:/sample" in joined
    assert "--rlimit_fsize 0" in joined and "--cgroup_pids_max 32" in joined
    assert "--disable_proc" in argv
    assert "--use_cgroupv2" not in runner.nsjail_argv("/x", tmp_path / "s", "a", cgroups=False)
    assert not any(a.startswith("--bindmount ") or a == "--bindmount" for a in argv), (
        "no writable binds"
    )
    assert argv[argv.index("--") + 1 :][:5] == [
        sys.executable,
        "-I",
        "-B",
        "-m",
        "app.sandbox.child",
    ]
    assert "/sample" in argv[argv.index("--") :]


def test_worker_processes_are_not_dumpable() -> None:
    code = (
        "import ctypes; from app.sandbox.policy import make_undumpable; make_undumpable(); "
        "print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))"
    )
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "0"


@pytest.mark.skipif(
    not os.environ.get("QALAA_TEST_NSJAIL"), reason="set QALAA_TEST_NSJAIL=1 where nsjail can run"
)
def test_inspection_inside_real_nsjail(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SENTINEL_SANDBOX", "nsjail")
    # Started as root, the jail maps to "nobody", which must be able to reach the
    # sample (the worker runs as its own user and owns its uploads folder).
    folder = Path(tempfile.mkdtemp(prefix="qalaa-nsjail-", dir="/tmp"))  # noqa: S108
    folder.chmod(0o755)
    sample = folder / "eicar.txt"
    sample.write_bytes(rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    sample.chmod(0o644)
    result = runner.run_static_inspection(sample, "eicar.txt")
    assert result.ok, result.reason
    assert any(f.category == "known_signature" for f in result.outcome.findings)


def test_ctypes_prctl_constant_matches() -> None:
    # PR_GET_DUMPABLE is 3 on every Linux architecture; guards the test above.
    assert ctypes.CDLL(None).prctl(3, 0, 0, 0, 0) in (0, 1, 2)
