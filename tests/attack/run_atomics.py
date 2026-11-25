"""Runs Qalaa's regression atomics (Atomic Red Team schema) against the real
background service and checks what it reports over qalaa-ipc.

    python3 tests/attack/run_atomics.py [--atomics DIR] [--daemon apps/desktop/dist/daemon.js]

Each test runs its executor command in a throwaway home folder, then waits for
the expected `alert` event (or makes sure none arrives). Tests marked
`status: gap` or `status: fixture` are reported, never counted as passes.
Exit code 1 if any test fails.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PLATFORMS = {"linux", "macos", "windows"}


def current_platform() -> str:
    return {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(platform.system(), "linux")


# --- Atomics ------------------------------------------------------------------------


@dataclass
class Atomic:
    technique: str
    name: str
    guid: str
    platforms: list[str]
    executor: str
    command: str
    cleanup: str
    qalaa: dict[str, Any]
    arguments: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        return str(self.qalaa.get("status", "covered"))


class AtomicError(ValueError):
    pass


def substitute(text: str, arguments: dict[str, Any]) -> str:
    def value(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in arguments:
            raise AtomicError(f"no input argument {key}")
        return str(arguments[key])

    return re.sub(r"#\{(\w+)\}", value, text)


def load_atomics(directory: Path) -> list[Atomic]:
    atomics: list[Atomic] = []
    guids: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        technique = doc.get("attack_technique")
        if not technique or not isinstance(doc.get("atomic_tests"), list):
            raise AtomicError(f"{path.name}: needs attack_technique and atomic_tests")
        for test in doc["atomic_tests"]:
            where = f"{path.name}: {test.get('name')}"
            guid = str(test.get("auto_generated_guid", ""))
            uuid.UUID(guid)
            if guid in guids:
                raise AtomicError(f"{where}: duplicate guid")
            guids.add(guid)
            platforms = test.get("supported_platforms") or []
            if not platforms or not set(platforms) <= PLATFORMS:
                raise AtomicError(f"{where}: supported_platforms must be within {sorted(PLATFORMS)}")
            executor = test.get("executor") or {}
            if executor.get("name") not in ("sh", "powershell", "python"):
                raise AtomicError(f"{where}: executor must be sh, powershell or python")
            qalaa = test.get("qalaa") or {}
            status = qalaa.get("status", "covered")
            if status == "covered" and not ("expect" in qalaa or "expect_none" in qalaa):
                raise AtomicError(f"{where}: a covered test needs expect or expect_none")
            if status not in ("covered", "gap", "fixture"):
                raise AtomicError(f"{where}: unknown status {status}")
            arguments = {k: v.get("default") for k, v in (test.get("input_arguments") or {}).items()}
            atomics.append(
                Atomic(
                    technique=str(technique),
                    name=str(test["name"]),
                    guid=guid,
                    platforms=list(platforms),
                    executor=executor["name"],
                    command=substitute(executor.get("command", ""), arguments),
                    cleanup=substitute(executor.get("cleanup_command", ""), arguments),
                    qalaa=qalaa,
                    arguments=arguments,
                )
            )
    return atomics


def matches(expected: dict[str, Any], event: dict[str, Any]) -> bool:
    """The event has the expected name and every expected payload field."""
    if event.get("event") != expected.get("event"):
        return False
    payload = event.get("payload") or {}
    return all(payload.get(k) == v for k, v in (expected.get("match") or {}).items())


# --- The service --------------------------------------------------------------------


class Service:
    """Starts the headless daemon in a throwaway data folder and talks to it over IPC."""

    def __init__(self, daemon: Path, home: Path) -> None:
        self.data = Path(tempfile.mkdtemp(prefix="qalaa-atomics-data-"))
        if current_platform() == "windows":
            self.endpoint = rf"\\.\pipe\qalaa-atomics-{uuid.uuid4().hex[:8]}"
        else:
            self.endpoint = str(self.data / "d.sock")
        self.env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home), "QALAA_DATA_DIR": str(self.data), "QALAA_IPC_ENDPOINT": self.endpoint}
        self.process = subprocess.Popen(["node", str(daemon)], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.events: queue.Queue[dict[str, Any]] = queue.Queue()
        self.replies: dict[int, dict[str, Any]] = {}
        self.ready = threading.Event()
        threading.Thread(target=self._daemon_output, daemon=True).start()
        if not self.ready.wait(30):
            raise RuntimeError("the background service did not start")
        token = (self.data / "ipc-token").read_text().strip()
        self.bridge = subprocess.Popen(["node", str(HERE / "ipc-bridge.mjs"), self.endpoint], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        threading.Thread(target=self._read, daemon=True).start()
        self.next_id = 0
        self.call("hello", {"token": token, "client": "atomics"})

    def _daemon_output(self) -> None:
        assert self.process.stdout
        for line in self.process.stdout:
            if "ready" in line:
                self.ready.set()
            print(f"  [service] {line.rstrip()}", file=sys.stderr)

    def _read(self) -> None:
        assert self.bridge.stdout
        for line in self.bridge.stdout:
            message = json.loads(line)
            if "event" in message:
                self.events.put(message)
            elif "id" in message:
                self.replies[message["id"]] = message

    def call(self, method: str, params: Any = None, timeout: float = 30) -> Any:
        self.next_id += 1
        request_id = self.next_id
        assert self.bridge.stdin
        self.bridge.stdin.write(json.dumps({"id": request_id, "method": method, "params": params}) + "\n")
        self.bridge.stdin.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if request_id in self.replies:
                reply = self.replies.pop(request_id)
                if "error" in reply:
                    raise RuntimeError(f"{method}: {reply['error']}")
                return reply.get("result")
            time.sleep(0.05)
        raise TimeoutError(method)

    def drain(self) -> None:
        while not self.events.empty():
            self.events.get_nowait()

    def close(self) -> None:
        for proc in (getattr(self, "bridge", None), self.process):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        shutil.rmtree(self.data, ignore_errors=True)


# --- Running ------------------------------------------------------------------------


def start(atomic: Atomic, env: dict[str, str], log: Path) -> subprocess.Popen[str]:
    if atomic.executor == "python":
        argv = [sys.executable, "-c", atomic.command]
    elif atomic.executor == "powershell":
        argv = ["powershell", "-NoProfile", "-NonInteractive", "-Command", atomic.command]
    else:
        argv = ["sh", "-c", atomic.command]
    output = log.open("w", encoding="utf-8")
    return subprocess.Popen(argv, env=env, text=True, stdout=output, stderr=subprocess.STDOUT)


def cleanup(atomic: Atomic, proc: subprocess.Popen[str], env: dict[str, str]) -> None:
    if atomic.cleanup:
        shell = ["powershell", "-NoProfile", "-Command"] if atomic.executor == "powershell" else ["sh", "-c"]
        subprocess.run([*shell, atomic.cleanup], env=env, check=False, timeout=60)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()


def run_one(atomic: Atomic, service: Service) -> tuple[str, str]:
    q = atomic.qalaa
    service.drain()
    if "before" in q:
        before = q["before"]
        service.call(before["method"], before.get("params"), timeout=60)
        # Wait for a look that actually completed, so what was there before the
        # attack is recorded as the baseline (a failed first look records nothing).
        if before.get("ready_method"):
            for _ in range(20):
                if (service.call(before["ready_method"], timeout=60) or {}).get(before.get("ready_field", "checkedAt")):
                    break
                time.sleep(1)
                service.call(before["method"], before.get("params"), timeout=60)
    log = Path(service.env["HOME"]) / f"atomic-{atomic.guid}.log"
    proc = start(atomic, service.env, log)
    expected = q.get("expect") or q.get("expect_none")
    want = "expect" in q
    deadline = time.monotonic() + float(q.get("within_seconds", 30))
    trigger = q.get("trigger")
    next_trigger = time.monotonic() + float(trigger.get("after_seconds", 2)) if trigger else None
    seen: list[dict[str, Any]] = []
    found = None
    try:
        while time.monotonic() < deadline and found is None:
            if next_trigger is not None and time.monotonic() >= next_trigger:
                service.call(trigger["method"], trigger.get("params"))
                next_trigger = time.monotonic() + 2
            try:
                event = service.events.get(timeout=0.5)
            except queue.Empty:
                continue
            seen.append(event)
            if matches(expected, event):
                found = event
    finally:
        cleanup(atomic, proc, service.env)
    if want and not found:
        # What the attack printed, and what the service sees, to tell a broken
        # atomic from a missed detection.
        output = log.read_text(encoding="utf-8", errors="replace")[-600:] if log.exists() else ""
        state = ""
        if (expected.get("match") or {}).get("kind") == "credential":
            try:
                incidents = service.call("credentials.get").get("incidents", [])
                state = f"; credential incidents: {[(i.get('program'), i.get('file')) for i in incidents][:8]}"
            except Exception as exc:  # noqa: BLE001 - diagnostics only
                state = f"; credentials.get failed: {exc}"
        if (expected.get("match") or {}).get("kind") == "listener":
            try:
                ports = service.call("listeners.get").get("listeners", [])
                state = f"; listeners now: {[(p.get('process'), p.get('port'), p.get('exposed'), p.get('fresh')) for p in ports][:12]}"
            except Exception as exc:  # noqa: BLE001 - diagnostics only
                state = f"; listeners.get failed: {exc}"
        return ("fail", f"no matching event; saw {[e.get('event') for e in seen]}{state}; atomic output: {output.strip()!r}")
    if want:
        return ("pass", f"got {found['payload']}")
    return ("fail", f"unexpected {found['payload']}") if found else ("pass", "nothing reported, as expected")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--atomics", type=Path, default=HERE / "atomics")
    parser.add_argument("--daemon", type=Path, default=REPO / "apps/desktop/dist/daemon.js")
    parser.add_argument("--only", help="run only tests whose technique or name contains this")
    args = parser.parse_args(argv)
    here = current_platform()
    atomics = [a for a in load_atomics(args.atomics) if not args.only or args.only in a.technique or args.only in a.name]
    # Resolved: on macOS /var is a link to /private/var, and lsof reports the real path.
    home = Path(tempfile.mkdtemp(prefix="qalaa-atomics-home-")).resolve()
    results: list[tuple[Atomic, str, str]] = []
    service: Service | None = None
    try:
        for atomic in atomics:
            if here not in atomic.platforms:
                continue
            if atomic.status != "covered":
                results.append((atomic, atomic.status, str(atomic.qalaa.get("note", ""))))
                continue
            service = service or Service(args.daemon, home)
            outcome, detail = run_one(atomic, service)
            results.append((atomic, outcome, detail))
            print(f"{outcome.upper():5} {atomic.technique} {atomic.name}: {detail}", flush=True)
    finally:
        if service:
            service.close()
        shutil.rmtree(home, ignore_errors=True)
    lines = [f"### Qalaa atomics on {here}", "", "| Technique | Test | Result | Detail |", "|---|---|---|---|"]
    lines += [f"| {a.technique} | {a.name} | {r} | {d.replace('|', '/')[:160]} |" for a, r, d in results]
    summary = "\n".join(lines)
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
            out.write(summary + "\n")
    return 1 if any(r == "fail" for _, r, _ in results) else 0


if __name__ == "__main__":
    sys.exit(main())
