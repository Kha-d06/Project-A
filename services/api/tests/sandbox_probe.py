"""Tries one forbidden (or allowed) thing inside the parser jail; run by test_sandbox.py.

    python -I tests/sandbox_probe.py <action> [cpu_seconds] [memory_mb]
Exit 0 means the action worked; a jailed failure shows as a signal or exit code 3.
"""

import os
import socket
import subprocess
import sys
import threading

from app.sandbox.policy import Limits, enter, read_only_roots

action = sys.argv[1]
cpu = int(sys.argv[2]) if len(sys.argv) > 2 else 60
memory = int(sys.argv[3]) if len(sys.argv) > 3 else 512
SAMPLE = sys.argv[4] if len(sys.argv) > 4 else None
OTHER = sys.argv[5] if len(sys.argv) > 5 else None
landlocked = enter(
    Limits(memory_bytes=memory * 1024 * 1024, cpu_seconds=cpu),
    read_only_roots() + ([SAMPLE] if SAMPLE else []),
)

if action == "read":
    # A library file: the parser's own code must stay readable.
    with open(os.__file__, "rb") as handle:
        handle.read(10)
elif action == "thread":
    t = threading.Thread(target=lambda: None)
    t.start()
    t.join()
elif action == "socket":
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
elif action == "unix":
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
elif action == "fork":
    os.fork()
elif action == "exec":
    os.execv("/bin/true", ["true"])  # noqa: S606 - the probe must try to start a program
elif action == "subprocess":
    subprocess.run(["/bin/true"], check=False)
elif action == "write":
    open("/tmp/qalaa-sandbox-probe", "w").close()  # noqa: SIM115, S108 - must be refused
elif action == "memory":
    try:
        block = bytearray(2 * 1024 * 1024 * 1024)
    except MemoryError:
        sys.exit(3)
elif action == "read_sample":
    with open(SAMPLE, "rb") as handle:  # type: ignore[arg-type]
        handle.read(10)
elif action == "read_other":
    try:
        with open(OTHER, "rb") as handle:  # type: ignore[arg-type]
            handle.read(10)
    except PermissionError:
        sys.exit(4)
elif action == "parent_environ":
    try:
        with open(f"/proc/{os.getppid()}/environ", "rb") as handle:
            handle.read(10)
    except PermissionError:
        sys.exit(4)
elif action == "landlock":
    sys.exit(0 if landlocked else 5)
elif action == "cpu":
    while True:
        pass
print("ok")
