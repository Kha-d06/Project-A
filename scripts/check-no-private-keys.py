#!/usr/bin/env python3
"""Fails if a private key or certificate bundle is committed.

Release-signing, code-signing and Android keys live only on the release
manager's offline machine or in the CI secret store (docs/release-signing-key.md,
docs/code-signing.md). Test fixtures may contain a private-key *header* to test
detectors, but never a key body: a PEM block whose next line is 40 or more base64
characters counts as a real key.
"""

import re
import subprocess
import sys

KEY_FILES = re.compile(r"\.(pem|key|p12|pfx|p8|jks|keystore|snk|ppk)$", re.IGNORECASE)
PEM_KEY = re.compile(r"-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----\s*\n\s*[A-Za-z0-9+/=]{40,}")


def tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True).stdout
    return [p for p in out.decode().split("\0") if p]


def main() -> int:
    problems = []
    for path in tracked():
        if KEY_FILES.search(path):
            problems.append(f"{path}: key or certificate file")
            continue
        try:
            with open(path, "rb") as f:
                text = f.read(2_000_000).decode("utf-8", "ignore")
        except OSError:
            continue
        if PEM_KEY.search(text):
            problems.append(f"{path}: contains a private key")
    for line in problems:
        print(f"::error::{line}")
    if problems:
        print("Private keys must never be committed. Remove them and rotate the key.")
        return 1
    print(f"No private keys in {len(tracked())} tracked files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
