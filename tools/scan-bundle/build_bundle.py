"""Build and sign qalaa-scan rule and model bundles.

    keygen --out KEYFILE                 new ed25519 key; prints the public key for keys/bundle-keys.txt
    build  --key KEYFILE --version V --out DIR [--rules R.yar ...] [--model model.json] [--previous DIR]

`build` copies the files in, writes manifest.json (sizes and SHA-256 of
every file) and manifest.sig (base64 ed25519 signature over manifest.json's
exact bytes). With --previous, it refuses a version that isn't newer and
prints which files changed, which is all a client downloads.

Keep the private key offline. Anyone holding it can make every Qalaa
desktop load their rules.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def keygen(out: Path) -> str:
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(raw.hex() + "\n")
    return public_hex(key)


def load_key(path: Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(path.read_text().strip()))


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def version_key(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("."))


def build(key: Ed25519PrivateKey, version: str, out: Path, rules: list[Path], model: Path | None, previous: Path | None = None) -> dict:
    version_key(version)  # must be dotted numbers, so clients can refuse downgrades
    if previous and version_key(version) <= version_key(json.loads((previous / "manifest.json").read_text())["version"]):
        raise SystemExit(f"version {version} is not newer than the previous bundle")
    if out.exists():
        shutil.rmtree(out)
    (out / "rules").mkdir(parents=True)
    files: dict[str, dict] = {}
    sources = [(f"rules/{r.name}", r) for r in rules] + ([("model.json", model)] if model else [])
    for name, src in sources:
        data = src.read_bytes()
        (out / name).write_bytes(data)
        files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    manifest = {
        "format": 1,
        "version": version,
        "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": dict(sorted(files.items())),
    }
    body = json.dumps(manifest, separators=(",", ":")).encode()
    (out / "manifest.json").write_bytes(body)
    (out / "manifest.sig").write_text(base64.b64encode(key.sign(body)).decode() + "\n")
    return manifest


def changed(old: dict, new: dict) -> list[str]:
    return [n for n, e in new["files"].items() if old["files"].get(n, {}).get("sha256") != e["sha256"]]


def main(argv: list[str]) -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("keygen")
    g.add_argument("--out", type=Path, required=True)
    b = sub.add_parser("build")
    b.add_argument("--key", type=Path, required=True)
    b.add_argument("--version", required=True)
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--rules", type=Path, nargs="*", default=[])
    b.add_argument("--model", type=Path)
    b.add_argument("--previous", type=Path)
    a = p.parse_args(argv)
    if a.cmd == "keygen":
        print(keygen(a.out))
        return
    m = build(load_key(a.key), a.version, a.out, a.rules, a.model, a.previous)
    if a.previous:
        old = json.loads((a.previous / "manifest.json").read_text())
        print("changed:", ", ".join(changed(old, m)) or "nothing")
    print(f"bundle {m['version']} with {len(m['files'])} files in {a.out}")


if __name__ == "__main__":
    main(sys.argv[1:])
