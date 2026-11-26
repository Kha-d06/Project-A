#!/usr/bin/env python3
"""CycloneDX 1.5 SBOM from a Cargo.lock or uv.lock, using the standard library only.

The JavaScript apps use `npm sbom --sbom-format cyclonedx`; this covers the Rust
apps (apps/desktop-native) and the API (services/api), so every release lists
exactly which third-party code it contains (audit QA-22).

    sbom-from-lock.py cargo apps/desktop-native/Cargo.lock qalaa-desktop-native > out.json
    sbom-from-lock.py uv services/api/uv.lock qalaa-api > out.json
"""

import json
import sys
import tomllib
import uuid
from datetime import UTC, datetime


def components(kind: str, lock: dict) -> list[dict]:
    out = []
    for package in lock.get("package", []):
        name, version = package["name"], package["version"]
        source = package.get("source")
        if kind == "cargo":
            # Workspace members have no source: they are Qalaa's own code, not a dependency.
            if not source:
                continue
            purl = f"pkg:cargo/{name}@{version}"
            digest = package.get("checksum")
        else:
            if not isinstance(source, dict) or "registry" not in source:
                continue
            purl = f"pkg:pypi/{name}@{version}"
            sdist = package.get("sdist", {}).get("hash", "")
            digest = sdist.removeprefix("sha256:") if sdist.startswith("sha256:") else None
        component = {"type": "library", "name": name, "version": version, "purl": purl, "bom-ref": purl}
        if digest:
            component["hashes"] = [{"alg": "SHA-256", "content": digest}]
        out.append(component)
    return sorted(out, key=lambda c: c["purl"])


def main(kind: str, path: str, product: str) -> int:
    if kind not in ("cargo", "uv"):
        print("kind must be cargo or uv", file=sys.stderr)
        return 2
    with open(path, "rb") as f:
        lock = tomllib.load(f)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "component": {"type": "application", "name": product},
        },
        "components": components(kind, lock),
    }
    json.dump(bom, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
