#!/usr/bin/env python3
"""Compares two build outputs file by file and fails on any difference.

    compare.py <build-a> <build-b> [--report report.md]

Prints the SHA-256 of every file that matches, and every file that differs or
exists on one side only. Exit code 1 if anything differs: a difference is never
hidden behind a passing check.
"""

import hashlib
import sys
from pathlib import Path


def digests(root: Path) -> dict[str, str]:
    out = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            out[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    a, b = Path(argv[0]), Path(argv[1])
    report = Path(argv[argv.index("--report") + 1]) if "--report" in argv else None
    left, right = digests(a), digests(b)
    same = sorted(k for k in left.keys() & right.keys() if left[k] == right[k])
    differ = sorted(k for k in left.keys() & right.keys() if left[k] != right[k])
    only = sorted(left.keys() ^ right.keys())
    lines = [f"# Reproducibility: {len(same)} identical, {len(differ)} different, {len(only)} on one side only", ""]
    lines += [f"- DIFFERENT `{k}`: {left[k][:16]} vs {right[k][:16]}" for k in differ]
    lines += [f"- ONLY IN {'A' if k in left else 'B'} `{k}`" for k in only]
    lines += ["", "Identical:", ""] + [f"- `{k}` {left[k]}" for k in same]
    text = "\n".join(lines) + "\n"
    print(text)
    if report:
        report.write_text(text)
    if not left:
        print("Nothing was built.", file=sys.stderr)
        return 1
    return 1 if differ or only else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
