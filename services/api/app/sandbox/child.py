"""Static inspection of one uploaded file, inside the parser jail.

Started by runner.py as `python -I -B -m app.sandbox.child <path> <name> <memory_mb> <cpu_s>`
with an environment holding no secrets. Imports and rule compilation happen
first; then the process locks itself down (policy.enter) before it reads a
byte of the sample. The result goes back as one JSON document on stdout.
"""

import dataclasses
import json
import os
import sys
from pathlib import Path
from typing import Any

from app.analyzers import file_scan, file_types, yara_scan
from app.analyzers.types import Outcome
from app.sandbox.policy import Limits, enter, read_only_roots

EXIT_MEMORY = 3


def serialize(outcome: Outcome) -> dict[str, Any]:
    return {
        "findings": [dataclasses.asdict(f) for f in outcome.findings],
        "checks": [c.as_dict() for c in outcome.checks],
        "details": outcome.details,
        "limitations": outcome.limitations,
    }


def main(argv: list[str]) -> int:
    path, filename = Path(argv[1]), argv[2]
    limits = Limits(memory_bytes=int(argv[3]) * 1024 * 1024, cpu_seconds=int(argv[4]))
    try:
        rule_set: yara_scan.RuleSet | None = yara_scan.load_rules()
    except Exception:  # noqa: BLE001 - yara_check reports rules that can't compile
        rule_set = None
    rules = os.environ.get("SENTINEL_YARA_RULES_DIR")
    readable = read_only_roots([rules] if rules else []) + [str(path)]
    if not enter(limits, readable):
        # Reported to the worker log; the other layers are still in place.
        sys.stderr.write("qalaa-sandbox: Landlock unavailable on this kernel\n")
    outcome = Outcome()
    try:
        detected = file_types.identify(path)
        file_scan.static_inspection(path, filename, detected, outcome, rule_set)
    except MemoryError:
        return EXIT_MEMORY
    sys.stdout.write(json.dumps(serialize(outcome), default=str))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
