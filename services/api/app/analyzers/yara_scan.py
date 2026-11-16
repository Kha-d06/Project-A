"""YARA signature matching on uploaded samples."""

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yara

from app.analyzers.types import Check, FindingData, Outcome, Severity
from app.core.config import get_settings

BUILT_IN_RULES = Path(__file__).resolve().parent.parent / "rules"
SCAN_TIMEOUT_SECONDS = 30
_SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class RuleSet:
    rules: yara.Rules
    built_in: int
    custom: int


def _rule_files(directory: Path) -> list[Path]:
    return sorted(path for path in directory.glob("*.yar*") if path.is_file())


@lru_cache
def load_rules() -> RuleSet:
    built_in = _rule_files(BUILT_IN_RULES)
    custom_dir = get_settings().yara_rules_dir
    custom = _rule_files(custom_dir) if custom_dir and custom_dir.is_dir() else []
    sources = {f"rules_{index}": str(path) for index, path in enumerate(built_in + custom)}
    rules = yara.compile(filepaths=sources)
    return RuleSet(rules, sum(1 for _ in rules), len(custom))


def yara_check(path: Path, outcome: Outcome) -> None:
    label, provider = "Signature rules", "YARA"
    try:
        rule_set = load_rules()
        matches = rule_set.rules.match(str(path), timeout=SCAN_TIMEOUT_SECONDS, fast=True)
    except yara.TimeoutError:
        outcome.checks.append(Check("yara", label, provider, "failed", "Rule matching timed out."))
        return
    except yara.Error as exc:
        outcome.checks.append(
            Check("yara", label, provider, "unavailable", f"Rules could not run ({exc}).")
        )
        return

    for match in matches:
        meta = match.meta
        declared = str(meta.get("severity", "low"))
        severity: Severity = next((s for s in _SEVERITIES if s == declared), "low")
        outcome.findings.append(
            FindingData(
                severity,
                "yara_match",
                str(meta.get("title", match.rule)),
                str(meta.get("explanation", "The file matches a signature rule.")),
                "SENTINEL YARA rules" if match.namespace.startswith("rules_") else provider,
                {"rule": match.rule},
            )
        )
    custom = f" plus {rule_set.custom} custom file(s)" if rule_set.custom else ""
    outcome.checks.append(
        Check(
            "yara",
            label,
            provider,
            "completed",
            f"Matched against {rule_set.built_in} rules{custom}: "
            + (f"{len(matches)} matched." if matches else "none matched."),
        )
    )
