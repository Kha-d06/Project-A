"""YARA signature matching on uploaded samples."""

import json
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


def compile_rules(custom_dir: Path | None) -> RuleSet:
    """Built-in rules plus an operator's own folder. Used inside the parser jail too."""
    built_in = _rule_files(BUILT_IN_RULES)
    custom = _rule_files(custom_dir) if custom_dir and custom_dir.is_dir() else []
    sources = {f"rules_{index}": str(path) for index, path in enumerate(built_in + custom)}
    rules = yara.compile(filepaths=sources)
    return RuleSet(rules, sum(1 for _ in rules), len(custom))


@lru_cache
def load_rules() -> RuleSet:
    return compile_rules(get_settings().yara_rules_dir)


def yara_check(path: Path, outcome: Outcome, rule_set: RuleSet | None = None) -> None:
    label, provider = "Signature rules", "YARA"
    try:
        rule_set = rule_set or load_rules()
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
                "Qalaa YARA rules" if match.namespace.startswith("rules_") else provider,
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


def _read_allowlist(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    entries = data.get("sha256", {}) if isinstance(data, dict) else {}
    return {
        str(k).lower(): str(v)
        for k, v in entries.items()
        if isinstance(k, str) and len(k) == 64 and all(c in "0123456789abcdefABCDEF" for c in k)
    }


@lru_cache
def load_allowlist() -> dict[str, str]:
    """Known false positives: SHA-256 -> reason (built in, plus the operator's own)."""
    allowed = _read_allowlist(BUILT_IN_RULES / "allowlist.json")
    custom_dir = get_settings().yara_rules_dir
    if custom_dir:
        allowed.update(_read_allowlist(custom_dir / "allowlist.json"))
    return allowed


def apply_allowlist(outcome: Outcome, sha256: str) -> None:
    """Drops rule matches on a file listed as a known false positive, and says so."""
    reason = load_allowlist().get(sha256.lower())
    if reason is None:
        return
    before = len(outcome.findings)
    outcome.findings = [f for f in outcome.findings if f.category != "yara_match"]
    if len(outcome.findings) != before:
        outcome.limitations.append(
            f"Signature rule matches on this exact file are not shown: it is a known false "
            f"positive ({reason})."
        )
