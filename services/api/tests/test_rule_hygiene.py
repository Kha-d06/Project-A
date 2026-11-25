"""YARA rule hygiene, signature-base style (P1-12)."""

import hashlib
import json
import re
import uuid
from datetime import date
from pathlib import Path

import pytest
import yara

from app.analyzers import yara_scan
from app.analyzers.types import FindingData, Outcome

RULES = yara_scan.BUILT_IN_RULES
NAME = re.compile(r"^(MAL|SUSP|HKTL|PUA|INFO)_[A-Z][A-Za-z0-9]*(_[A-Za-z0-9]+)+$")
REQUIRED = {
    "id",
    "author",
    "date",
    "modified",
    "reference",
    "score",
    "title",
    "explanation",
    "severity",
}


def compiled() -> yara.Rules:
    sources = {f"r{i}": str(p) for i, p in enumerate(sorted(RULES.glob("*.yar")))}
    # Warnings (slow or overly broad strings, for example) fail the build.
    return yara.compile(filepaths=sources, error_on_warning=True)


def test_rules_compile_without_warnings() -> None:
    assert sum(1 for _ in compiled()) >= 9


def test_names_and_meta() -> None:
    ids: set[str] = set()
    names: set[str] = set()
    for rule in compiled():
        assert NAME.match(rule.identifier), f"{rule.identifier}: prefix MAL_/SUSP_/HKTL_/PUA_/INFO_"
        assert rule.identifier not in names
        names.add(rule.identifier)
        meta = rule.meta
        missing = REQUIRED - set(meta)
        assert not missing, f"{rule.identifier} is missing {sorted(missing)}"
        rid = str(meta["id"])
        uuid.UUID(rid)
        assert rid not in ids, f"duplicate id {rid}"
        ids.add(rid)
        assert isinstance(meta["score"], int) and 0 <= meta["score"] <= 100
        assert date.fromisoformat(str(meta["date"])) <= date.fromisoformat(str(meta["modified"]))
        assert str(meta["reference"]).startswith("https://")
        assert meta["severity"] in ("critical", "high", "medium", "low", "info")
        if rule.identifier.startswith("INFO_"):
            assert meta["score"] < 40, "an INFO_ rule is not a threat on its own"


def test_regexes_are_bounded() -> None:
    """Every regex string limits its repeats or anchors on literals: no bare .* or .+ ."""
    for path in RULES.glob("*.yar"):
        for line in path.read_text().splitlines():
            m = re.search(r"=\s*/(.*)/[a-z ]*$", line.strip())
            if m:
                body = m.group(1)
                assert not re.search(r"(?<!\\)\.[*+]", body), (
                    f"unbounded wildcard in {line.strip()}"
                )


def test_clean_system_files_do_not_match() -> None:
    """A small clean corpus: the programs and libraries on this machine."""
    rules = compiled()
    hits: list[str] = []
    checked = 0
    for folder in (Path("/usr/bin"), Path("/usr/sbin")):
        for path in sorted(folder.glob("*"))[:300]:
            if not path.is_file() or path.stat().st_size > 50 * 1024 * 1024:
                continue
            checked += 1
            for match in rules.match(str(path), timeout=30, fast=True):
                if int(match.meta.get("score", 0)) >= 40:
                    hits.append(f"{match.rule}: {path}")
    assert checked > 50
    assert hits == [], hits


def test_known_false_positives_are_suppressed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = b"known benign file"
    digest = hashlib.sha256(sample).hexdigest()
    (tmp_path / "allowlist.json").write_text(json.dumps({"sha256": {digest: "vendor installer"}}))
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "yara_rules_dir", tmp_path)
    yara_scan.load_allowlist.cache_clear()
    try:
        outcome = Outcome(
            findings=[
                FindingData("medium", "yara_match", "x", "y", "z"),
                FindingData("info", "executable", "a", "b", "c"),
            ]
        )
        yara_scan.apply_allowlist(outcome, digest)
        assert [f.category for f in outcome.findings] == ["executable"]
        assert "vendor installer" in outcome.limitations[0]
        other = Outcome(findings=[FindingData("medium", "yara_match", "x", "y", "z")])
        yara_scan.apply_allowlist(other, "0" * 64)
        assert len(other.findings) == 1
    finally:
        yara_scan.load_allowlist.cache_clear()
