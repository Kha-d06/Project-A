"""LIEF-based facts about Linux, macOS and Windows programs (Wave 4.A, server side)."""

import shutil
import sys
from pathlib import Path

import lief
import pytest

from app.analyzers.binary_info import binary_findings, judge
from app.sandbox import runner

LS = Path(shutil.which("ls") or "/bin/ls")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs a Linux binary")


def titles(facts: dict) -> set[str]:
    return {f.title for f in judge(facts)}


@linux
def test_an_ordinary_system_program_has_no_findings() -> None:
    findings, details = binary_findings(LS, "elf")
    assert findings == []
    assert details["binary"]["format"] == "elf"
    assert details["binary"]["nx"] is True


@linux
def test_an_executable_stack_and_odd_loader_are_reported(tmp_path: Path) -> None:
    b = lief.parse(str(LS))
    for seg in b.segments:
        if str(seg.type).endswith("GNU_STACK"):
            seg.flags = (
                lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.W | lief.ELF.Segment.FLAGS.X
            )
    b.interpreter = "/tmp/ld.so"  # noqa: S108 - a path written into the test binary
    out = tmp_path / "patched"
    b.write(str(out))
    names = {f.title for f in binary_findings(out, "elf")[0]}
    assert "The program asks for an executable stack" in names
    assert "The program uses an unusual loader" in names


def test_rules_from_facts() -> None:
    elf = {"format": "elf", "imports": ["memfd_create", "fexecve"], "rwx_segments": ["LOAD@0x1000"],
           "upx": True, "libraries": ["/tmp/evil.so"], "interpreter": "/lib64/ld-linux-x86-64.so.2"}  # fmt: skip # noqa: S108
    assert titles(elf) == {
        "Can run code without writing it to disk",
        "Part of the program is both writable and executable",
        "The program is compressed with UPX",
        "The program loads a library from a temporary folder",
    }
    assert titles({"format": "elf", "imports": ["memfd_create"]}) == set()
    assert titles({"format": "macho", "signed": False}) == {"This macOS program isn't signed"}
    assert titles({"format": "macho", "signed": True}) == set()
    tampered = judge(
        {"format": "pe", "signed": True, "signature_matches": False, "issuers": ["CN=x"]}
    )
    assert tampered[0].severity == "high"
    assert titles({"format": "pe", "signed": True, "signature_matches": True}) == set()
    assert titles({"format": "pe", "signed": False}) == set()


def test_garbage_is_an_answer_not_a_crash(tmp_path: Path) -> None:
    junk = tmp_path / "x"
    junk.write_bytes(b"\x7fELF" + bytes(range(256)) * 4)
    findings, details = binary_findings(junk, "elf")
    assert findings == []
    assert "binary" in details
    assert binary_findings(junk, "macho") == (
        [],
        {"binary": "the headers don't match the detected type"},
    )


@linux
def test_lief_runs_inside_the_parser_jail(tmp_path: Path) -> None:
    sample = tmp_path / "program"
    shutil.copy(LS, sample)
    result = runner.run_static_inspection(sample, "program")
    assert result.ok, result.reason
    assert result.outcome.details["binary"]["format"] == "elf"
