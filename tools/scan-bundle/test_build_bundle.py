"""The signing tool's output is what qalaa-scan verifies (checked end to end in CI)."""

import base64
import json
from pathlib import Path

import pytest
from build_bundle import build, changed, keygen, load_key, public_hex


def test_keygen_writes_a_private_key_only_the_owner_can_read(tmp_path: Path) -> None:
    pub = keygen(tmp_path / "k")
    assert len(pub) == 64
    assert (tmp_path / "k").stat().st_mode & 0o077 == 0
    assert public_hex(load_key(tmp_path / "k")) == pub
    with pytest.raises(FileExistsError):
        keygen(tmp_path / "k")  # never overwrites a key


def test_build_signs_the_exact_manifest_bytes(tmp_path: Path) -> None:
    keygen(tmp_path / "k")
    key = load_key(tmp_path / "k")
    rule = tmp_path / "a.yar"
    rule.write_text("rule a { condition: false }")
    m = build(key, "2026.11.25.1", tmp_path / "out", [rule], None)
    body = (tmp_path / "out/manifest.json").read_bytes()
    sig = base64.b64decode((tmp_path / "out/manifest.sig").read_text())
    key.public_key().verify(sig, body)  # raises if wrong
    assert json.loads(body)["files"]["rules/a.yar"]["size"] == len(rule.read_bytes())
    assert m["version"] == "2026.11.25.1"

    rule.write_text("rule a { condition: true }")
    m2 = build(key, "2026.11.25.2", tmp_path / "out2", [rule], None, previous=tmp_path / "out")
    assert changed(m, m2) == ["rules/a.yar"]
    with pytest.raises(SystemExit):
        build(key, "2026.11.25.1", tmp_path / "out3", [rule], None, previous=tmp_path / "out2")
