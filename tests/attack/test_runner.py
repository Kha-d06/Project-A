"""The atomics runner: schema checks, argument substitution, event matching."""

from pathlib import Path

import pytest

import run_atomics as r

ATOMICS = Path(__file__).with_name("atomics")


def test_every_atomic_is_valid_and_unique() -> None:
    atomics = r.load_atomics(ATOMICS)
    assert len(atomics) >= 12
    assert len({a.guid for a in atomics}) == len(atomics)
    covered = [a for a in atomics if a.status == "covered"]
    assert {a.technique for a in covered} >= {"T1552.004", "T1552.001", "T1555.003", "T1555.001", "T1571"}
    # Gaps and fixtures say why, so the coverage map is honest.
    assert all(a.qalaa.get("note") for a in atomics if a.status != "covered")
    # Input arguments are filled in; nothing like #{x} is left over.
    assert not any("#{" in a.command or "#{" in a.cleanup for a in atomics)


def write(tmp_path: Path, body: str) -> Path:
    (tmp_path / "t.yaml").write_text(body)
    return tmp_path


@pytest.mark.parametrize(
    "body",
    [
        "atomic_tests: []\n",
        "attack_technique: T1\natomic_tests:\n - {name: a, auto_generated_guid: not-a-uuid, supported_platforms: [linux], executor: {name: sh}}\n",
        "attack_technique: T1\natomic_tests:\n - {name: a, auto_generated_guid: 00000000-0000-4000-8000-000000000009, supported_platforms: [amiga], executor: {name: sh}}\n",
        "attack_technique: T1\natomic_tests:\n - {name: a, auto_generated_guid: 00000000-0000-4000-8000-000000000009, supported_platforms: [linux], executor: {name: cmd}}\n",
        "attack_technique: T1\natomic_tests:\n - {name: a, auto_generated_guid: 00000000-0000-4000-8000-000000000009, supported_platforms: [linux], executor: {name: sh}, qalaa: {}}\n",
        "attack_technique: T1\natomic_tests:\n - {name: a, auto_generated_guid: 00000000-0000-4000-8000-000000000009, supported_platforms: [linux], executor: {name: sh, command: 'echo #{missing}'}, qalaa: {status: gap, note: x}}\n",
    ],
)
def test_malformed_atomics_are_refused(tmp_path: Path, body: str) -> None:
    with pytest.raises((r.AtomicError, ValueError)):
        r.load_atomics(write(tmp_path, body))


def test_matching_is_by_event_name_and_payload_subset() -> None:
    expected = {"event": "alert", "match": {"kind": "credential", "credential": "ssh_key"}}
    assert r.matches(expected, {"event": "alert", "payload": {"kind": "credential", "credential": "ssh_key", "pid": 3}})
    assert not r.matches(expected, {"event": "alert", "payload": {"kind": "credential", "credential": "env_file"}})
    assert not r.matches(expected, {"event": "home.changed", "payload": {"kind": "credential", "credential": "ssh_key"}})


def test_substitution() -> None:
    assert r.substitute("sleep #{hold}; port #{port}", {"hold": 5, "port": 80}) == "sleep 5; port 80"
