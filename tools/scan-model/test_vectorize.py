"""The Python vectorizer, and the fixture that keeps it in step with Rust.

UPDATE_FIXTURES=1 rewrites apps/desktop-native/crates/qalaa-scan/tests/fixtures/vector-parity.json.
"""

import json
import os
from pathlib import Path

from vectorize import VECTOR_LEN, ember_to_raw, fnv1a, vectorize

FIXTURE = Path(__file__).resolve().parents[2] / "apps/desktop-native/crates/qalaa-scan/tests/fixtures/vector-parity.json"


def sample_raw() -> dict:
    hist = [0.0] * 256
    hist[0], hist[0x41], hist[0xFF] = 0.5, 0.25, 0.25
    be = [0.0] * 256
    be[3], be[200] = 0.75, 0.25
    dist = [0.0] * 96
    dist[33] = 1.0
    return {
        "version": 1, "format": "pe", "size": 123456, "vsize": 200000,
        "byte_histogram": hist, "byte_entropy_histogram": be,
        "strings": {"count": 42, "avg_length": 9.5, "printable_dist": dist, "entropy": 4.25,
                    "paths": 2, "urls": 1, "registry": 3, "mz": 1},
        "header": {"timestamp": 1700000000, "machine": "AMD64", "characteristics": 0x22, "subsystem": 2,
                   "dll_characteristics": 0x8160, "major_image_version": 1, "major_linker_version": 14,
                   "major_os_version": 6, "size_of_code": 4096, "size_of_headers": 1024, "size_of_heap_commit": 4096},
        "sections": [
            {"name": ".text", "size": 4096, "vsize": 4000, "entropy": 6.1, "executable": True, "writable": False},
            {"name": ".data", "size": 512, "vsize": 800, "entropy": 1.2, "executable": False, "writable": True},
            {"name": "", "size": 0, "vsize": 64, "entropy": 0.0, "executable": False, "writable": False},
        ],
        "entry_section": ".text",
        "imports": ["kernel32.dll:CreateFileW", "kernel32.dll:WriteFile", "advapi32.dll:RegSetValueExW", "libc.so.6:"],
        "exports": ["DllMain", "Run"],
        "has_debug": True, "has_relocations": False, "has_resources": True, "has_signature": False, "has_tls": True,
        "symbols": 0, "parse_error": None,
    }  # fmt: skip


def test_vector_length_and_hash() -> None:
    assert fnv1a("") == 0x811C9DC5 and fnv1a("a") == 0xE40C292C
    assert len(vectorize(sample_raw())) == VECTOR_LEN


def test_fixture_matches() -> None:
    raw = sample_raw()
    payload = {"raw": raw, "vector": vectorize(raw)}
    if os.environ.get("UPDATE_FIXTURES"):
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(json.dumps(payload) + "\n")
    assert json.loads(FIXTURE.read_text()) == json.loads(json.dumps(payload))


def test_ember_records_convert() -> None:
    record = {
        "histogram": [10] + [0] * 255, "byteentropy": [5] * 256,
        "strings": {"numstrings": 3, "avlength": 6.0, "printabledist": [1] * 96, "entropy": 5.0,
                    "paths": 0, "urls": 1, "registry": 0, "MZ": 1},
        "general": {"size": 1000, "vsize": 4096, "has_debug": 0, "exports": 0, "imports": 2, "has_relocations": 1,
                    "has_resources": 0, "has_signature": 0, "has_tls": 0, "symbols": 0},
        "header": {"coff": {"timestamp": 5, "machine": "I386", "characteristics": ["EXECUTABLE_IMAGE", "DLL"]},
                   "optional": {"major_linker_version": 9, "sizeof_code": 512}},
        "section": {"entry": ".text", "sections": [{"name": ".text", "size": 512, "entropy": 6.0, "vsize": 500,
                                                    "props": ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]}]},
        "imports": {"KERNEL32.dll": ["ExitProcess", "GetProcAddress"]}, "exports": [],
    }  # fmt: skip
    raw = ember_to_raw(record)
    assert raw["byte_histogram"][0] == 1.0
    assert raw["header"]["characteristics"] == 0x2002
    assert raw["imports"] == ["kernel32.dll:ExitProcess", "kernel32.dll:GetProcAddress"]
    assert raw["sections"][0]["executable"] and not raw["sections"][0]["writable"]
    assert len(vectorize(raw)) == VECTOR_LEN
