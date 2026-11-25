"""Feature vector for qalaa-scan's model, identical to features::vectorize in Rust.

Input is qalaa-scan's raw feature JSON (`qalaa-scan features FILE` prints it,
and `ember_to_raw` converts an EMBER raw-feature record). Written from the
published EMBER feature descriptions; no EMBER code is used. Keep the order in
step with apps/desktop-native/crates/qalaa-scan/src/features.rs: the Rust test
`vectors_match_the_training_scripts` checks a fixture this script writes.
"""

from __future__ import annotations

import math
from typing import Any

FEATURE_VERSION = 1
SECTION_BUCKETS, LIBRARY_BUCKETS, FUNCTION_BUCKETS, EXPORT_BUCKETS, MACHINE_BUCKETS = 50, 256, 1024, 128, 10
VECTOR_LEN = 256 + 256 + 104 + 10 + 3 + 7 + MACHINE_BUCKETS + 8 + 5 + SECTION_BUCKETS * 4 + LIBRARY_BUCKETS + FUNCTION_BUCKETS + EXPORT_BUCKETS


def fnv1a(s: str) -> int:
    h = 0x811C9DC5
    for b in s.encode():
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def hashed(pairs: list[tuple[str, float]], buckets: int) -> list[float]:
    out = [0.0] * buckets
    for name, value in pairs:
        out[fnv1a(name) % buckets] += value
    return out


def vectorize(r: dict[str, Any]) -> list[float]:
    v: list[float] = []
    v += r["byte_histogram"]
    v += r["byte_entropy_histogram"]
    s = r["strings"]
    v += [s["count"], s["avg_length"], s["entropy"], s["paths"], s["urls"], s["registry"], s["mz"], math.log(s["count"] + 1.0)]
    v += (list(s["printable_dist"]) + [0.0] * 96)[:96]
    v += [
        r["size"], r["vsize"], float(r["has_debug"]), len(r["exports"]), len(r["imports"]),
        float(r["has_relocations"]), float(r["has_resources"]), float(r["has_signature"]), float(r["has_tls"]), r["symbols"],
    ]  # fmt: skip
    v += [float(r["format"] == f) for f in ("pe", "elf", "macho")]
    h = r["header"]
    v += [h["timestamp"], h["characteristics"], h["subsystem"], h["dll_characteristics"],
          h["major_image_version"], h["major_linker_version"], h["major_os_version"]]  # fmt: skip
    v += hashed([(h["machine"], 1.0)], MACHINE_BUCKETS)
    v += [h["size_of_code"], h["size_of_headers"], h["size_of_heap_commit"]]
    v += [float((h["characteristics"] >> bit) & 1) for bit in range(5)]
    secs = r["sections"]
    v += [
        len(secs),
        sum(1 for x in secs if x["size"] == 0),
        sum(1 for x in secs if x["name"] == ""),
        sum(1 for x in secs if x["executable"]),
        sum(1 for x in secs if x["writable"]),
    ]
    v += hashed([(x["name"], x["size"]) for x in secs], SECTION_BUCKETS)
    v += hashed([(x["name"], x["entropy"]) for x in secs], SECTION_BUCKETS)
    v += hashed([(x["name"], x["vsize"]) for x in secs], SECTION_BUCKETS)
    v += hashed([(r["entry_section"], 1.0)], SECTION_BUCKETS)
    libs = sorted({i.split(":")[0] for i in r["imports"]})
    v += hashed([(lib, 1.0) for lib in libs], LIBRARY_BUCKETS)
    v += hashed([(i, 1.0) for i in r["imports"] if not i.endswith(":")], FUNCTION_BUCKETS)
    v += hashed([(e, 1.0) for e in r["exports"]], EXPORT_BUCKETS)
    assert len(v) == VECTOR_LEN, len(v)
    return [float(x) for x in v]


MACHINES = {"I386", "AMD64", "ARM", "ARMNT", "ARM64", "IA64"}


def ember_to_raw(e: dict[str, Any]) -> dict[str, Any]:
    """An EMBER raw-feature record (the MIT-licensed dataset) as qalaa-scan raw features.

    EMBER stores totals, not normalised shares, so they are normalised here the
    same way qalaa-scan computes them from a file.
    """
    hist = e["histogram"]
    total = sum(hist) or 1
    be = e["byteentropy"]
    be_total = sum(be) or 1
    st = e["strings"]
    printable = st.get("printabledist", [0] * 96)
    p_total = sum(printable) or 1
    gen, head = e["general"], e["header"]
    coff, opt = head["coff"], head["optional"]
    chars = coff.get("characteristics", [])
    char_bits = {"RELOCS_STRIPPED": 0x1, "EXECUTABLE_IMAGE": 0x2, "LINE_NUMS_STRIPPED": 0x4, "LOCAL_SYMS_STRIPPED": 0x8,
                 "AGGRESIVE_WS_TRIM": 0x10, "LARGE_ADDRESS_AWARE": 0x20, "CHARA_32BIT_MACHINE": 0x100, "DLL": 0x2000}  # fmt: skip
    sections = [
        {
            "name": s["name"],
            "size": s["size"],
            "vsize": s["vsize"],
            "entropy": s["entropy"],
            "executable": "MEM_EXECUTE" in s.get("props", []),
            "writable": "MEM_WRITE" in s.get("props", []),
        }
        for s in e["section"]["sections"]
    ]
    imports = [f"{lib.lower()}:{fn}" for lib, fns in e["imports"].items() for fn in fns]
    machine = coff.get("machine", "UNKNOWN")
    return {
        "version": FEATURE_VERSION,
        "format": "pe",
        "size": gen["size"],
        "vsize": gen["vsize"],
        "byte_histogram": [c / total for c in hist],
        "byte_entropy_histogram": [c / be_total for c in be],
        "strings": {
            "count": st["numstrings"],
            "avg_length": st["avlength"],
            "printable_dist": [c / p_total for c in printable],
            "entropy": st["entropy"],
            "paths": st["paths"],
            "urls": st["urls"],
            "registry": st["registry"],
            "mz": st["MZ"],
        },
        "header": {
            "timestamp": coff.get("timestamp", 0),
            "machine": machine if machine in MACHINES else "UNKNOWN",
            "characteristics": sum(char_bits.get(c, 0) for c in chars),
            "subsystem": 0,
            "dll_characteristics": 0,
            "major_image_version": opt.get("major_image_version", 0),
            "major_linker_version": opt.get("major_linker_version", 0),
            "major_os_version": opt.get("major_operating_system_version", 0),
            "size_of_code": opt.get("sizeof_code", 0),
            "size_of_headers": opt.get("sizeof_headers", 0),
            "size_of_heap_commit": opt.get("sizeof_heap_commit", 0),
        },
        "sections": sections,
        "entry_section": e["section"].get("entry", ""),
        "imports": imports,
        "exports": list(e.get("exports", [])),
        "has_debug": bool(gen.get("has_debug")),
        "has_relocations": bool(gen.get("has_relocations")),
        "has_resources": bool(gen.get("has_resources")),
        "has_signature": bool(gen.get("has_signature")),
        "has_tls": bool(gen.get("has_tls")),
        "symbols": gen.get("symbols", 0),
        "parse_error": None,
    }
