"""Static facts about Linux (ELF) and macOS (Mach-O) programs, and whether a
Windows program's Authenticode signature matches its contents, using LIEF
(Apache-2.0).

Runs inside the parser jail like every other parser here (app.sandbox): LIEF
is native code reading hostile input. Nothing is executed. Facts are pulled
out first (`*_facts`), then judged (`judge`), so the rules can be tested
without crafted binaries for every case.

What a program imports shows what it could do, not what it will do; the
explanations say so.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.analyzers.types import FindingData

logger = logging.getLogger(__name__)
SOURCE = "Qalaa executable analysis (LIEF)"

try:
    import lief

    lief.logging.disable()
except ImportError:  # pragma: no cover - LIEF is a declared dependency
    lief = None  # type: ignore[assignment]


def available() -> bool:
    return lief is not None


_STANDARD_LOADERS = (
    "/lib/ld-linux",
    "/lib64/ld-linux",
    "/lib/ld-musl",
    "/usr/lib/ld-linux",
    "/usr/lib64/ld-linux",
    "/lib/ld64.so",
    "/lib64/ld64.so",
    "/system/bin/linker",
)
# Paths a binary names, not files Qalaa uses: world-writable folders.
_UNTRUSTED_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/users/shared/", "/private/tmp/")  # noqa: S108


def _flags(segment: Any) -> tuple[bool, bool]:
    flags = int(segment.flags)
    return bool(flags & 2), bool(flags & 1)  # (writable, executable): PF_W, PF_X


def elf_facts(binary: Any) -> dict[str, Any]:
    stack_exec = False
    rwx: list[str] = []
    for seg in binary.segments:
        kind = str(seg.type).rsplit(".", 1)[-1]
        writable, executable = _flags(seg)
        if kind == "GNU_STACK":
            stack_exec = executable
        elif kind == "LOAD" and writable and executable:
            rwx.append(f"LOAD@{seg.virtual_address:#x}")
    imports = sorted({s.name for s in binary.imported_symbols if s.name})[:2000]
    sections = [s.name for s in binary.sections][:64]
    return {
        "format": "elf",
        "interpreter": binary.interpreter if binary.has_interpreter else None,
        "pie": bool(binary.is_pie),
        "nx": bool(binary.has_nx),
        "stack_executable": stack_exec,
        "rwx_segments": rwx,
        "imports": imports,
        "libraries": list(binary.libraries)[:64],
        "sections": sections,
        "stripped": not any(s.name == ".symtab" for s in binary.sections),
        "statically_linked": not binary.has_interpreter,
        "upx": any(n.upper().startswith("UPX") for n in sections),
    }


def macho_facts(binary: Any) -> dict[str, Any]:
    rwx = []
    for seg in binary.segments:
        prot = int(seg.init_protection)
        if prot & 2 and prot & 4:  # VM_PROT_WRITE, VM_PROT_EXECUTE
            rwx.append(seg.name)
    return {
        "format": "macho",
        "signed": bool(binary.has_code_signature),
        "pie": bool(binary.is_pie),
        "rwx_segments": rwx,
        "imports": sorted({s.name for s in binary.imported_symbols if s.name})[:2000],
        "libraries": [lib.name for lib in binary.libraries][:64],
    }


def pe_signature_facts(binary: Any) -> dict[str, Any]:
    signatures = list(binary.signatures)
    if not signatures:
        return {"format": "pe", "signed": False}
    result = binary.verify_signature()
    ok = result == lief.PE.Signature.VERIFICATION_FLAGS.OK
    signers = []
    for sig in signatures[:2]:
        for signer in list(sig.signers)[:2]:
            signers.append(str(signer.issuer)[:200])
    return {"format": "pe", "signed": True, "signature_matches": ok, "issuers": signers}


def judge(facts: dict[str, Any]) -> list[FindingData]:
    out: list[FindingData] = []
    imports = set(facts.get("imports", []))
    fmt = facts["format"]
    if facts.get("stack_executable"):
        out.append(
            FindingData(
                "medium",
                "capability",
                "The program asks for an executable stack",
                "Modern Linux programs keep their stack non-executable so injected data can't "
                "run as code. Asking for the opposite is rare outside old or exploit code.",
                SOURCE,
            )
        )
    if facts.get("rwx_segments"):
        out.append(
            FindingData(
                "medium",
                "packed",
                "Part of the program is both writable and executable",
                "Code that rewrites itself in memory is typical of packers and shellcode "
                "loaders. Some just-in-time compilers do it too.",
                SOURCE,
                {"segments": facts["rwx_segments"][:8]},
            )
        )
    interp = facts.get("interpreter")
    if interp and not interp.startswith(_STANDARD_LOADERS):
        out.append(
            FindingData(
                "medium",
                "capability",
                "The program uses an unusual loader",
                f"It names {interp!r} as its loader instead of the system's, so code from "
                "that file runs before the program itself.",
                SOURCE,
                {"interpreter": interp},
            )
        )
    if fmt == "elf" and "memfd_create" in imports and imports & {"fexecve", "execveat"}:
        out.append(
            FindingData(
                "high",
                "capability",
                "Can run code without writing it to disk",
                "The program imports memfd_create together with fexecve/execveat, the usual "
                "way to start a program straight from memory and leave no file behind.",
                SOURCE,
                {"imports": sorted(imports & {"memfd_create", "fexecve", "execveat"})},
            )
        )
    if fmt == "elf" and "ptrace" in imports and "process_vm_writev" in imports:
        out.append(
            FindingData(
                "medium",
                "capability",
                "Can change other programs' memory",
                "ptrace with process_vm_writev lets a program write into other running "
                "programs. Debuggers need this; so does malware that injects code.",
                SOURCE,
            )
        )
    if facts.get("upx"):
        out.append(
            FindingData(
                "low",
                "packed",
                "The program is compressed with UPX",
                "Its real code is unpacked only when it runs, so it can't be inspected here. "
                "Legitimate tools use UPX too; it is context, not proof.",
                SOURCE,
            )
        )
    bad_libs = [
        lib for lib in facts.get("libraries", []) if lib.lower().startswith(_UNTRUSTED_DIRS)
    ]
    if bad_libs:
        out.append(
            FindingData(
                "medium",
                "capability",
                "The program loads a library from a temporary folder",
                "Anyone can write to those folders, so the code that runs isn't the code "
                "that was installed.",
                SOURCE,
                {"libraries": bad_libs[:8]},
            )
        )
    if fmt == "macho" and not facts.get("signed"):
        out.append(
            FindingData(
                "low",
                "unsigned",
                "This macOS program isn't signed",
                "macOS blocks unsigned programs unless you override it. Only do that if you "
                "know exactly where it came from.",
                SOURCE,
            )
        )
    if fmt == "pe" and facts.get("signed") and not facts.get("signature_matches"):
        out.append(
            FindingData(
                "high",
                "tampered_signature",
                "The program's signature doesn't match its contents",
                "It carries a digital signature, but the file was changed after signing or "
                "the signature is malformed. Malware sometimes copies a real signature to "
                "look trustworthy.",
                SOURCE,
                {"issuers": facts.get("issuers", [])},
            )
        )
    return out


def binary_findings(path: Path, kind: str) -> tuple[list[FindingData], dict[str, Any]]:
    """`kind` is the detected file type key: "elf", "macho" or "pe"."""
    if lief is None:
        return [], {"binary": "LIEF is not installed on this server"}
    try:
        binary = lief.parse(str(path))
    except Exception:  # noqa: BLE001 - malformed input is an answer, not a crash
        binary = None
    if binary is None:
        return [], {"binary": "the program's headers could not be parsed"}
    try:
        if kind == "elf" and isinstance(binary, lief.ELF.Binary):
            facts = elf_facts(binary)
        elif kind == "macho" and isinstance(binary, lief.MachO.Binary):
            facts = macho_facts(binary)
        elif kind == "pe" and isinstance(binary, lief.PE.Binary):
            facts = pe_signature_facts(binary)
        else:
            return [], {"binary": "the headers don't match the detected type"}
    except Exception:  # noqa: BLE001 - a half-valid file: report, don't crash the inspection
        logger.info("LIEF could not read every structure of a %s file", kind)
        return [], {"binary": "the program's structures could not all be parsed"}
    details = {k: v for k, v in facts.items() if k not in ("imports", "sections")}
    details["imports"] = len(facts.get("imports", []))
    return judge(facts), {"binary": details}
