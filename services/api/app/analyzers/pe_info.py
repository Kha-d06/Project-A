"""Static facts about Windows executables (PE files), using pefile.

Nothing is executed. Capabilities are inferred from the Windows functions a
program imports, which shows what it could do, not what it will do.
"""

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pefile

from app.analyzers.types import FindingData, Severity

logger = logging.getLogger(__name__)
SOURCE = "SENTINEL executable analysis (pefile)"
_HIGH_ENTROPY = 7.2

# Sets of imports that together indicate a capability. Each is common in malware
# and rare in everyday applications, but legitimate security and system tools use
# them too, which the explanations say.
_CAPABILITIES: tuple[tuple[frozenset[str], Severity, str, str], ...] = (
    (
        frozenset({"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}),
        "high",
        "Can inject code into other programs",
        "The program imports the functions needed to write code into another running program "
        "and start it there, a technique malware uses to hide. Debuggers and some security "
        "tools use it legitimately.",
    ),
    (
        frozenset({"SetWindowsHookExA", "GetAsyncKeyState"}),
        "medium",
        "Can monitor keyboard input",
        "The program can observe keystrokes system-wide. Keyloggers rely on this; so do some "
        "accessibility and hotkey tools.",
    ),
    (
        frozenset({"SetWindowsHookExW", "GetAsyncKeyState"}),
        "medium",
        "Can monitor keyboard input",
        "The program can observe keystrokes system-wide. Keyloggers rely on this; so do some "
        "accessibility and hotkey tools.",
    ),
    (
        frozenset({"CryptEncrypt", "FindFirstFileW", "FindNextFileW", "DeleteFileW"}),
        "medium",
        "Can encrypt files across folders and delete originals",
        "This combination is characteristic of ransomware, though backup and archiving tools "
        "can use it too.",
    ),
)


def _imports(pe: pefile.PE) -> set[str]:
    names: set[str] = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imported in entry.imports:
            if imported.name:
                names.add(imported.name.decode(errors="replace"))
    return names


def pe_findings(path: Path) -> tuple[list[FindingData], dict[str, Any]]:
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            ]
        )
    except pefile.PEFormatError:
        return [], {"pe": "not a valid Windows executable"}

    try:
        imports = _imports(pe)
        timestamp = pe.FILE_HEADER.TimeDateStamp
        sections = [
            {
                "name": section.Name.rstrip(b"\0").decode(errors="replace"),
                "entropy": round(section.get_entropy(), 2),
            }
            for section in pe.sections[:16]
        ]
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        signed = security.VirtualAddress != 0 and security.Size > 0
        is_dll = pe.is_dll()
    finally:
        pe.close()

    findings: list[FindingData] = []
    for required, severity, title, explanation in _CAPABILITIES:
        if required <= imports and not any(f.title == title for f in findings):
            findings.append(
                FindingData(
                    severity,
                    "capability",
                    title,
                    explanation,
                    SOURCE,
                    {"imports": sorted(required)},
                )
            )

    packed = [s["name"] for s in sections if s["entropy"] >= _HIGH_ENTROPY]
    if packed:
        findings.append(
            FindingData(
                "low",
                "packed",
                "Parts of the program are compressed or encrypted",
                "Sections with near-random content hide the program's code from inspection. "
                "Installers and protected software do this too, so it is context, not proof.",
                SOURCE,
                {"sections": packed},
            )
        )
    if not imports:
        findings.append(
            FindingData(
                "low",
                "packed",
                "Program hides which system functions it uses",
                "A Windows program with no visible imports usually loads them at runtime to "
                "avoid inspection.",
                SOURCE,
            )
        )

    compiled = datetime.fromtimestamp(timestamp, tz=UTC) if timestamp else None
    details = {
        "pe": {
            "kind": "DLL" if is_dll else "program",
            "compiled": compiled.isoformat() if compiled else None,
            "has_signature": signed,
            "imports": len(imports),
            "sections": sections,
        }
    }
    return findings, details
