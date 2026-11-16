"""Static inspection of an uploaded file. Nothing here executes or renders the sample."""

import hashlib
import re
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy.orm import Session

from app.analyzers import file_types
from app.analyzers.file_types import FileType, extension_of
from app.analyzers.office_macros import macro_findings
from app.analyzers.pe_info import pe_findings
from app.analyzers.types import Check, FindingData, Outcome, Severity
from app.analyzers.yara_scan import yara_check
from app.core.config import get_settings
from app.intel import providers
from app.intel.feeds import MALWAREBAZAAR
from app.intel.lookup import find_indicators, fresh_sources

SOURCE = "SENTINEL static file inspection"

_HASH_CHUNK_BYTES = 1024 * 1024
_CONTENT_SCAN_BYTES = 8 * 1024 * 1024

# Archive limits. Entries are listed from the ZIP directory only; nothing is extracted.
_MAX_ARCHIVE_ENTRIES = 2000
_BOMB_RATIO = 100
_BOMB_MIN_EXPANDED_BYTES = 100 * 1024 * 1024
_MAX_LISTED_NAMES = 25

_RUNNABLE_EXTENSIONS = frozenset(
    {"exe", "scr", "dll", "bat", "cmd", "com", "msi", "vbs", "vbe", "js", "jse", "wsf", "hta",
     "ps1", "lnk", "jar", "apk", "iso", "img"}
)  # fmt: skip
_DOCUMENT_EXTENSIONS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt",
                                  "jpg", "jpeg", "png", "gif", "rtf", "csv"})  # fmt: skip
_ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "gz", "tar", "iso"})

# The EICAR string is a harmless, industry-standard antivirus test pattern.
_EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _name_findings(filename: str, detected: FileType) -> list[FindingData]:
    findings = []
    parts = filename.lower().split(".")
    extension = extension_of(filename)

    if len(parts) > 2 and parts[-1] in _RUNNABLE_EXTENSIONS and parts[-2] in _DOCUMENT_EXTENSIONS:
        findings.append(
            FindingData(
                "high",
                "disguised_file",
                "File name is made to look like a document but is a program",
                f"The name ends in “.{parts[-2]}.{parts[-1]}”. Windows often hides the last "
                "part, so the file appears to be a document while it actually runs code.",
                SOURCE,
                {"file_name": filename},
            )
        )

    declared_matches = extension in detected.extensions or detected in (
        file_types.TEXT,
        file_types.BINARY,
    )
    if detected is file_types.ZIP and extension in _ARCHIVE_EXTENSIONS:
        declared_matches = True
    if not declared_matches:
        severity: Severity = "high" if detected.executable else "medium"
        findings.append(
            FindingData(
                severity,
                "type_mismatch",
                f"File is really a {detected.label.lower()}, not what its name suggests",
                f"The name ends in “.{extension or '(none)'}” but the content is a "
                f"{detected.label.lower()}. A mismatch like this can be an honest mistake or "
                "an attempt to get past filters and trick the person opening it.",
                SOURCE,
                {"file_name": filename, "detected_type": detected.label},
            )
        )
    return findings


def _archive_findings(path: Path, outcome: Outcome) -> list[FindingData]:
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        outcome.limitations.append("The archive is damaged and its contents could not be listed.")
        return []

    findings = []
    with archive:
        entries = archive.infolist()
    listed = entries[:_MAX_ARCHIVE_ENTRIES]
    if len(entries) > _MAX_ARCHIVE_ENTRIES:
        outcome.limitations.append(
            f"The archive holds {len(entries):,} entries; only the first "
            f"{_MAX_ARCHIVE_ENTRIES:,} were listed."
        )

    expanded = sum(entry.file_size for entry in listed)
    compressed = sum(entry.compress_size for entry in listed) or 1
    outcome.details["archive"] = {
        "entries": len(entries),
        "expanded_bytes": expanded,
        "names": [entry.filename[:200] for entry in listed[:_MAX_LISTED_NAMES]],
    }

    if expanded >= _BOMB_MIN_EXPANDED_BYTES and expanded / compressed >= _BOMB_RATIO:
        findings.append(
            FindingData(
                "high",
                "archive_bomb",
                "Archive expands to an extreme size",
                "The contents are compressed far beyond what normal files achieve. Archives "
                "built this way are designed to exhaust disk space or crash the software that "
                "opens them.",
                SOURCE,
                {"expanded_bytes": expanded, "compression_ratio": round(expanded / compressed)},
            )
        )

    traversal = [
        entry.filename
        for entry in listed
        if entry.filename.startswith(("/", "\\"))
        or ".." in PurePosixPath(entry.filename.replace("\\", "/")).parts
        or re.match(r"^[a-zA-Z]:", entry.filename)
    ]
    if traversal:
        findings.append(
            FindingData(
                "high",
                "path_traversal",
                "Archive tries to write files outside its own folder",
                "Some entries use paths that climb out of the extraction folder. Unpacking "
                "this with vulnerable software could overwrite other files on the device.",
                SOURCE,
                {"entries": [name[:200] for name in traversal[:5]]},
            )
        )

    runnable = [e.filename for e in listed if extension_of(e.filename) in _RUNNABLE_EXTENSIONS]
    if runnable:
        findings.append(
            FindingData(
                "medium",
                "archive_contents",
                "Archive contains programs or scripts",
                "Sending a program inside an archive is a common way to get it past email "
                "filters. Do not run these unless you know exactly what they are.",
                SOURCE,
                {"entries": [name[:200] for name in runnable[:10]]},
            )
        )

    if any(entry.flag_bits & 0x1 for entry in listed):
        findings.append(
            FindingData(
                "low",
                "archive_contents",
                "Archive is password-protected",
                "Encrypted contents cannot be inspected by any scanner. Password-protected "
                "attachments with the password in the same message are a known malware "
                "delivery method.",
                SOURCE,
            )
        )
        outcome.limitations.append("Encrypted archive entries could not be inspected.")
    return findings


def _office_findings(path: Path) -> list[FindingData]:
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()[:_MAX_ARCHIVE_ENTRIES]
    except (zipfile.BadZipFile, OSError):
        return []
    macro_parts = [name for name in names if name.lower().endswith("vbaproject.bin")]
    if not macro_parts:
        return []
    return [
        FindingData(
            "medium",
            "macros",
            "Document contains macros",
            "Macros are small programs embedded in a document. They are the most common way "
            "Office files deliver malware. Do not click “Enable content” unless you trust the "
            "sender and expected a document with macros.",
            SOURCE,
            {"macro_parts": macro_parts[:5]},
        )
    ]


def _pdf_findings(content: bytes) -> list[FindingData]:
    def has(name: bytes) -> bool:
        return re.search(rb"/" + name + rb"(?![A-Za-z])", content) is not None

    findings = []
    has_script = has(b"JavaScript") or has(b"JS")
    auto_action = has(b"OpenAction") or has(b"AA")
    if has(b"Launch"):
        findings.append(
            FindingData(
                "high",
                "pdf_active_content",
                "PDF can launch another program",
                "The document contains a launch action, which asks the reader to start an "
                "external program or file. Ordinary documents have no reason to do this.",
                SOURCE,
                {"pdf_feature": "/Launch"},
            )
        )
    if has_script:
        findings.append(
            FindingData(
                "medium" if auto_action else "low",
                "pdf_active_content",
                "PDF contains JavaScript"
                + (" that runs when the file opens" if auto_action else ""),
                "Scripts inside PDFs are used by interactive forms, but also by exploits that "
                "target outdated PDF readers. Open it only in an up-to-date reader.",
                SOURCE,
                {"pdf_feature": "/JavaScript", "runs_automatically": auto_action},
            )
        )
    if has(b"EmbeddedFile"):
        findings.append(
            FindingData(
                "low",
                "pdf_active_content",
                "PDF carries an embedded file",
                "Another file is attached inside this PDF. Be careful about opening "
                "attachments from within a document.",
                SOURCE,
                {"pdf_feature": "/EmbeddedFile"},
            )
        )
    return findings


def _content_findings(path: Path, filename: str, detected: FileType, outcome: Outcome) -> None:
    with path.open("rb") as handle:
        content = handle.read(_CONTENT_SCAN_BYTES)
    if path.stat().st_size > _CONTENT_SCAN_BYTES:
        megabytes = _CONTENT_SCAN_BYTES // (1024 * 1024)
        outcome.limitations.append(
            f"Only the first {megabytes} MB of the file were searched for suspicious content."
        )

    if _EICAR in content:
        outcome.findings.append(
            FindingData(
                "critical",
                "known_signature",
                "EICAR antivirus test file",
                "This is the standard test pattern used to confirm that a scanner is working. "
                "It is harmless, and it is reported the same way real malware would be.",
                SOURCE,
            )
        )

    if detected is file_types.PDF:
        outcome.findings += _pdf_findings(content)
        outcome.limitations.append(
            "PDF content stored in compressed streams was not unpacked, so active content "
            "hidden there would not be seen."
        )
    elif detected in (file_types.DOCX, file_types.XLSX, file_types.PPTX, file_types.OLE):
        findings, details = macro_findings(path)
        # olevba is authoritative when it can parse the file; the structural check
        # still catches a macro part that olevba could not decode.
        outcome.findings += findings or (
            _office_findings(path) if detected is not file_types.OLE else []
        )
        outcome.details.update(details)
    elif detected in (file_types.ZIP, file_types.JAR, file_types.APK):
        outcome.findings += _archive_findings(path, outcome)
    elif detected is file_types.PE:
        findings, details = pe_findings(path)
        outcome.findings += findings
        outcome.details.update(details)

    if detected.executable:
        outcome.findings.append(
            FindingData(
                "info",
                "executable",
                f"This is a {detected.label.lower()}",
                "Programs can do anything your account is allowed to do. Static checks cannot "
                "tell what a program does when it runs, so only run it if you trust where it "
                "came from.",
                SOURCE,
            )
        )


def hash_reputation_check(db: Session, sha256: str, outcome: Outcome) -> None:
    label, provider = "Known malware hashes", "MalwareBazaar feed (local copy)"
    for match in find_indicators(db, "sha256", sha256):
        outcome.findings.append(
            FindingData(
                "critical",
                "threat_intelligence",
                f"This file is listed as malware by {match.source_name}",
                "The file's fingerprint matches a sample that was submitted and catalogued as "
                "malware. Delete it and do not open it.",
                match.source_name,
                match.evidence(),
            )
        )
    sources = fresh_sources(db, (MALWAREBAZAAR,))
    if not sources:
        outcome.checks.append(
            Check(
                "hash_reputation",
                label,
                provider,
                "unavailable",
                "No recently synchronised malware hash feed is available on this server.",
                core=True,
            )
        )
        return
    outcome.checks.append(
        Check(
            "hash_reputation",
            label,
            provider,
            "completed",
            f"Compared the SHA-256 fingerprint against {sources[0].indicator_count:,} recently "
            "reported samples. Only recent samples are covered.",
            core=True,
        )
    )


def antivirus_check(path: Path, outcome: Outcome) -> None:
    label, provider = "Antivirus signatures", "ClamAV"
    try:
        result = providers.clamav_scan(path)
    except providers.ProviderUnavailableError as exc:
        outcome.checks.append(
            Check("antivirus", label, provider, "unavailable", f"{exc}.", core=True)
        )
        return
    if result.infected:
        outcome.findings.append(
            FindingData(
                "critical",
                "known_signature",
                f"ClamAV identified this file as {result.signature}",
                "The file matches a signature in the ClamAV malware database. Delete it and "
                "do not open it.",
                "ClamAV",
                {"signature": result.signature},
            )
        )
    outcome.checks.append(
        Check(
            "antivirus",
            label,
            provider,
            "completed",
            f"Detected: {result.signature}." if result.infected else "No signature matched.",
            core=True,
        )
    )


def analyze_file(payload: dict[str, Any], db: Session) -> Outcome:
    path = get_settings().upload_dir / payload["storage_name"]
    filename: str = payload["file_name"]
    outcome = Outcome()

    sha256 = sha256_of(path)
    detected = file_types.identify(path)
    outcome.details.update(
        {
            "file_name": filename,
            "size_bytes": path.stat().st_size,
            "sha256": sha256,
            "detected_type": detected.label,
        }
    )
    outcome.checks.append(
        Check(
            "file_identity",
            "File type and fingerprint",
            SOURCE,
            "completed",
            f"Identified from its content as a {detected.label.lower()}.",
        )
    )

    outcome.findings += _name_findings(filename, detected)
    _content_findings(path, filename, detected, outcome)
    outcome.checks.append(
        Check(
            "static_inspection",
            "Structure and embedded content",
            SOURCE,
            "completed",
            "Looked for disguised file types, macros, risky archive contents and, for Windows "
            "programs, their capabilities.",
        )
    )
    yara_check(path, outcome)
    hash_reputation_check(db, sha256, outcome)
    antivirus_check(path, outcome)

    outcome.limitations.append(
        "This is static analysis: the file was inspected, never opened or run. Behaviour that "
        "only shows when a file executes cannot be detected this way."
    )
    return outcome
