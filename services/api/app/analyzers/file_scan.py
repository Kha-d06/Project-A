"""Static inspection of an uploaded file. Nothing here executes or renders the sample."""

import hashlib
import re
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy.orm import Session

from app.analyzers import file_types
from app.analyzers.file_types import FileType, extension_of
from app.analyzers.office_macros import macro_findings
from app.analyzers.pe_info import pe_findings
from app.analyzers.types import Check, FindingData, Outcome, Severity
from app.analyzers.yara_scan import (
    SCAN_TIMEOUT_SECONDS,
    RuleSet,
    apply_allowlist,
    load_rules,
    yara_check,
)
from app.core.config import get_settings
from app.intel import providers
from app.intel.feeds import MALWAREBAZAAR, THREATFOX
from app.intel.lookup import find_indicators, fresh_sources
from app.sandbox.runner import merge_into, run_static_inspection

SOURCE = "Qalaa static file inspection"

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

# Archive members are read into memory, one at a time, under these limits. They
# are never written to disk and never run.
_MAX_MEMBERS_SCANNED = 200
_MAX_MEMBER_BYTES = 10 * 1024 * 1024
_MAX_MEMBERS_TOTAL_BYTES = 50 * 1024 * 1024

# PDF stream decompression limits.
_MAX_PDF_STREAMS = 500
_MAX_PDF_STREAM_BYTES = 2 * 1024 * 1024
_MAX_PDF_INFLATED_BYTES = 16 * 1024 * 1024
_PDF_STREAM = re.compile(
    rb"<<(?:(?!>>\s*stream).){0,2000}?/FlateDecode.{0,2000}?>>\s*stream\r?\n", re.S
)

_EXECUTABLE_MAGIC = ((b"MZ", "Windows program"), (b"\x7fELF", "Linux program"))

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


def _archive_member_findings(path: Path, outcome: Outcome) -> list[FindingData]:
    """Look inside each archive member: fingerprint, disguised programs, the test
    signature and YARA rules. Members are read into memory with a hard cap."""
    findings: list[FindingData] = []
    hashes: list[dict[str, str]] = []
    total = scanned = 0
    try:
        rules = load_rules().rules
    except Exception:  # noqa: BLE001 - YARA is optional for members
        rules = None
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return []
    with archive:
        for entry in archive.infolist()[:_MAX_ARCHIVE_ENTRIES]:
            if entry.is_dir() or entry.flag_bits & 0x1:
                continue
            if scanned >= _MAX_MEMBERS_SCANNED or total >= _MAX_MEMBERS_TOTAL_BYTES:
                outcome.limitations.append(
                    "Only part of the archive's contents was inspected because of size limits."
                )
                break
            if entry.file_size > _MAX_MEMBER_BYTES:
                continue
            try:
                with archive.open(entry) as member:
                    data = member.read(_MAX_MEMBER_BYTES + 1)
            except (zipfile.BadZipFile, NotImplementedError, OSError, RuntimeError, zlib.error):
                continue
            if len(data) > _MAX_MEMBER_BYTES:
                continue  # the directory lied about the size
            scanned += 1
            total += len(data)
            name = entry.filename[:200]
            digest = hashlib.sha256(data).hexdigest()
            hashes.append({"name": name, "sha256": digest})

            if _EICAR in data:
                findings.append(
                    FindingData(
                        "critical",
                        "known_signature",
                        f"EICAR antivirus test file inside the archive ({name})",
                        "The standard antivirus test pattern is inside this archive. It is "
                        "harmless, and it is reported the same way real malware would be.",
                        SOURCE,
                        {"entry": name},
                    )
                )
            ext = extension_of(entry.filename)
            for magic, label in _EXECUTABLE_MAGIC:
                if data.startswith(magic) and ext in _DOCUMENT_EXTENSIONS:
                    findings.append(
                        FindingData(
                            "high",
                            "disguised_file",
                            f"“{name}” is a {label.lower()} disguised as a .{ext} file",
                            "The archive contains a program whose name makes it look like a "
                            "document or picture. This is a classic way to trick people into "
                            "running malware.",
                            SOURCE,
                            {"entry": name, "actual_type": label},
                        )
                    )
            if rules is not None:
                try:
                    matches = rules.match(data=data, timeout=SCAN_TIMEOUT_SECONDS, fast=True)
                except Exception:  # noqa: BLE001 - a rule failure must not stop the scan
                    matches = []
                for match in matches:
                    findings.append(
                        FindingData(
                            "medium",
                            "yara_match",
                            f"{match.meta.get('title', match.rule)} (inside {name})",
                            str(match.meta.get("explanation", "A member matches a signature.")),
                            "Qalaa YARA rules",
                            {"rule": match.rule, "entry": name},
                        )
                    )
    if hashes:
        outcome.details["archive_members"] = hashes[:_MAX_LISTED_NAMES]
        outcome.details["archive_members_scanned"] = scanned
    outcome.details.setdefault("_member_hashes", [h["sha256"] for h in hashes])
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


def inflate_pdf_streams(content: bytes) -> tuple[bytes, int]:
    """Decompress FlateDecode streams so names hidden inside them (often in object
    streams) can be seen. Bounded per stream and in total against zip bombs."""
    inflated: list[bytes] = []
    total = 0
    count = 0
    for match in _PDF_STREAM.finditer(content):
        if count >= _MAX_PDF_STREAMS or total >= _MAX_PDF_INFLATED_BYTES:
            break
        start = match.end()
        end = content.find(b"endstream", start)
        if end == -1:
            break
        decoder = zlib.decompressobj()
        try:
            data = decoder.decompress(
                content[start:end], min(_MAX_PDF_STREAM_BYTES, _MAX_PDF_INFLATED_BYTES - total)
            )
        except zlib.error:
            continue
        count += 1
        total += len(data)
        inflated.append(data)
    return b"\n".join(inflated), count


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
        inflated, streams = inflate_pdf_streams(content)
        outcome.findings += _pdf_findings(content + b"\n" + inflated)
        if streams:
            outcome.details["pdf_streams_unpacked"] = streams
        if _EICAR in inflated:
            outcome.findings.append(
                FindingData(
                    "critical",
                    "known_signature",
                    "EICAR antivirus test file (inside a compressed PDF stream)",
                    "The standard antivirus test pattern is hidden in this PDF. It is harmless, "
                    "and it is reported the same way real malware would be.",
                    SOURCE,
                )
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
        if detected is file_types.ZIP:
            outcome.findings += _archive_member_findings(path, outcome)
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


def static_inspection(
    path: Path,
    filename: str,
    detected: FileType,
    outcome: Outcome,
    rule_set: RuleSet | None = None,
) -> None:
    """The part that parses hostile content. Runs inside the parser jail (app.sandbox)."""
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
    yara_check(path, outcome, rule_set)


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
    member_hashes: list[str] = outcome.details.pop("_member_hashes", [])
    for member_hash in dict.fromkeys(member_hashes):
        for match in find_indicators(db, "sha256", member_hash):
            outcome.findings.append(
                FindingData(
                    "critical",
                    "threat_intelligence",
                    f"A file inside this archive is listed as malware by {match.source_name}",
                    "One of the archive's files matches a catalogued malware sample. Delete "
                    "the archive and do not open anything inside it.",
                    match.source_name,
                    match.evidence(),
                )
            )
    sources = fresh_sources(db, (MALWAREBAZAAR, THREATFOX))
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
            f"Compared the SHA-256 fingerprint against "
            f"{sum(source.indicator_count for source in sources):,} recently "
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


def virustotal_check(sha256: str, outcome: Outcome) -> None:
    """Only with the user's consent, and only the fingerprint: the file is never uploaded."""
    label, provider = "VirusTotal fingerprint lookup", "VirusTotal"
    try:
        result = providers.virustotal_hash(sha256)
    except providers.ProviderUnavailableError as exc:
        outcome.checks.append(Check("virustotal", label, provider, "unavailable", f"{exc}."))
        return
    if not result.known:
        outcome.checks.append(
            Check(
                "virustotal",
                label,
                provider,
                "completed",
                "VirusTotal has never seen this file. That is common for personal documents and "
                "new files; it says nothing about safety.",
            )
        )
        return
    outcome.details["virustotal"] = {
        "malicious": result.malicious,
        "suspicious": result.suspicious,
        "engines": result.engines,
        "label": result.label,
    }
    if result.malicious >= 3:
        outcome.findings.append(
            FindingData(
                "critical",
                "known_signature",
                f"{result.malicious} of {result.engines} antivirus engines flag this file",
                "VirusTotal has scanned this exact file before and several independent "
                "antivirus engines identified it as malicious"
                + (f" ({result.label})" if result.label else "")
                + ". Delete it.",
                provider,
                {"malicious": result.malicious, "engines": result.engines, "label": result.label},
            )
        )
    elif result.malicious or result.suspicious:
        outcome.findings.append(
            FindingData(
                "medium",
                "known_signature",
                f"{result.malicious + result.suspicious} of {result.engines} antivirus engines "
                "flag this file",
                "A small number of engines flagged it. Single detections are sometimes false "
                "alarms, but treat the file with caution.",
                provider,
                {"malicious": result.malicious, "suspicious": result.suspicious},
            )
        )
    outcome.checks.append(
        Check(
            "virustotal",
            label,
            provider,
            "completed",
            f"Known to VirusTotal: {result.malicious} of {result.engines} engines flag it.",
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
    # Everything that parses the file's contents runs in a separate, jailed process.
    merge_into(outcome, run_static_inspection(path, filename))
    apply_allowlist(outcome, sha256)
    hash_reputation_check(db, sha256, outcome)
    antivirus_check(path, outcome)
    if payload.get("virustotal_consent"):
        virustotal_check(sha256, outcome)

    outcome.limitations.append(
        "This is static analysis: the file was inspected, never opened or run. Behaviour that "
        "only shows when a file executes cannot be detected this way."
    )
    return outcome
