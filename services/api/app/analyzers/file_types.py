"""File type identification from content. The file name is never trusted for this."""

import zipfile
from dataclasses import dataclass
from pathlib import Path

_HEADER_BYTES = 4096
_OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
_MACHO_MAGICS = {bytes.fromhex(m) for m in ("feedface", "feedfacf", "cefaedfe", "cffaedfe")}


@dataclass(frozen=True)
class FileType:
    key: str
    label: str
    extensions: frozenset[str]
    executable: bool = False


def _file_type(key: str, label: str, *extensions: str, executable: bool = False) -> FileType:
    return FileType(key, label, frozenset(extensions), executable)


PDF = _file_type("pdf", "PDF document", "pdf")
ZIP = _file_type("zip", "ZIP archive", "zip")
DOCX = _file_type("docx", "Word document", "docx", "docm", "dotx", "dotm")
XLSX = _file_type("xlsx", "Excel workbook", "xlsx", "xlsm", "xltx", "xltm")
PPTX = _file_type("pptx", "PowerPoint presentation", "pptx", "pptm", "ppsx")
APK = _file_type("apk", "Android app package", "apk", executable=True)
JAR = _file_type("jar", "Java archive", "jar", executable=True)
OLE = _file_type("ole", "Legacy Office document", "doc", "xls", "ppt", "msg", "msi")
PE = _file_type(
    "pe", "Windows program", "exe", "dll", "scr", "sys", "com", "cpl", "ocx", executable=True
)
ELF = _file_type("elf", "Linux program", "", "so", "bin", "elf", executable=True)
MACHO = _file_type("macho", "macOS program", "", "dylib", executable=True)
PNG = _file_type("png", "PNG image", "png")
JPEG = _file_type("jpeg", "JPEG image", "jpg", "jpeg")
GIF = _file_type("gif", "GIF image", "gif")
TEXT = _file_type("text", "Text file")
BINARY = _file_type("binary", "Unrecognised binary data")

SCRIPT_EXTENSIONS = frozenset({"js", "py", "ps1", "vbs", "bat", "cmd", "sh", "hta", "wsf", "jse"})


def extension_of(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _zip_subtype(path: Path) -> FileType:
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist()[:5000])
    except (zipfile.BadZipFile, OSError):
        return ZIP
    if "AndroidManifest.xml" in names and "classes.dex" in names:
        return APK
    if "[Content_Types].xml" in names:
        if any(name.startswith("word/") for name in names):
            return DOCX
        if any(name.startswith("xl/") for name in names):
            return XLSX
        if any(name.startswith("ppt/") for name in names):
            return PPTX
    if "META-INF/MANIFEST.MF" in names:
        return JAR
    return ZIP


def _looks_like_text(header: bytes) -> bool:
    if b"\0" in header:
        return header[:2] in (b"\xff\xfe", b"\xfe\xff")  # UTF-16 with a byte-order mark
    try:
        header.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A multi-byte character cut off by the read boundary is still text.
        return exc.start >= len(header) - 4
    return True


def identify(path: Path) -> FileType:
    with path.open("rb") as handle:
        header = handle.read(_HEADER_BYTES)

    if header.startswith(b"%PDF-"):
        return PDF
    if header.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return _zip_subtype(path)
    if header.startswith(_OLE_MAGIC):
        return OLE
    if header.startswith(b"MZ"):
        return PE
    if header.startswith(b"\x7fELF"):
        return ELF
    if header[:4] in _MACHO_MAGICS:
        return MACHO
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return PNG
    if header.startswith(b"\xff\xd8\xff"):
        return JPEG
    if header.startswith((b"GIF87a", b"GIF89a")):
        return GIF
    if not header or _looks_like_text(header):
        return TEXT
    return BINARY
