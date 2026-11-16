"""Fast verdicts for the browser extension.

Runs only local checks (address patterns and the stored indicator database), so it
answers in milliseconds, contacts no third party and never fetches the site. The
full link scanner remains available for a deeper look.
"""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from sqlalchemy.orm import Session

from app.analyzers.types import FindingData
from app.analyzers.url_heuristics import analyze_url_text
from app.analyzers.url_scan import indicator_findings
from app.analyzers.urls import ParsedUrl, parse_url
from app.intel.feeds import THREATFOX, URLHAUS
from app.intel.lookup import fresh_sources
from app.models.base import utcnow

Verdict = Literal["dangerous", "suspicious", "caution", "no_known_threat", "unavailable", "skipped"]

# How long the extension may reuse an answer. Bad news is cached longer than good
# news so a newly listed site is noticed within half an hour.
CACHE_SECONDS: dict[Verdict, int] = {
    "dangerous": 6 * 3600,
    "suspicious": 3600,
    "caution": 3600,
    "no_known_threat": 1800,
    "unavailable": 300,
    "skipped": 86400,
}
_SEVERITY_TO_VERDICT: dict[str, Verdict] = {
    "critical": "dangerous",
    "high": "suspicious",
    "medium": "caution",
}
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_RISKY_DOWNLOAD_EXTENSIONS = frozenset(
    {"exe", "scr", "msi", "bat", "cmd", "com", "vbs", "js", "jse", "wsf", "hta", "ps1", "jar",
     "apk", "lnk", "iso", "img", "dll"}
)  # fmt: skip
_DOCUMENT_EXTENSIONS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png",
                                  "txt", "mp4", "mp3", "zip"})  # fmt: skip
SOURCE = "SENTINEL quick check"


@dataclass
class QuickResult:
    verdict: Verdict
    host: str
    reasons: list[FindingData] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=utcnow)

    @property
    def cache_seconds(self) -> int:
        return CACHE_SECONDS[self.verdict]


def _is_private_ip(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return not address.is_global


def _verdict_for(findings: list[FindingData], reputation_available: bool) -> Verdict:
    for severity in ("critical", "high", "medium"):
        if any(finding.severity == severity for finding in findings):
            return _SEVERITY_TO_VERDICT[severity]
    return "no_known_threat" if reputation_available else "unavailable"


def _evaluate(db: Session, url: ParsedUrl, *, host_only: bool = False) -> QuickResult:
    if url.is_ip_address and _is_private_ip(url.host):
        return QuickResult(
            "skipped",
            url.host,
            limitations=["Addresses on private networks are not checked."],
        )

    findings = analyze_url_text(url) + indicator_findings(db, url)
    feeds = fresh_sources(db, (URLHAUS, THREATFOX))
    result = QuickResult(
        _verdict_for(findings, bool(feeds)),
        url.host,
        reasons=sorted(
            (finding for finding in findings if finding.severity != "info"),
            key=lambda finding: _SEVERITY_ORDER.index(finding.severity),
        ),
        sources=["SENTINEL address patterns"] + [source.name for source in feeds],
    )
    if result.verdict == "unavailable":
        result.limitations.append(
            "The threat database is not up to date on this server, so a clean result could "
            "not be confirmed."
        )
    if host_only:
        result.limitations.append(
            "Only the domain name was checked (privacy mode), so links listed by their full "
            "address cannot be recognised."
        )
    return result


def quick_check_url(db: Session, raw_url: str, *, host_only: bool) -> QuickResult:
    url = parse_url(raw_url)
    if host_only:
        url = parse_url(f"{url.scheme}://{url.host}/")
    return _evaluate(db, url, host_only=host_only)


def quick_check_download(db: Session, raw_url: str, filename: str) -> QuickResult:
    result = _evaluate(db, parse_url(raw_url))
    if result.verdict == "skipped":
        return result

    parts = filename.lower().rsplit("/", 1)[-1].split(".")
    extension = parts[-1] if len(parts) > 1 else ""
    disguised = len(parts) > 2 and parts[-2] in _DOCUMENT_EXTENSIONS
    if disguised and extension in _RISKY_DOWNLOAD_EXTENSIONS:
        result.reasons.append(
            FindingData(
                "high",
                "disguised_file",
                "The file name disguises a program as a document",
                f"“{filename}” ends in “.{parts[-2]}.{extension}”. It will run code when "
                "opened, even though it looks like a document.",
                SOURCE,
                {"file_name": filename},
            )
        )
    elif extension in _RISKY_DOWNLOAD_EXTENSIONS:
        result.reasons.append(
            FindingData(
                "low",
                "download",
                "This download is a program or script",
                "Only run it if you trust where it came from.",
                SOURCE,
                {"file_name": filename},
            )
        )
    result.reasons.sort(key=lambda finding: _SEVERITY_ORDER.index(finding.severity))
    result.verdict = _verdict_for(result.reasons, result.verdict != "unavailable")
    result.limitations.append(
        "The browser does not let extensions read downloaded files, so only the download's "
        "address and name were checked. Scan the file itself for a full check."
    )
    return result
