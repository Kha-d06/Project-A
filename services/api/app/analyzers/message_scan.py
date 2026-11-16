import re
from typing import Any

from sqlalchemy.orm import Session

from app.analyzers.message_patterns import (
    EMAIL_PATTERN,
    PHONE_PATTERN,
    RULES,
    URL_PATTERN,
    MessageRule,
)
from app.analyzers.types import Check, FindingData, Outcome
from app.analyzers.url_heuristics import analyze_url_text
from app.analyzers.url_scan import community_finding, indicator_findings
from app.analyzers.urls import InvalidUrlError, ParsedUrl, parse_url
from app.intel.feeds import COMMUNITY, URLHAUS
from app.intel.lookup import find_indicators, fresh_sources

SOURCE = "SENTINEL message pattern analysis"
MAX_MESSAGE_LENGTH = 10_000
_MAX_URLS_CHECKED = 10
_EXCERPT_CONTEXT = 30
_MIN_PHONE_DIGITS = 9


def _excerpt(text: str, match: re.Match[str]) -> str:
    start = max(0, match.start() - _EXCERPT_CONTEXT)
    end = min(len(text), match.end() + _EXCERPT_CONTEXT)
    snippet = " ".join(text[start:end].split())
    return f"{'…' if start else ''}{snippet}{'…' if end < len(text) else ''}"


def _rule_finding(rule: MessageRule, text: str, arabic: bool = False) -> FindingData | None:
    for pattern in rule.patterns:
        match = pattern.search(text)
        if match:
            return FindingData(
                rule.severity,
                rule.category,
                rule.title_ar if arabic and rule.title_ar else rule.title,
                rule.explanation_ar if arabic and rule.explanation_ar else rule.explanation,
                SOURCE,
                {"matched_text": _excerpt(text, match)},
            )
    return None


def extract_urls(text: str) -> list[ParsedUrl]:
    urls: dict[str, ParsedUrl] = {}
    without_emails = EMAIL_PATTERN.sub(" ", text)
    for match in URL_PATTERN.finditer(without_emails):
        try:
            parsed = parse_url(match.group().rstrip(".,;:!?)»”"))
        except InvalidUrlError:
            continue
        urls.setdefault(parsed.normalized, parsed)
    return list(urls.values())


def normalize_phone(raw: str) -> str:
    """Digits only. International numbers, written with + or 00, become +<digits>."""
    digits = re.sub(r"\D", "", raw)
    if raw.strip().startswith("+"):
        return f"+{digits}"
    if digits.startswith("00"):
        return f"+{digits[2:]}"
    return digits


def _extract_phones(text: str) -> list[str]:
    phones = []
    for match in PHONE_PATTERN.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if len(digits) >= _MIN_PHONE_DIGITS:
            phones.append(match.group().strip())
    return list(dict.fromkeys(phones))


def analyze_message(payload: dict[str, Any], db: Session) -> Outcome:
    text: str = payload["content"]
    outcome = Outcome()

    arabic = payload.get("locale") == "ar"
    for rule in RULES:
        finding = _rule_finding(rule, text, arabic)
        if finding:
            outcome.findings.append(finding)
    outcome.checks.append(
        Check(
            "message_patterns",
            "Scam and phishing language",
            SOURCE,
            "completed",
            f"Compared the text against {len(RULES)} manipulation patterns in English and Arabic.",
            core=True,
        )
    )

    urls = extract_urls(text)
    checked = urls[:_MAX_URLS_CHECKED]
    feed_available = bool(fresh_sources(db, (URLHAUS,)))
    for url in checked:
        for finding in analyze_url_text(url):
            finding.evidence = {"link": url.normalized, **finding.evidence}
            outcome.findings.append(finding)
        outcome.findings += indicator_findings(db, url)

    if urls:
        outcome.checks.append(
            Check(
                "embedded_links",
                "Links in the message",
                "SENTINEL URL pattern analysis",
                "completed",
                f"Inspected the address of {len(checked)} link{'s' if len(checked) != 1 else ''}"
                " without opening " + ("it." if len(checked) == 1 else "them."),
            )
        )
        outcome.checks.append(
            Check(
                "local_threat_feed",
                "Known malicious links",
                "URLhaus feed (local copy)",
                "completed" if feed_available else "unavailable",
                "Compared the links against the local threat feed."
                if feed_available
                else "No recently synchronised threat feed is available on this server.",
            )
        )
        outcome.limitations.append(
            "Links in the message were not opened. Run a link scan on any of them to check "
            "redirects, certificates and domain age."
        )
    if len(urls) > _MAX_URLS_CHECKED:
        outcome.limitations.append(
            f"The message contains {len(urls)} links; only the first {_MAX_URLS_CHECKED} "
            "were inspected."
        )

    phones = _extract_phones(text)
    for phone in phones:
        for match in find_indicators(db, "phone", normalize_phone(phone)):
            if match.source_key == COMMUNITY:
                outcome.findings.append(community_finding(match, f"The number {phone}"))

    outcome.details["indicators"] = {
        "urls": [url.normalized for url in urls],
        "emails": list(dict.fromkeys(EMAIL_PATTERN.findall(text))),
        "phone_numbers": phones,
    }
    outcome.details["character_count"] = len(text)
    outcome.limitations.append(
        "This analysis recognises common scam wording. A well-written or unusual scam may "
        "not match any pattern, and a genuine message can occasionally match one."
    )
    return outcome
