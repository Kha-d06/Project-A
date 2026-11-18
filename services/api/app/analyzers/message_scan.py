import re
from typing import Any

from sqlalchemy.orm import Session

from app.ai.classify import ClassificationUnavailableError, classify_message
from app.analyzers.message_patterns import (
    EMAIL_PATTERN,
    PHONE_PATTERN,
    RULES,
    URL_PATTERN,
    MessageRule,
)
from app.analyzers.types import Check, FindingData, Outcome
from app.analyzers.url_heuristics import BRAND_DOMAINS, analyze_url_text, brand_name
from app.analyzers.url_scan import community_finding, indicator_findings
from app.analyzers.urls import InvalidUrlError, ParsedUrl, parse_url
from app.intel.feeds import COMMUNITY, THREATFOX, URLHAUS
from app.intel.lookup import find_indicators, fresh_sources

SOURCE = "Qalaa message pattern analysis"
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


# Words that show a message claims to come from an institution.
_INSTITUTION = re.compile(
    r"\b(bank|banking|ministry|government|police|customs|post|courier|tax|visa|immigration|"
    r"absher|uae ?pass|nafath|salik|aramex|dhl|fedex)\b|بنك|مصرف|وزارة|شرطة|الجمارك|البريد|"
    r"الضريبة|الجوازات|أبشر|ابشر|نفاذ|سالك",
    re.IGNORECASE,
)


def _sender_check(sender: str, text: str, db: Session, outcome: Outcome) -> None:
    """Banks and government bodies in the Gulf send SMS from registered sender names
    (such as AD-ENBD), not from personal mobile numbers."""
    digits = re.sub(r"\D", "", sender)
    outcome.details["sender"] = sender
    if len(digits) < 7:
        return
    phone = normalize_phone(sender)
    claim = _INSTITUTION.search(text)
    brand = next(
        (b for b in BRAND_DOMAINS if len(b) >= 4 and b in text.lower().replace(" ", "")), None
    )
    if claim or brand:
        named = brand_name(brand) if brand else claim.group(0) if claim else "an organisation"
        outcome.findings.append(
            FindingData(
                "medium",
                "personal_number_sender",
                f"Claims to be from {named} but was sent from a personal phone number",
                "Banks, couriers and government services send text messages from registered "
                "sender names, not from ordinary mobile numbers. A message like this from a "
                "personal number is a common scam pattern.",
                SOURCE,
                {"sender": sender[:60]},
            )
        )
    for match in find_indicators(db, "phone", phone):
        if match.source_key == COMMUNITY:
            outcome.findings.append(community_finding(match, f"The sender {sender[:30]}"))


def _ai_check(text: str, outcome: Outcome) -> None:
    label, provider = "AI second opinion", "Language model (with your consent)"
    try:
        result = classify_message(text)
    except ClassificationUnavailableError as exc:
        outcome.checks.append(Check("ai_classification", label, provider, "unavailable", f"{exc}."))
        return
    outcome.details["ai_opinion"] = {"label": result.label, "reason": result.reason}
    if result.label == "likely_scam":
        outcome.findings.append(
            FindingData(
                "low",
                "ai_opinion",
                "An AI model thinks this reads like a scam",
                (result.reason or "The wording resembles known scam messages.")
                + " This is an automated opinion and does not change the verdict on its own.",
                provider,
                {"model": result.model},
            )
        )
    readable = result.label.replace("_", " ")
    outcome.checks.append(
        Check(
            "ai_classification",
            label,
            provider,
            "completed",
            f"The model's view: {readable}. Links, emails and numbers were masked before sending.",
        )
    )


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
    feed_available = bool(fresh_sources(db, (URLHAUS, THREATFOX)))
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
                "Qalaa URL pattern analysis",
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
    sender = str(payload.get("sender") or "").strip()
    if sender:
        _sender_check(sender, text, db, outcome)
    if payload.get("ai_consent"):
        _ai_check(text, outcome)
    outcome.limitations.append(
        "This analysis recognises common scam wording. A well-written or unusual scam may "
        "not match any pattern, and a genuine message can occasionally match one."
    )
    return outcome
