"""Screenshot scans: a picture of a chat, SMS, email or web page.

Always: any QR codes in the image are decoded and checked.
With the user's consent (and an AI provider configured): the visible text,
links and phone numbers are transcribed by a vision model, then judged by the
same rules as message and link scans. The model's own opinion is shown but can
never decide the verdict.
"""

from typing import Any

from PIL import Image, UnidentifiedImageError
from sqlalchemy.orm import Session

from app.ai.vision import VisionUnavailableError, read_screenshot
from app.analyzers.message_patterns import RULES
from app.analyzers.message_scan import _rule_finding, normalize_phone
from app.analyzers.qr_scan import classify, decode_image
from app.analyzers.types import Check, FindingData, Outcome
from app.analyzers.url_heuristics import analyze_url_text
from app.analyzers.url_scan import community_finding, indicator_findings
from app.analyzers.urls import InvalidUrlError, parse_url
from app.core.config import get_settings
from app.intel.feeds import COMMUNITY
from app.intel.lookup import find_indicators

SOURCE = "Qalaa screenshot analysis"
_MAX_URLS = 5


def _check_urls(raw_urls: list[str], db: Session, outcome: Outcome) -> list[str]:
    checked: list[str] = []
    for raw in raw_urls:
        try:
            url = parse_url(raw)
        except InvalidUrlError:
            continue
        if url.normalized in checked:
            continue
        checked.append(url.normalized)
        for finding in analyze_url_text(url) + indicator_findings(db, url):
            finding.evidence = {"link": url.normalized, **finding.evidence}
            outcome.findings.append(finding)
        if len(checked) >= _MAX_URLS:
            break
    return checked


def analyze_screenshot(payload: dict[str, Any], db: Session) -> Outcome:
    path = get_settings().upload_dir / payload["storage_name"]
    outcome = Outcome()
    try:
        codes = decode_image(path)
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError):
        outcome.checks.append(
            Check(
                "image",
                "Read the image",
                SOURCE,
                "failed",
                "The file is not an image that can be read.",
            )
        )
        outcome.limitations.append("The file is not an image that can be read.")
        return outcome

    qr_links = [content for content in codes if classify(content)[0] == "url"]
    outcome.checks.append(
        Check(
            "qr_decode",
            "QR codes in the image",
            "zxing-cpp",
            "completed",
            f"Found {len(codes)} QR code(s)." if codes else "No QR codes in the image.",
        )
    )

    texts: list[str] = []
    urls: list[str] = list(qr_links)
    phones: list[str] = []
    if payload.get("ai_consent"):
        try:
            reading = read_screenshot(str(path))
        except VisionUnavailableError as exc:
            outcome.checks.append(
                Check(
                    "ai_reading",
                    "Text in the image",
                    "Language model (with your consent)",
                    "unavailable",
                    f"{exc}.",
                )
            )
            outcome.limitations.append(
                "The text in the image was not read, so only QR codes were checked."
            )
        else:
            texts.append(reading.text)
            urls += reading.urls
            phones += reading.phones
            outcome.details["transcribed_characters"] = len(reading.text)
            outcome.checks.append(
                Check(
                    "ai_reading",
                    "Text in the image",
                    "Language model (with your consent)",
                    "completed",
                    f"Transcribed {len(reading.text)} characters, {len(reading.urls)} link(s) and {len(reading.phones)} phone number(s); "
                    "Qalaa's own rules then judged them.",
                )
            )
            if reading.label == "likely_scam":
                outcome.findings.append(
                    FindingData(
                        "low",
                        "ai_opinion",
                        "An AI model thinks this reads like a scam",
                        (reading.reason or "The content resembles known scams.")
                        + " This is an automated opinion and does not change the verdict on its own.",
                        "Language model (with your consent)",
                        {"model": reading.model},
                    )
                )
    else:
        outcome.limitations.append(
            "The text in the image was not read, because AI reading was not chosen. Paste the "
            "message text into the message scanner, or allow AI reading, for a full check."
        )

    text = "\n".join(texts)
    if text:
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
    checked = _check_urls(urls, db, outcome)
    if checked:
        outcome.checks.append(
            Check(
                "embedded_links",
                "Links in the image",
                "Qalaa URL pattern analysis",
                "completed",
                f"Inspected the address of {len(checked)} link(s) without opening them.",
            )
        )
    for phone in phones:
        for match in find_indicators(db, "phone", normalize_phone(phone)):
            if match.source_key == COMMUNITY:
                outcome.findings.append(community_finding(match, f"The number {phone}"))
    outcome.details["links"] = checked
    outcome.details["phone_numbers"] = phones[:10]
    outcome.limitations.append(
        "A screenshot cannot show where a message really came from. Links were checked by their address only; run a link scan to follow them."
    )
    return outcome
