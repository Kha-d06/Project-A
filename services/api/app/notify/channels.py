"""Replies on messaging channels: Telegram, WhatsApp and email.

Only the verdict, the summary and the top findings are sent back, with a link
to the full report. Links found in scanned content are never echoed.
"""

import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import ScanJob
from app.notify.email import EmailUnavailableError, send_email

logger = logging.getLogger(__name__)
_TIMEOUT = 15

RISK_LABELS = {
    "en": {
        "known_malicious": "🔴 Known malicious",
        "suspicious": "🟠 Suspicious",
        "no_known_threat": "🟢 No known threat (not a guarantee)",
        "inconclusive": "⚪ Inconclusive",
    },
    "ar": {
        "known_malicious": "🔴 ضار معروف",
        "suspicious": "🟠 مشبوه",
        "no_known_threat": "🟢 لا يوجد تهديد معروف (وهذا ليس ضمانًا)",
        "inconclusive": "⚪ غير حاسم",
    },
}


class ChannelUnavailableError(Exception):
    pass


def reply_text(scan: ScanJob, *, include_link: bool = True) -> str:
    locale = "ar" if scan.payload.get("locale") == "ar" else "en"
    if scan.status == "failed":
        return (
            "تعذّر إكمال الفحص. حاول مرة أخرى."
            if locale == "ar"
            else "The scan could not be completed. Please try again."
        )
    lines = [f"Qalaa: {RISK_LABELS[locale].get(scan.risk or 'inconclusive', scan.risk or '')}"]
    if scan.summary:
        lines.append(scan.summary)
    serious = [f for f in scan.findings if f.severity in ("critical", "high", "medium")][:3]
    for finding in serious:
        lines.append(f"• {finding.title}")
    if include_link:
        base = get_settings().public_url.rstrip("/")
        label = "التقرير الكامل" if locale == "ar" else "Full report"
        lines.append(f"{label}: {base}/scan/{scan.id}")
    return "\n".join(lines)[:3500]


def send_telegram(chat_id: int | str, text: str) -> None:
    token = get_settings().telegram_bot_token
    if not token:
        raise ChannelUnavailableError("Telegram is not configured")
    try:
        response = httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise ChannelUnavailableError(f"Telegram did not accept the message ({exc})") from exc


def send_whatsapp(recipient: str, text: str) -> None:
    settings = get_settings()
    if not settings.whatsapp_access_token or not settings.whatsapp_phone_number_id:
        raise ChannelUnavailableError("WhatsApp is not configured")
    try:
        response = httpx.post(
            f"https://graph.facebook.com/v21.0/{settings.whatsapp_phone_number_id}/messages",
            headers={"Authorization": f"Bearer {settings.whatsapp_access_token}"},
            json={
                "messaging_product": "whatsapp",
                "to": recipient,
                "type": "text",
                "text": {"body": text, "preview_url": False},
            },
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise ChannelUnavailableError(f"WhatsApp did not accept the message ({exc})") from exc


def send_reply(db: Session, scan: ScanJob, reply_to: dict[str, Any]) -> None:
    channel = reply_to.get("channel")
    if channel == "telegram":
        send_telegram(reply_to["chat_id"], reply_text(scan))
    elif channel == "whatsapp":
        send_whatsapp(str(reply_to["to"]), reply_text(scan))
    elif channel == "email":
        subject = str(reply_to.get("subject") or "your message")[:120]
        try:
            send_email(db, str(reply_to["to"]), f"Qalaa result: {subject}", reply_text(scan))
        except EmailUnavailableError as exc:
            raise ChannelUnavailableError(str(exc)) from exc
    else:
        raise ChannelUnavailableError(f"Unknown channel {channel!r}")
