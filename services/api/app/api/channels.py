"""Ways to scan without opening the website: Telegram, WhatsApp and email.

Each channel turns what it receives into an ordinary scan (a link scan for a
lone link, otherwise a message scan; email attachments become file scans) and
the task worker replies with the verdict when the scan finishes. Nothing
received this way is attached to an account, and message text is discarded
after the scan like any other message scan.
"""

import contextlib
import hashlib
import hmac
import io
import json
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.analyzers.message_scan import MAX_MESSAGE_LENGTH
from app.analyzers.urls import InvalidUrlError, parse_url
from app.api.deps import Db
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.notify.channels import ChannelUnavailableError, send_telegram, send_whatsapp
from app.scans import service
from app.scans.storage import store_sample

router = APIRouter(tags=["Bots and email"])

CHAT_LIMIT = RateLimit("channel-chat", max_requests=30, window_seconds=3600)
EMAIL_LIMIT = RateLimit("channel-email", max_requests=20, window_seconds=3600)
MAX_EMAIL_BYTES = 15 * 1024 * 1024
MAX_ATTACHMENTS = 3
_ARABIC = re.compile(r"[؀-ۿ]")
_MIN_TEXT = 10

HELP = {
    "en": (
        "Send me a link or paste a suspicious message, and I will check it with Qalaa. "
        "I reply with the verdict and a link to the full report. Messages are analysed and "
        "then discarded. I never say something is safe: at best, no known threat was found."
    ),
    "ar": (
        "أرسل لي رابطًا أو الصق رسالة مشبوهة وسأفحصها باستخدام قلعة، ثم أرد عليك بالنتيجة "
        "ورابط للتقرير الكامل. تُحلَّل الرسائل ثم تُحذف. لا أقول أبدًا إن شيئًا آمن؛ في أفضل "
        "الأحوال لم يُعثر على تهديد معروف."
    ),
}
TOO_SHORT = {
    "en": "That is too short to check. Send a full link or paste the whole message.",
    "ar": "النص قصير جدًا لفحصه. أرسل رابطًا كاملًا أو الصق الرسالة كلها.",
}


def _locale(text: str) -> str:
    return "ar" if _ARABIC.search(text) else "en"


def scan_text(db: Session, text: str, reply_to: dict[str, Any]) -> str | None:
    """Starts the right kind of scan. Returns an immediate reply if none was started."""
    text = text.strip()[:MAX_MESSAGE_LENGTH]
    locale = _locale(text)
    if text.lower() in ("/start", "/help", "help", "مساعدة"):
        return HELP[locale]
    lone_link = None
    if " " not in text and "\n" not in text:
        try:
            lone_link = parse_url(text).normalized
        except InvalidUrlError:
            lone_link = None
    if lone_link:
        service.create_scan(
            db,
            scan_type="url",
            target=lone_link,
            payload={"url": lone_link, "reply_to": reply_to},
            user=None,
            locale=locale,
        )
        return None
    if len(text) < _MIN_TEXT:
        return TOO_SHORT[locale]
    excerpt = " ".join(text.split())[:80]
    service.create_scan(
        db,
        scan_type="message",
        target=excerpt,
        payload={"content": text, "reply_to": reply_to},
        user=None,
        locale=locale,
    )
    return None


# --- Telegram -------------------------------------------------------------------------


@router.post("/bots/telegram", include_in_schema=False)
async def telegram_update(request: Request, db: Db) -> dict[str, bool]:
    settings = get_settings()
    secret = settings.telegram_webhook_secret
    if not settings.telegram_bot_token or not secret:
        raise ApiError(404, "not_found", "Not found.")
    supplied = request.headers.get("x-telegram-bot-api-secret-token", "")
    if not hmac.compare_digest(supplied, secret):
        raise ApiError(403, "forbidden", "Invalid secret token.")
    try:
        update = json.loads(await request.body())
    except ValueError:
        return {"ok": True}
    message = update.get("message") or update.get("edited_message") or {}
    chat_id = (message.get("chat") or {}).get("id")
    text = message.get("text") or message.get("caption")
    if chat_id is None or not isinstance(text, str):
        return {"ok": True}
    rate_limit.enforce(CHAT_LIMIT, f"telegram:{chat_id}")
    reply = scan_text(db, text, {"channel": "telegram", "chat_id": chat_id})
    if reply:
        with contextlib.suppress(ChannelUnavailableError):
            send_telegram(chat_id, reply)
    return {"ok": True}


# --- WhatsApp Cloud API ---------------------------------------------------------------


@router.get("/bots/whatsapp", include_in_schema=False, response_class=PlainTextResponse)
def whatsapp_verify(
    mode: str = Query("", alias="hub.mode"),
    token: str = Query("", alias="hub.verify_token"),
    challenge: str = Query("", alias="hub.challenge"),
) -> str:
    expected = get_settings().whatsapp_verify_token
    if mode == "subscribe" and expected and hmac.compare_digest(token, expected):
        return challenge[:200]
    raise ApiError(403, "forbidden", "Verification failed.")


@router.post("/bots/whatsapp", include_in_schema=False)
async def whatsapp_update(request: Request, db: Db) -> dict[str, bool]:
    settings = get_settings()
    if not settings.whatsapp_app_secret or not settings.whatsapp_access_token:
        raise ApiError(404, "not_found", "Not found.")
    body = await request.body()
    expected = (
        "sha256="
        + hmac.new(settings.whatsapp_app_secret.encode(), body, hashlib.sha256).hexdigest()
    )
    if not hmac.compare_digest(request.headers.get("x-hub-signature-256", ""), expected):
        raise ApiError(403, "forbidden", "Invalid signature.")
    try:
        payload = json.loads(body)
    except ValueError:
        return {"ok": True}
    for entry in payload.get("entry", [])[:10]:
        for change in entry.get("changes", [])[:10]:
            for message in (change.get("value") or {}).get("messages", [])[:10]:
                sender = message.get("from")
                text = (message.get("text") or {}).get("body")
                if not sender or not isinstance(text, str):
                    continue
                rate_limit.enforce(CHAT_LIMIT, f"whatsapp:{sender}")
                reply = scan_text(db, text, {"channel": "whatsapp", "to": sender})
                if reply:
                    with contextlib.suppress(ChannelUnavailableError):
                        send_whatsapp(sender, reply)
    return {"ok": True}


# --- Scan by email --------------------------------------------------------------------


def _authentication_failed(message: EmailMessage) -> bool:
    """Drop mail the receiving provider marked as failing DMARC: the sender address
    is probably forged, and replying would send our mail to a bystander."""
    results = " ".join(str(v) for v in message.get_all("Authentication-Results", []))
    return "dmarc=fail" in results.lower()


def _body_text(message: EmailMessage) -> str:
    part = message.get_body(preferencelist=("plain", "html"))
    if part is None:
        return ""
    content = part.get_content()
    if part.get_content_type() == "text/html":
        content = re.sub(r"<(script|style)\b.*?</\1>", " ", content, flags=re.S | re.I)
        content = re.sub(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>", r" \1 ", content, flags=re.I)
        content = re.sub(r"<[^>]+>", " ", content)
    return str(content)


@router.post("/inbound/email", status_code=202, include_in_schema=False)
async def inbound_email(request: Request, db: Db) -> dict[str, int]:
    settings = get_settings()
    token = settings.inbound_email_token
    if not token:
        raise ApiError(404, "not_found", "Not found.")
    supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied, token):
        raise ApiError(403, "forbidden", "Invalid token.")
    raw = await request.body()
    if len(raw) > MAX_EMAIL_BYTES:
        raise ApiError(413, "too_large", "Message too large.")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    if not isinstance(message, EmailMessage):
        return {"scans": 0}
    # Reply to the From address only (the one DMARC protects), never Reply-To,
    # which anyone can set to a bystander's address.
    sender = parseaddr(str(message.get("From") or ""))[1].lower()
    auto = str(message.get("Auto-Submitted", "no")).lower() != "no"
    own = settings.inbound_email_address and sender == settings.inbound_email_address.lower()
    if not sender or "@" not in sender or auto or own or _authentication_failed(message):
        return {"scans": 0}
    rate_limit.enforce(EMAIL_LIMIT, f"email:{sender}")
    subject = str(message.get("Subject", ""))[:150]
    reply_to = {"channel": "email", "to": sender, "subject": subject}

    scans = 0
    text = f"{subject}\n\n{_body_text(message)}".strip()
    if len(text) >= _MIN_TEXT:
        scan_text(db, text, reply_to)
        scans += 1
    for part in list(message.iter_attachments())[:MAX_ATTACHMENTS]:
        content = part.get_payload(decode=True)
        if not isinstance(content, bytes) or not content:
            continue
        name = re.sub(r"[\x00-\x1f\x7f/\\]", "_", part.get_filename() or "attachment")[-255:]
        try:
            storage_name, _ = store_sample(io.BytesIO(content))
        except ApiError:
            continue  # too large to scan
        service.create_scan(
            db,
            scan_type="file",
            target=name,
            payload={"storage_name": storage_name, "file_name": name, "reply_to": reply_to},
            user=None,
            locale=_locale(subject),
        )
        scans += 1
    return {"scans": scans}
