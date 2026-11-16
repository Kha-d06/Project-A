"""Outgoing email.

Three backends, chosen by SENTINEL_EMAIL_BACKEND:
* smtp: real delivery through the configured SMTP server (STARTTLS by default);
* outbox: messages are stored in the outbox_emails table, for development and tests;
* disabled: nothing is sent, and features that depend on email say so.
"""

import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr, parseaddr

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import OutboxEmail

logger = logging.getLogger(__name__)
_SMTP_TIMEOUT_SECONDS = 20


class EmailUnavailableError(Exception):
    pass


def email_enabled() -> bool:
    settings = get_settings()
    if settings.email_backend == "smtp":
        return bool(settings.smtp_host)
    return settings.email_backend == "outbox"


def send_email(db: Session, recipient: str, subject: str, body: str) -> None:
    """Plain-text email only: no remote images, no tracking, nothing to render."""
    settings = get_settings()
    if not email_enabled():
        raise EmailUnavailableError("Email delivery is not configured on this server.")
    if settings.email_backend == "outbox":
        db.add(OutboxEmail(recipient=recipient, subject=subject, body=body))
        db.commit()
        return

    message = EmailMessage()
    name, address = parseaddr(settings.email_from)
    message["From"] = formataddr((name, address))
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(
            settings.smtp_host or "", settings.smtp_port, timeout=_SMTP_TIMEOUT_SECONDS
        ) as smtp:
            if settings.smtp_starttls:
                smtp.starttls()
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password or "")
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        logger.warning(
            "Email to %s could not be sent: %s", recipient.split("@")[-1], type(exc).__name__
        )
        raise EmailUnavailableError("The email could not be sent. Please try again later.") from exc
