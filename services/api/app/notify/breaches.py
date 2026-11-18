"""Breach monitoring: a weekly re-check of opted-in users' own email addresses
against Have I Been Pwned. Only breaches not reported before are announced."""

import contextlib
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ApiError
from app.models import User, UserSettings
from app.notify.email import EmailUnavailableError, email_enabled, send_email
from app.notify.push import send_push

logger = logging.getLogger(__name__)


def check_breaches(db: Session) -> int:
    """Returns how many users were told about new breaches."""
    from app.api.breach import hibp_breaches

    if not get_settings().hibp_api_key:
        return 0
    told = 0
    rows = db.execute(
        select(User, UserSettings)
        .join(UserSettings, UserSettings.user_id == User.id)
        .where(UserSettings.breach_monitoring.is_(True), User.disabled_at.is_(None))
    ).all()
    for user, settings in rows:
        if email_enabled() and user.email_verified_at is None:
            continue  # only confirmed addresses are monitored
        try:
            breaches = hibp_breaches(user.email)
        except ApiError as exc:
            logger.info("Breach check skipped: %s", exc.message)
            break  # service unavailable or rate limited: try again next week
        known = set(settings.known_breaches or [])
        new = [item for item in breaches if str(item.get("Name")) not in known]
        if not new:
            continue
        settings.known_breaches = sorted(known | {str(item.get("Name")) for item in breaches})
        db.commit()
        names = ", ".join(str(item.get("Title") or item.get("Name")) for item in new[:10])
        base = get_settings().public_url.rstrip("/")
        body = (
            f"Your email address appeared in {len(new)} newly listed data breach(es): {names}.\n\n"
            "Change the password on those sites and anywhere you reused it, and turn on two-step "
            f"verification.\n\nDetails: {base}/dashboard/breach\n"
        )
        if email_enabled():
            try:
                send_email(db, user.email, "SENTINEL: your email appeared in a data breach", body)
                db.commit()
            except EmailUnavailableError:
                pass
        send_push(
            db,
            user.id,
            "New data breach found",
            f"Your email appeared in: {names[:120]}",
            "/dashboard/breach",
        )
        told += 1
    return told


def check_identities(db: Session) -> int:
    """Weekly check of confirmed extra addresses (identity monitoring). New
    breaches are emailed to the account holder. Returns how many addresses had
    new breaches."""
    from app.api.breach import hibp_breaches
    from app.api.identity import breach_summary
    from app.models import MonitoredIdentity
    from app.models.base import utcnow

    if not get_settings().hibp_api_key:
        return 0
    found = 0
    rows = db.execute(
        select(MonitoredIdentity, User)
        .join(User, User.id == MonitoredIdentity.user_id)
        .where(MonitoredIdentity.verified_at.is_not(None), User.disabled_at.is_(None))
        .order_by(MonitoredIdentity.last_checked_at.asc().nulls_first())
    ).all()
    for item, user in rows:
        try:
            breaches = breach_summary(hibp_breaches(item.value))
        except ApiError as exc:
            logger.info("Identity check paused: %s", exc.message)
            break  # unavailable or rate limited: the oldest-checked go first next time
        known = {str(b.get("name")) for b in item.known_breaches or [] if isinstance(b, dict)}
        new = [b for b in breaches if b["name"] not in known]
        item.known_breaches = breaches
        item.last_checked_at = utcnow()
        db.commit()
        if not new:
            continue
        found += 1
        names = ", ".join(str(b["title"]) for b in new[:10])
        base = get_settings().public_url.rstrip("/")
        body = (
            f"{item.value}, one of the addresses you asked SENTINEL to watch, appeared in "
            f"{len(new)} newly listed data breach(es): {names}.\n\n"
            "Change the password on those sites and anywhere you reused it, and turn on two-step "
            f"verification.\n\nDetails: {base}/dashboard/breach\n"
        )
        if email_enabled():
            with contextlib.suppress(EmailUnavailableError):
                send_email(
                    db, user.email, "SENTINEL: a monitored address appeared in a breach", body
                )
        send_push(
            db,
            user.id,
            "New data breach found",
            f"{item.value}: {names[:100]}",
            "/dashboard/breach",
        )
    return found
