"""Weekly safety summary: what SENTINEL caught for you in the last seven days."""

import uuid
from collections import Counter
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import CommunityReport, ExtensionEvent, ScanJob, User, UserSettings
from app.models.base import utcnow
from app.notify.email import EmailUnavailableError, email_enabled, send_email
from app.notify.push import send_push

TIPS = (
    "Banks and government services never ask for one-time codes. Anyone who asks for one is trying to take over an account.",
    "Before paying a fine or delivery fee from a text message, open the official app yourself instead of the link.",
    "Turn on two-step verification for your email first: it protects the password resets of every other account.",
    "A caller who rushes you is a warning sign. Hang up and call back on a number you already know.",
    "QR codes on parking machines and posters can be stickers placed over the real ones. Check before you pay.",
)


def build_summary(db: Session, user_id: uuid.UUID, days: int = 7) -> dict[str, Any]:
    since = utcnow() - timedelta(days=days)
    risks = Counter(
        dict(
            db.execute(
                select(ScanJob.risk, func.count())
                .where(
                    ScanJob.user_id == user_id,
                    ScanJob.created_at >= since,
                    ScanJob.risk.is_not(None),
                )
                .group_by(ScanJob.risk)
            ).all()
        )
    )
    browsing = Counter(
        dict(
            db.execute(
                select(ExtensionEvent.kind, func.count())
                .where(ExtensionEvent.user_id == user_id, ExtensionEvent.created_at >= since)
                .group_by(ExtensionEvent.kind)
            ).all()
        )
    )
    reports_verified = db.scalar(
        select(func.count())
        .select_from(CommunityReport)
        .where(CommunityReport.status == "verified", CommunityReport.reviewed_at >= since)
    )
    week = int(utcnow().strftime("%W"))
    return {
        "days": days,
        "scans": sum(risks.values()),
        "known_malicious": risks.get("known_malicious", 0),
        "suspicious": risks.get("suspicious", 0),
        "browser_warnings": browsing.get("warning_shown", 0) + browsing.get("download_warning", 0),
        "community_reports_verified": reports_verified or 0,
        "tip": TIPS[week % len(TIPS)],
    }


def summary_text(summary: dict[str, Any]) -> str:
    base = get_settings().public_url.rstrip("/")
    caught = summary["known_malicious"] + summary["suspicious"]
    lines = [
        f"In the last {summary['days']} days:",
        f"- You ran {summary['scans']} scan(s); {caught} needed attention "
        f"({summary['known_malicious']} known threat(s), {summary['suspicious']} suspicious).",
        f"- SENTINEL Protect warned you {summary['browser_warnings']} time(s) while browsing"
        + (
            " (only counted if you chose to keep warning history)."
            if summary["browser_warnings"] == 0
            else "."
        ),
        f"- Moderators confirmed {summary['community_reports_verified']} new scam report(s) from the community.",
        "",
        f"Tip of the week: {summary['tip']}",
        "",
        f"Your dashboard: {base}/dashboard",
        f"Stop these emails: {base}/dashboard/settings",
    ]
    return "\n".join(lines)


def send_weekly_summaries(db: Session) -> int:
    sent = 0
    users = db.scalars(
        select(User)
        .join(UserSettings, UserSettings.user_id == User.id)
        .where(UserSettings.weekly_summary.is_(True), User.disabled_at.is_(None))
    ).all()
    for user in users:
        summary = build_summary(db, user.id)
        if email_enabled() and user.email_verified_at is not None:
            try:
                send_email(db, user.email, "Your weekly SENTINEL summary", summary_text(summary))
                db.commit()
                sent += 1
            except EmailUnavailableError:
                pass
        caught = summary["known_malicious"] + summary["suspicious"]
        send_push(
            db,
            user.id,
            "Your weekly SENTINEL summary",
            f"{summary['scans']} scans, {caught} needed attention. {summary['tip'][:90]}",
            "/dashboard",
        )
    return sent
