"""Community reports: submission, duplicate detection and moderation.

Reports are unverified claims. Nothing a reporter writes is shown publicly; only
a moderator-verified report becomes visible, and then only its category and
subject. Verified websites and phone numbers are added to the indicator store so
scans can warn about them.
"""

import hashlib
import logging
import re
import uuid
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.analyzers.message_scan import normalize_phone
from app.analyzers.urls import InvalidUrlError, indicator_digest, parse_url
from app.core.errors import ApiError
from app.intel.feeds import COMMUNITY, FeedIndicator, get_or_create_source, store_indicators
from app.models import CommunityReport, ThreatIndicator, User
from app.models.base import utcnow

COMMUNITY_SOURCE_NAME = "SENTINEL community reports (moderator-verified)"
logger = logging.getLogger(__name__)
# Scam sites are abandoned within weeks; phone numbers get reassigned. A verified
# report stops protecting after this, unless a moderator verifies it again.
VERIFICATION_LIFETIME = {"phone_number": timedelta(days=365)}
DEFAULT_VERIFICATION_LIFETIME = timedelta(days=180)
_MIN_PHONE_DIGITS = 7


def normalize_subject(category: str, subject: str) -> str:
    """The canonical form of what is being reported. Raises ApiError if unusable."""
    text = " ".join(subject.split())
    if category == "website":
        try:
            url = parse_url(text)
        except InvalidUrlError as exc:
            raise ApiError(422, "invalid_subject", f"Enter the website address. {exc}") from exc
        return url.normalized if url.path not in ("", "/") or url.query else url.host
    if category == "phone_number":
        phone = normalize_phone(text)
        if len(phone.lstrip("+")) < _MIN_PHONE_DIGITS:
            raise ApiError(
                422,
                "invalid_subject",
                "Enter the full phone number, with country code if you know it.",
            )
        return phone
    if category == "social_account":
        return re.sub(r"^https?://(www\.)?", "", text.lower()).rstrip("/")
    return text.lower()


def subject_key(category: str, normalized: str) -> str:
    return hashlib.sha256(f"{category}:{normalized}".encode()).hexdigest()


def similar_count(db: Session, key: str, excluding: uuid.UUID | None = None) -> int:
    query = (
        select(func.count()).select_from(CommunityReport).where(CommunityReport.subject_key == key)
    )
    if excluding:
        query = query.where(CommunityReport.id != excluding)
    return db.scalar(query) or 0


def _indicators_for(report: CommunityReport) -> list[FeedIndicator]:
    if report.category == "phone_number":
        return [FeedIndicator("phone", report.subject, "scam_phone_number")]
    if report.category == "website":
        if "://" in report.subject:
            url = parse_url(report.subject)
            return [
                FeedIndicator("url", url.normalized, "reported_scam"),
                FeedIndicator("host", url.host, "reported_scam"),
            ]
        return [FeedIndicator("host", report.subject, "reported_scam")]
    return []


def _sync_indicators(db: Session, report: CommunityReport) -> None:
    """Keep the community indicator set equal to what verified reports support."""
    source = get_or_create_source(db, COMMUNITY, COMMUNITY_SOURCE_NAME)
    now = utcnow()
    still_verified = db.scalar(
        select(func.count())
        .select_from(CommunityReport)
        .where(
            CommunityReport.subject_key == report.subject_key,
            CommunityReport.status == "verified",
            (CommunityReport.verification_expires_at.is_(None))
            | (CommunityReport.verification_expires_at > now),
        )
    )
    indicators = _indicators_for(report)
    if still_verified:
        store_indicators(db, source, indicators)
    else:
        digests = [indicator_digest(indicator.value) for indicator in indicators]
        if digests:
            db.execute(
                delete(ThreatIndicator).where(
                    ThreatIndicator.source_id == source.id,
                    ThreatIndicator.value_digest.in_(digests),
                )
            )
    source.indicator_count = (
        db.scalar(
            select(func.count())
            .select_from(ThreatIndicator)
            .where(ThreatIndicator.source_id == source.id)
        )
        or 0
    )
    source.last_success_at = utcnow()


def review(
    db: Session,
    report: CommunityReport,
    moderator: User,
    status: str,
    note: str | None,
    duplicate_of: uuid.UUID | None,
) -> CommunityReport:
    if status == "duplicate":
        original = db.get(CommunityReport, duplicate_of) if duplicate_of else None
        if original is None or original.id == report.id:
            raise ApiError(
                422, "invalid_duplicate", "Choose the original report this one duplicates."
            )
        report.duplicate_of_id = original.id
    else:
        report.duplicate_of_id = None
    report.status = status
    report.moderator_note = note
    report.reviewed_by_id = moderator.id
    report.reviewed_at = utcnow()
    report.verification_expires_at = (
        report.reviewed_at
        + VERIFICATION_LIFETIME.get(report.category, DEFAULT_VERIFICATION_LIFETIME)
        if status == "verified"
        else None
    )
    db.flush()
    _sync_indicators(db, report)
    db.commit()
    _tell_reporter(db, report)
    return report


def _tell_reporter(db: Session, report: CommunityReport) -> None:
    """Let a signed-in reporter know the outcome, if email is set up. Anonymous
    reporters check with their tracking link instead."""
    from app.notify.email import EmailUnavailableError, email_enabled, send_email

    reporter = db.get(User, report.reporter_id) if report.reporter_id else None
    if reporter is None or reporter.email_verified_at is None or not email_enabled():
        return
    outcome = {
        "verified": "A moderator confirmed it. SENTINEL now warns people who check it.",
        "rejected": "A moderator could not confirm it from the information provided.",
        "duplicate": "It had already been reported, so it was merged with the earlier report.",
    }[report.status]
    note = (
        f"\n\nMessage from the moderator:\n{report.moderator_note}" if report.moderator_note else ""
    )
    try:
        send_email(
            db,
            reporter.email,
            "Your SENTINEL report was reviewed",
            f"Thank you for your report about “{report.subject[:120]}”.\n\n{outcome}{note}\n",
        )
        db.commit()
    except EmailUnavailableError:
        logger.info("Reporter notification not sent: email unavailable")


def expire_verifications(db: Session) -> int:
    """Withdraw indicators whose verification lapsed recently (run hourly)."""
    now = utcnow()
    lapsed = db.scalars(
        select(CommunityReport).where(
            CommunityReport.status == "verified",
            CommunityReport.verification_expires_at < now,
            CommunityReport.verification_expires_at > now - timedelta(days=2),
        )
    ).all()
    for report in lapsed:
        _sync_indicators(db, report)
    db.commit()
    return len(lapsed)


def reporter_reputation(db: Session, reporter_id: uuid.UUID | None) -> dict[str, int | str]:
    """How often this person's earlier reports were confirmed. Helps moderators
    order the queue; it never decides a report on its own."""
    if reporter_id is None:
        return {"level": "anonymous", "verified": 0, "rejected": 0}
    counts = dict(
        db.execute(
            select(CommunityReport.status, func.count())
            .where(
                CommunityReport.reporter_id == reporter_id,
                CommunityReport.status.in_(("verified", "rejected")),
            )
            .group_by(CommunityReport.status)
        ).all()
    )
    verified, rejected = int(counts.get("verified", 0)), int(counts.get("rejected", 0))
    if verified >= 3 and verified >= 3 * rejected:
        level = "trusted"
    elif rejected >= 3 and rejected > verified:
        level = "unreliable"
    else:
        level = "new"
    return {"level": level, "verified": verified, "rejected": rejected}


def mask_phone(phone: str) -> str:
    """Public listings show only the start and end of a number: scammers often spoof
    numbers that belong to someone else."""
    if len(phone) <= 6:
        return phone
    return phone[:4] + "•" * (len(phone) - 6) + phone[-2:]
