"""Community reports: submission, duplicate detection and moderation.

Reports are unverified claims. Nothing a reporter writes is shown publicly; only
a moderator-verified report becomes visible, and then only its category and
subject. Verified websites and phone numbers are added to the indicator store so
scans can warn about them.
"""

import hashlib
import re
import uuid

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.analyzers.message_scan import normalize_phone
from app.analyzers.urls import InvalidUrlError, indicator_digest, parse_url
from app.core.errors import ApiError
from app.intel.feeds import COMMUNITY, FeedIndicator, get_or_create_source, store_indicators
from app.models import CommunityReport, ThreatIndicator, User
from app.models.base import utcnow

COMMUNITY_SOURCE_NAME = "SENTINEL community reports (moderator-verified)"
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
    still_verified = db.scalar(
        select(func.count())
        .select_from(CommunityReport)
        .where(
            CommunityReport.subject_key == report.subject_key, CommunityReport.status == "verified"
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
    db.flush()
    _sync_indicators(db, report)
    db.commit()
    return report


def mask_phone(phone: str) -> str:
    """Public listings show only the start and end of a number: scammers often spoof
    numbers that belong to someone else."""
    if len(phone) <= 6:
        return phone
    return phone[:4] + "•" * (len(phone) - 6) + phone[-2:]
