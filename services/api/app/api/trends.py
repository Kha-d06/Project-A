"""Public scam trends: what kinds of scams Qalaa has been seeing recently.

Only aggregate counts are published: categories of warning signs found in
scans, verified community reports by type and country, and verdict totals.
Nothing that was scanned or reported is shown, and any count below a small
threshold is hidden so that no individual case can be singled out.
"""

from collections import Counter
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Query, Request
from sqlalchemy import func, select

from app.analyzers.phones import phone_info
from app.api.deps import Db
from app.core import rate_limit
from app.core.rate_limit import RateLimit, client_address
from app.models import CommunityReport, Finding, ScanJob
from app.models.base import utcnow

router = APIRouter(prefix="/trends", tags=["Trends"])
TRENDS_LIMIT = RateLimit("trends", max_requests=120, window_seconds=3600)
MIN_COUNT = 3

COUNTRY_TLDS = {
    "ae": "United Arab Emirates", "sa": "Saudi Arabia", "qa": "Qatar", "kw": "Kuwait",
    "bh": "Bahrain", "om": "Oman", "eg": "Egypt", "jo": "Jordan", "uk": "United Kingdom",
}  # fmt: skip
# Categories of findings that describe a scam technique, in the order shown.
SCAM_CATEGORIES = (
    "credential_request", "account_threat", "delivery_scam", "fine_scam", "government_impersonation",
    "prize_scam", "job_scam", "investment_scam", "payment_pressure", "pilgrimage_scam", "utility_scam",
    "personal_data_request", "brand_impersonation", "typosquatting", "homograph", "visual_impersonation",
    "macros", "disguised_file", "known_signature", "threat_intelligence", "community_report",
    "personal_number_sender",
)  # fmt: skip


def _hide_small(counts: Counter[str]) -> dict[str, int]:
    return {key: value for key, value in counts.most_common() if value >= MIN_COUNT}


def _report_country(category: str, subject: str) -> str:
    if category == "phone_number":
        return phone_info(subject).country or "Unknown"
    if category == "website":
        host = subject.split("://")[-1].split("/")[0]
        return COUNTRY_TLDS.get(host.rsplit(".", 1)[-1], "International")
    return "Unspecified"


@router.get("")
def trends(request: Request, db: Db, days: int = Query(30, ge=7, le=90)) -> dict[str, Any]:
    rate_limit.enforce(TRENDS_LIMIT, client_address(request))
    since = utcnow() - timedelta(days=days)
    techniques = Counter(
        dict(
            db.execute(
                select(Finding.category, func.count(func.distinct(Finding.scan_id)))
                .join(ScanJob, ScanJob.id == Finding.scan_id)
                .where(
                    ScanJob.created_at >= since,
                    Finding.category.in_(SCAM_CATEGORIES),
                    Finding.severity.in_(("critical", "high", "medium")),
                )
                .group_by(Finding.category)
            ).all()
        )
    )
    verdicts: Counter[str] = Counter()
    for risk, count in db.execute(
        select(ScanJob.risk, func.count())
        .where(ScanJob.created_at >= since, ScanJob.risk.is_not(None))
        .group_by(ScanJob.risk)
    ):
        if risk:
            verdicts[risk] = count
    reports = db.execute(
        select(CommunityReport.category, CommunityReport.subject).where(
            CommunityReport.status == "verified", CommunityReport.reviewed_at >= since
        )
    ).all()
    by_category = Counter(category for category, _ in reports)
    by_country = Counter(_report_country(category, subject) for category, subject in reports)
    return {
        "days": days,
        "generated_at": utcnow(),
        "techniques": _hide_small(techniques),
        "verdicts": _hide_small(verdicts),
        "verified_reports_by_category": _hide_small(by_category),
        "verified_reports_by_country": _hide_small(by_country),
        "minimum_count": MIN_COUNT,
    }
