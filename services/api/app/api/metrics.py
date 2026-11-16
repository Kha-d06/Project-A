"""Prometheus metrics, computed from the database at scrape time.

Read from the database rather than counted in memory, so the API and the scan
workers (separate processes) report one consistent picture. Disabled unless
SENTINEL_METRICS_TOKEN is set; Prometheus must send it as a bearer token.
"""

import hmac
from datetime import timedelta

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select

from app.api.deps import Db
from app.core.config import get_settings
from app.core.errors import ApiError
from app.models import CommunityReport, ExtensionInstallation, ScanJob, ThreatSource, User
from app.models.base import utcnow

router = APIRouter(tags=["System"])


def _line(name: str, value: float, labels: dict[str, str] | None = None) -> str:
    label_text = ",".join(f'{key}="{val}"' for key, val in (labels or {}).items())
    return f"{name}{{{label_text}}} {value}" if label_text else f"{name} {value}"


@router.get("/system/metrics", response_class=PlainTextResponse, include_in_schema=False)
def metrics(request: Request, db: Db) -> str:
    token = get_settings().metrics_token
    supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not token or not hmac.compare_digest(supplied, token):
        # Indistinguishable from a missing route, so the endpoint is not advertised.
        raise ApiError(404, "not_found", "Not Found")

    now = utcnow()
    lines = [
        "# HELP sentinel_scans_24h Scans created in the last 24 hours.",
        "# TYPE sentinel_scans_24h gauge",
    ]
    scans = db.execute(
        select(ScanJob.scan_type, ScanJob.status, func.count())
        .where(ScanJob.created_at >= now - timedelta(hours=24))
        .group_by(ScanJob.scan_type, ScanJob.status)
    ).all()
    lines += [_line("sentinel_scans_24h", count, {"type": t, "status": s}) for t, s, count in scans]

    stuck = db.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(
            ScanJob.status.in_(("queued", "processing")),
            ScanJob.created_at < now - timedelta(minutes=15),
        )
    )
    lines += [
        "# HELP sentinel_scans_stuck Scans queued or processing for over 15 minutes.",
        "# TYPE sentinel_scans_stuck gauge",
        _line("sentinel_scans_stuck", stuck or 0),
        "# HELP sentinel_feed_age_seconds Seconds since each threat feed last synchronised.",
        "# TYPE sentinel_feed_age_seconds gauge",
    ]
    sources = list(db.scalars(select(ThreatSource)))
    for source in sources:
        if source.last_success_at:
            age = (now - source.last_success_at).total_seconds()
            lines.append(_line("sentinel_feed_age_seconds", round(age), {"feed": source.key}))
    lines += [
        "# HELP sentinel_feed_indicators Indicators stored per feed.",
        "# TYPE sentinel_feed_indicators gauge",
    ]
    lines += [
        _line("sentinel_feed_indicators", s.indicator_count, {"feed": s.key}) for s in sources
    ]

    pending = db.scalar(
        select(func.count()).select_from(CommunityReport).where(CommunityReport.status == "pending")
    )
    lines += [
        "# HELP sentinel_reports_pending Community reports awaiting moderation.",
        "# TYPE sentinel_reports_pending gauge",
        _line("sentinel_reports_pending", pending or 0),
        "# HELP sentinel_users Registered accounts.",
        "# TYPE sentinel_users gauge",
        _line("sentinel_users", db.scalar(select(func.count()).select_from(User)) or 0),
        "# HELP sentinel_extension_installations Active extension installations.",
        "# TYPE sentinel_extension_installations gauge",
        _line(
            "sentinel_extension_installations",
            db.scalar(
                select(func.count())
                .select_from(ExtensionInstallation)
                .where(ExtensionInstallation.revoked_at.is_(None))
            )
            or 0,
        ),
    ]
    return "\n".join(lines) + "\n"
