"""Prometheus metrics, computed from the database at scrape time.

Read from the database rather than counted in memory, so the API and the scan
workers (separate processes) report one consistent picture. Disabled unless
SENTINEL_METRICS_TOKEN is set; Prometheus must send it as a bearer token.
"""

import contextlib
import hmac
from datetime import timedelta

import redis
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.deps import Db
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.models import CommunityReport, ExtensionInstallation, ScanJob, ThreatSource, User, Webhook
from app.models.base import utcnow
from app.notify.email import EmailUnavailableError, email_enabled, send_email

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
    failing = db.scalar(
        select(func.count()).select_from(Webhook).where(Webhook.consecutive_failures >= 3)
    )
    lines += [
        "# HELP sentinel_webhooks_failing Webhooks with three or more failed deliveries in a row.",
        "# TYPE sentinel_webhooks_failing gauge",
        _line("sentinel_webhooks_failing", failing or 0),
        "# HELP sentinel_queue_length Tasks waiting in each Celery queue (-1 when Redis is unreachable).",
        "# TYPE sentinel_queue_length gauge",
    ]
    for queue in ("scans", "tasks"):
        try:
            length = redis.Redis.from_url(get_settings().redis_url, socket_timeout=2).llen(queue)
        except redis.RedisError:
            length = -1
        lines.append(_line("sentinel_queue_length", float(length), {"queue": queue}))
    return "\n".join(lines) + "\n"


class _Alert(BaseModel):
    status: str = Field(max_length=20)
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str | None = Field(default=None, max_length=40)  # noqa: N815 - Alertmanager's name


class _AlertBatch(BaseModel):
    status: str = Field(max_length=20)
    alerts: list[_Alert] = Field(default_factory=list, max_length=200)


ALERT_LIMIT = RateLimit("monitoring-alerts", max_requests=120, window_seconds=3600)


@router.post("/system/alerts", status_code=204, include_in_schema=False)
def receive_alerts(body: _AlertBatch, request: Request, db: Db) -> None:
    """Alertmanager webhook: emails the administrators about firing or resolved
    alerts, through SENTINEL's own mail settings. Authenticated with the same
    bearer token as /system/metrics."""
    token = get_settings().metrics_token
    supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not token or not hmac.compare_digest(supplied, token):
        raise ApiError(404, "not_found", "Not Found")
    rate_limit.enforce(ALERT_LIMIT, "alertmanager")
    if not body.alerts or not email_enabled():
        return
    firing = [a for a in body.alerts if a.status == "firing"]
    resolved = [a for a in body.alerts if a.status != "firing"]
    lines: list[str] = []
    for title, group in (("Firing", firing), ("Resolved", resolved)):
        if not group:
            continue
        lines.append(f"{title}:")
        for alert in group:
            name = alert.labels.get("alertname", "alert")[:80]
            severity = alert.labels.get("severity", "")[:20]
            summary = (
                alert.annotations.get("summary") or alert.annotations.get("description") or ""
            )[:300]
            lines.append(f"  - {name}{f' ({severity})' if severity else ''}: {summary}")
        lines.append("")
    lines.append("What to do for each alert: docs/operations.md, section 'Monitoring and alerts'.")
    subject = (
        f"[SENTINEL] {len(firing)} alert(s) firing"
        if firing
        else f"[SENTINEL] {len(resolved)} alert(s) resolved"
    )
    admins = db.scalars(
        select(User.email).where(User.role == "admin", User.disabled_at.is_(None))
    ).all()
    for address in admins:
        # One unreachable mailbox must not stop the others.
        with contextlib.suppress(EmailUnavailableError):
            send_email(db, address, subject, "\n".join(lines))
