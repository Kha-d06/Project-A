"""Administration. Every route requires the admin role, checked on the server."""

import uuid
from datetime import timedelta
from typing import Annotated

import redis
from fastapi import APIRouter, Query, Request
from sqlalchemy import delete, func, or_, select

from app.api.auth import LOGIN_ACCOUNT_LIMIT, LOGIN_IP_LIMIT, REGISTER_LIMIT, record_event
from app.api.deps import AdminUser, Db
from app.api.extension import CHECK_LIMIT, ENROLL_LIMIT, LINK_ATTEMPT_LIMIT
from app.api.intelligence import LOOKUP_LIMIT
from app.api.reports import REPORT_LIMIT
from app.api.scans import EXPLANATION_LIMIT, FILE_SCAN_LIMIT, SCAN_LIMIT, WEBSITE_SCAN_LIMIT
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import rejection_counts
from app.intel.feeds import FEEDS
from app.models import AuditEvent, CommunityReport, ScanJob, ThreatSource, User, UserSession
from app.models.base import utcnow
from app.schemas.admin import (
    AdminOverview,
    AdminScan,
    AdminUserPage,
    AuditEntry,
    AuditPage,
    FeedHealth,
    UserUpdate,
    WorkerHealth,
)
from app.schemas.admin import AdminUser as AdminUserOut

router = APIRouter(prefix="/admin", tags=["Administration"])

MONITORED_LIMITS = [
    limit.name
    for limit in (
        SCAN_LIMIT, FILE_SCAN_LIMIT, WEBSITE_SCAN_LIMIT, EXPLANATION_LIMIT, LOGIN_IP_LIMIT,
        LOGIN_ACCOUNT_LIMIT, REGISTER_LIMIT, ENROLL_LIMIT, LINK_ATTEMPT_LIMIT, CHECK_LIMIT,
        REPORT_LIMIT, LOOKUP_LIMIT,
    )
]  # fmt: skip
_WORKER_PING_SECONDS = 1.5
_STUCK_AFTER = timedelta(minutes=15)


def worker_health() -> WorkerHealth:
    settings = get_settings()
    if settings.run_scans_inline:
        return WorkerHealth(
            reachable=True, workers=[], queued_tasks=0, detail="Scans run inline (test mode)."
        )
    try:
        queued = int(redis.Redis.from_url(settings.redis_url, socket_timeout=2).llen("celery"))
    except redis.RedisError:
        return WorkerHealth(
            reachable=False, workers=[], queued_tasks=None, detail="Redis is not reachable."
        )
    from app.workers.celery_app import celery_app  # imported late: needs a broker connection

    replies = celery_app.control.inspect(timeout=_WORKER_PING_SECONDS).ping() or {}
    workers = sorted(replies)
    detail = (
        f"{len(workers)} worker(s) answered."
        if workers
        else "No worker answered. Scans will stay queued."
    )
    return WorkerHealth(
        reachable=bool(workers), workers=workers, queued_tasks=queued, detail=detail
    )


def _feed_health(db: Db) -> list[FeedHealth]:
    cutoff = utcnow() - timedelta(hours=get_settings().feed_stale_after_hours)
    sources = {source.key: source for source in db.scalars(select(ThreatSource))}
    health = []
    for feed in FEEDS:
        source = sources.get(feed.key)
        health.append(
            FeedHealth(
                name=feed.name,
                indicators=source.indicator_count if source else 0,
                last_success_at=source.last_success_at if source else None,
                last_attempt_at=source.last_attempt_at if source else None,
                last_error=source.last_error if source else None,
                fresh=bool(source and source.last_success_at and source.last_success_at >= cutoff),
            )
        )
    return health


@router.get("/overview", response_model=AdminOverview)
def overview(db: Db, admin: AdminUser) -> AdminOverview:
    now = utcnow()
    day_ago = now - timedelta(hours=24)
    by_status = dict(
        db.execute(
            select(ScanJob.status, func.count())
            .where(ScanJob.created_at >= day_ago)
            .group_by(ScanJob.status)
        ).all()
    )
    return AdminOverview(
        users_total=db.scalar(select(func.count()).select_from(User)) or 0,
        users_new_7d=db.scalar(
            select(func.count()).select_from(User).where(User.created_at >= now - timedelta(days=7))
        )
        or 0,
        scans_24h=by_status,
        failed_24h=by_status.get("failed", 0),
        stuck=db.scalar(
            select(func.count())
            .select_from(ScanJob)
            .where(
                ScanJob.status.in_(("queued", "processing")),
                ScanJob.created_at < now - _STUCK_AFTER,
            )
        )
        or 0,
        reports_pending=db.scalar(
            select(func.count())
            .select_from(CommunityReport)
            .where(CommunityReport.status == "pending")
        )
        or 0,
        workers=worker_health(),
        feeds=_feed_health(db),
        rate_limit_rejections_24h=rejection_counts(MONITORED_LIMITS),
    )


@router.get("/users", response_model=AdminUserPage)
def list_users(
    db: Db,
    admin: AdminUser,
    query: Annotated[str | None, Query(max_length=100)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
) -> AdminUserPage:
    page_size = 25
    conditions = []
    if query:
        pattern = f"%{query.lower()}%"
        conditions.append(or_(User.email.ilike(pattern), User.display_name.ilike(pattern)))
    scans = select(func.count()).where(ScanJob.user_id == User.id).correlate(User).scalar_subquery()
    rows = db.execute(
        select(User, scans)
        .where(*conditions)
        .order_by(User.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return AdminUserPage(
        items=[
            AdminUserOut(
                id=user.id,
                email=user.email,
                display_name=user.display_name,
                role=user.role,
                created_at=user.created_at,
                disabled=user.disabled_at is not None,
                scans=count,
            )
            for user, count in rows
        ],
        total=db.scalar(select(func.count()).select_from(User).where(*conditions)) or 0,
    )


@router.patch("/users/{user_id}", response_model=AdminUserOut)
def update_user(
    user_id: uuid.UUID, body: UserUpdate, request: Request, db: Db, admin: AdminUser
) -> AdminUserOut:
    user = db.get(User, user_id)
    if user is None:
        raise ApiError(404, "user_not_found", "This account does not exist.")
    if user.id == admin.id and (body.role not in (None, "admin") or body.disabled):
        raise ApiError(
            409, "cannot_change_self", "You cannot remove your own administrator access."
        )
    if body.role is not None and body.role != user.role:
        record_event(
            db, request, admin, "admin_role_changed", f"{user.email}: {user.role} → {body.role}"
        )
        user.role = body.role
    if body.disabled is not None and body.disabled != (user.disabled_at is not None):
        user.disabled_at = utcnow() if body.disabled else None
        if body.disabled:
            db.execute(delete(UserSession).where(UserSession.user_id == user.id))
        record_event(
            db,
            request,
            admin,
            "admin_account_disabled" if body.disabled else "admin_account_enabled",
            user.email,
        )
    db.commit()
    count = (
        db.scalar(select(func.count()).select_from(ScanJob).where(ScanJob.user_id == user.id)) or 0
    )
    return AdminUserOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        created_at=user.created_at,
        disabled=user.disabled_at is not None,
        scans=count,
    )


@router.get("/scans", response_model=list[AdminScan])
def recent_scans(
    db: Db,
    admin: AdminUser,
    status: Annotated[
        str | None, Query(pattern="^(queued|processing|completed|failed|inconclusive)$")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[AdminScan]:
    query = select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)
    if status:
        query = query.where(ScanJob.status == status)
    return [
        AdminScan(
            id=job.id,
            scan_type=job.scan_type,
            status=job.status,
            error=job.error,
            created_at=job.created_at,
            completed_at=job.completed_at,
            duration_seconds=(job.completed_at - job.started_at).total_seconds()
            if job.completed_at and job.started_at
            else None,
        )
        for job in db.scalars(query)
    ]


@router.get("/audit", response_model=AuditPage)
def audit_log(db: Db, admin: AdminUser, page: Annotated[int, Query(ge=1)] = 1) -> AuditPage:
    page_size = 50
    rows = db.execute(
        select(AuditEvent, User.email)
        .outerjoin(User, AuditEvent.user_id == User.id)
        .order_by(AuditEvent.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return AuditPage(
        items=[
            AuditEntry(
                action=event.action,
                detail=event.detail,
                user_email=email,
                ip_address=event.ip_address,
                created_at=event.created_at,
            )
            for event, email in rows
        ],
        total=db.scalar(select(func.count()).select_from(AuditEvent)) or 0,
        page=page,
    )


@router.post("/feeds/sync", status_code=202)
def sync_feeds(request: Request, db: Db, admin: AdminUser) -> dict[str, str]:
    record_event(db, request, admin, "admin_feed_sync")
    db.commit()
    if get_settings().run_scans_inline:
        from app.intel.feeds import sync_all_feeds

        sync_all_feeds(db)
        return {"status": "completed"}
    from app.workers.tasks import sync_feeds_task

    sync_feeds_task.delay()
    return {"status": "queued"}
