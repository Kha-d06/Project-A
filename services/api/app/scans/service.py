import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import ScanJob, User, UserSession
from app.models.base import utcnow
from app.scans.runner import run_scan
from app.scans.storage import delete_sample

# Scans submitted without an account are reachable only by their unguessable ID
# and are removed after this period.
ANONYMOUS_SCAN_RETENTION = timedelta(days=30)
_STUCK_SCAN_AGE = timedelta(minutes=15)
_TARGET_MAX_LENGTH = 300


def owner_for_new_scan(user: User | None) -> uuid.UUID | None:
    if user is None or not user.settings.save_scan_history:
        return None
    return user.id


def create_scan(
    db: Session,
    *,
    scan_type: str,
    target: str,
    payload: dict[str, Any],
    user: User | None,
    locale: str = "en",
) -> ScanJob:
    job = ScanJob(
        scan_type=scan_type,
        target=target[:_TARGET_MAX_LENGTH],
        # The language of the page that submitted the scan; summaries follow it.
        payload={**payload, "locale": locale},
        user_id=owner_for_new_scan(user),
    )
    db.add(job)
    db.commit()

    if get_settings().run_scans_inline:
        run_scan(db, job.id)
    else:
        from app.workers.tasks import run_scan_task  # imported late: needs a broker connection

        run_scan_task.delay(str(job.id))
    return job


def delete_scan(db: Session, job: ScanJob) -> None:
    storage_name = job.payload.get("storage_name")
    if storage_name:
        delete_sample(storage_name)
    db.delete(job)
    db.commit()


def history_query(
    user_id: uuid.UUID,
    *,
    scan_type: str | None = None,
    risk: str | None = None,
    status: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Any:
    query = select(ScanJob).where(ScanJob.user_id == user_id)
    if scan_type:
        query = query.where(ScanJob.scan_type == scan_type)
    if risk:
        query = query.where(ScanJob.risk == risk)
    if status:
        query = query.where(ScanJob.status == status)
    if since:
        query = query.where(ScanJob.created_at >= since)
    if until:
        query = query.where(ScanJob.created_at <= until)
    return query


def count(db: Session, query: Any) -> int:
    return db.scalar(select(func.count()).select_from(query.subquery())) or 0


def purge_expired_data(db: Session) -> None:
    """Retention sweep: old anonymous scans, expired sessions, scans a dead worker left behind."""
    now = utcnow()
    expired = db.scalars(
        select(ScanJob).where(
            ScanJob.user_id.is_(None), ScanJob.created_at < now - ANONYMOUS_SCAN_RETENTION
        )
    ).all()
    for job in expired:
        delete_scan(db, job)

    stuck = db.scalars(
        select(ScanJob).where(
            ScanJob.status.in_(("queued", "processing")),
            ScanJob.created_at < now - _STUCK_SCAN_AGE,
        )
    ).all()
    for job in stuck:
        storage_name = job.payload.get("storage_name")
        if storage_name:
            delete_sample(storage_name)
        job.payload = {k: v for k, v in job.payload.items() if k not in ("content", "storage_name")}
        job.status = "failed"
        job.error = "The scan did not finish. Please submit it again."
        job.completed_at = now

    db.execute(delete(UserSession).where(UserSession.expires_at < now))
    db.commit()
