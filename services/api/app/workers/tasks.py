import uuid

from app.core.db import get_session_factory
from app.intel.feeds import sync_all_feeds
from app.scans.runner import run_scan
from app.scans.service import purge_expired_data
from app.workers.celery_app import celery_app


@celery_app.task(name="sentinel.run_scan")  # type: ignore[untyped-decorator]
def run_scan_task(scan_id: str) -> None:
    with get_session_factory()() as db:
        run_scan(db, uuid.UUID(scan_id))


@celery_app.task(name="sentinel.sync_feeds")  # type: ignore[untyped-decorator]
def sync_feeds_task() -> None:
    with get_session_factory()() as db:
        sync_all_feeds(db)


@celery_app.task(name="sentinel.purge_expired")  # type: ignore[untyped-decorator]
def purge_expired_task() -> None:
    with get_session_factory()() as db:
        purge_expired_data(db)
