from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery("sentinel", broker=settings.redis_url, include=["app.workers.tasks"])
celery_app.conf.update(
    task_ignore_result=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=180,
    task_soft_time_limit=150,
    broker_connection_retry_on_startup=True,
    timezone="UTC",
    # Scans run in the isolated scan worker; everything that needs full database
    # access (feeds, retention, notifications) runs in the task worker.
    task_default_queue="tasks",
    task_routes={"sentinel.run_scan": {"queue": "scans"}},
)

if settings.feed_sync_enabled:
    celery_app.conf.beat_schedule = {
        "sync-threat-feeds": {"task": "sentinel.sync_feeds", "schedule": crontab(minute=7)},
        "purge-expired-data": {"task": "sentinel.purge_expired", "schedule": crontab(minute=37)},
    }
