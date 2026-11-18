"""Web Push notifications (VAPID), for browsers that subscribed in settings.

Payloads are short and contain no scanned content: a title, a sentence and a
link back to Qalaa. Subscriptions the push service reports as gone are deleted.
"""

import json
import logging
import uuid

from pywebpush import WebPushException, webpush  # type: ignore[import-untyped]
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import PushSubscription
from app.models.base import utcnow

logger = logging.getLogger(__name__)


def push_enabled() -> bool:
    settings = get_settings()
    return bool(settings.vapid_public_key and settings.vapid_private_key)


def send_push(
    db: Session, user_id: uuid.UUID, title: str, body: str, url: str = "/dashboard"
) -> int:
    """Returns how many browsers accepted the notification."""
    if not push_enabled():
        return 0
    settings = get_settings()
    payload = json.dumps({"title": title[:80], "body": body[:200], "url": url})
    delivered = 0
    for subscription in db.scalars(
        select(PushSubscription).where(PushSubscription.user_id == user_id)
    ):
        try:
            webpush(
                subscription_info={
                    "endpoint": subscription.endpoint,
                    "keys": {"p256dh": subscription.p256dh, "auth": subscription.auth},
                },
                data=payload,
                vapid_private_key=settings.vapid_private_key,
                vapid_claims={"sub": settings.vapid_subject},
                ttl=24 * 3600,
                timeout=10,
            )
            subscription.last_success_at = utcnow()
            delivered += 1
        except WebPushException as exc:
            status = getattr(exc.response, "status_code", None)
            if status in (404, 410):
                db.delete(subscription)  # the browser unsubscribed or the endpoint expired
            else:
                logger.info("Push not delivered (%s)", status)
    db.commit()
    return delivered
