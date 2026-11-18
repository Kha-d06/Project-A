"""Web Push subscriptions and the weekly summary preview."""

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select

from app.api.deps import Db, RequiredUser, SessionUser
from app.core.config import get_settings
from app.core.errors import ApiError
from app.models import PushSubscription
from app.notify.push import push_enabled, send_push
from app.notify.summary import build_summary

router = APIRouter(tags=["Notifications"])
MAX_SUBSCRIPTIONS = 10


class PushKeys(BaseModel):
    p256dh: str = Field(min_length=20, max_length=200)
    auth: str = Field(min_length=10, max_length=100)


class PushSubscribe(BaseModel):
    endpoint: str = Field(min_length=20, max_length=1000, pattern=r"^https://")
    keys: PushKeys


class PushUnsubscribe(BaseModel):
    endpoint: str = Field(max_length=1000)


@router.get("/push/key")
def push_key() -> dict[str, str | None]:
    """The VAPID public key browsers need to subscribe. Null when push is off."""
    return {"public_key": get_settings().vapid_public_key if push_enabled() else None}


@router.post("/push/subscriptions", status_code=201)
def subscribe(body: PushSubscribe, request: Request, db: Db, user: SessionUser) -> dict[str, bool]:
    if not push_enabled():
        raise ApiError(503, "push_unavailable", "Notifications are not set up on this server.")
    existing = db.scalar(select(PushSubscription).where(PushSubscription.endpoint == body.endpoint))
    if existing:
        existing.user_id = user.id
        existing.p256dh = body.keys.p256dh
        existing.auth = body.keys.auth
    else:
        count = db.scalar(
            select(func.count())
            .select_from(PushSubscription)
            .where(PushSubscription.user_id == user.id)
        )
        if (count or 0) >= MAX_SUBSCRIPTIONS:
            raise ApiError(
                409,
                "too_many_devices",
                "Notifications are on for too many browsers; turn one off first.",
            )
        db.add(
            PushSubscription(
                user_id=user.id,
                endpoint=body.endpoint,
                p256dh=body.keys.p256dh,
                auth=body.keys.auth,
                user_agent=(request.headers.get("user-agent") or "")[:200] or None,
            )
        )
    db.commit()
    return {"subscribed": True}


@router.delete("/push/subscriptions", status_code=204)
def unsubscribe(body: PushUnsubscribe, db: Db, user: SessionUser) -> None:
    db.execute(
        delete(PushSubscription).where(
            PushSubscription.user_id == user.id, PushSubscription.endpoint == body.endpoint
        )
    )
    db.commit()


@router.post("/push/test")
def test_push(db: Db, user: SessionUser) -> dict[str, int]:
    return {
        "delivered": send_push(
            db,
            user.id,
            "Qalaa notifications work",
            "You will be told here when something needs your attention.",
        )
    }


@router.get("/user/summary")
def my_summary(db: Db, user: RequiredUser) -> dict[str, Any]:
    return build_summary(db, user.id)
