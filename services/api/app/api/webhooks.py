"""Webhooks: signed notifications when the user's scans finish."""

import uuid

from fastapi import APIRouter, Request
from sqlalchemy import func, select

from app.api.auth import record_event
from app.api.deps import Db, SessionUser
from app.core.crypto import encrypt
from app.core.errors import ApiError
from app.core.security import new_token
from app.models import Webhook
from app.schemas.sharing import WebhookCreate, WebhookCreated, WebhookOut

router = APIRouter(prefix="/user/webhooks", tags=["Webhooks"])
MAX_WEBHOOKS = 5


@router.get("", response_model=list[WebhookOut])
def list_webhooks(db: Db, user: SessionUser) -> list[Webhook]:
    return list(
        db.scalars(select(Webhook).where(Webhook.user_id == user.id).order_by(Webhook.created_at))
    )


@router.post("", response_model=WebhookCreated, status_code=201)
def create_webhook(
    body: WebhookCreate, request: Request, db: Db, user: SessionUser
) -> WebhookCreated:
    count = db.scalar(select(func.count()).select_from(Webhook).where(Webhook.user_id == user.id))
    if (count or 0) >= MAX_WEBHOOKS:
        raise ApiError(409, "too_many_webhooks", f"You can have up to {MAX_WEBHOOKS} webhooks.")
    secret = f"whsec_{new_token()}"
    hook = Webhook(
        user_id=user.id,
        url=body.url,
        secret_encrypted=encrypt(secret),
        events=sorted(set(body.events)),
    )
    db.add(hook)
    record_event(db, request, user, "webhook_created", body.url)
    db.commit()
    return WebhookCreated.model_validate(
        {**WebhookOut.model_validate(hook).model_dump(), "secret": secret}
    )


@router.patch("/{webhook_id}", response_model=WebhookOut)
def set_active(webhook_id: uuid.UUID, active: bool, db: Db, user: SessionUser) -> Webhook:
    hook = db.get(Webhook, webhook_id)
    if hook is None or hook.user_id != user.id:
        raise ApiError(404, "webhook_not_found", "That webhook does not exist.")
    hook.active = active
    if active:
        hook.consecutive_failures = 0
    db.commit()
    return hook


@router.delete("/{webhook_id}", status_code=204)
def delete_webhook(webhook_id: uuid.UUID, request: Request, db: Db, user: SessionUser) -> None:
    hook = db.get(Webhook, webhook_id)
    if hook is None or hook.user_id != user.id:
        raise ApiError(404, "webhook_not_found", "That webhook does not exist.")
    record_event(db, request, user, "webhook_deleted", hook.url)
    db.delete(hook)
    db.commit()
