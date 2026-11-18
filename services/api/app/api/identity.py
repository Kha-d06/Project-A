"""Identity monitoring: watch more of your email addresses for data breaches.

Each address must be confirmed with a six-digit code sent to it before it is
monitored, so nobody can watch an address they do not control. Confirmed
addresses are checked against Have I Been Pwned when added and then weekly,
together with the account's own address; new breaches are emailed to the
account and to the affected address.
"""

import contextlib
import secrets
import uuid
from datetime import timedelta
from typing import Any

from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.auth import record_event
from app.api.breach import hibp_breaches
from app.api.deps import Db, SessionUser
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.core.security import token_digest
from app.models import MonitoredIdentity
from app.models.base import utcnow
from app.notify.email import EmailUnavailableError, email_enabled, send_email

router = APIRouter(prefix="/identity", tags=["Identity monitoring"])

MAX_IDENTITIES = 5
CODE_LIFETIME = timedelta(minutes=30)
MAX_CODE_ATTEMPTS = 5
ADD_LIMIT = RateLimit("identity-add", max_requests=10, window_seconds=3600)
VERIFY_LIMIT = RateLimit("identity-verify", max_requests=20, window_seconds=3600)


class IdentityIn(BaseModel):
    email: str = Field(max_length=320)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class IdentityBreach(BaseModel):
    name: str
    title: str
    breach_date: str | None = None
    data_classes: list[str] = []


class IdentityOut(BaseModel):
    id: uuid.UUID
    email: str
    verified: bool
    created_at: Any
    last_checked_at: Any
    breaches: list[IdentityBreach]


class IdentityStatus(BaseModel):
    available: bool
    email_available: bool
    max_identities: int
    identities: list[IdentityOut]


def _out(item: MonitoredIdentity) -> IdentityOut:
    return IdentityOut(
        id=item.id,
        email=item.value,
        verified=item.verified_at is not None,
        created_at=item.created_at,
        last_checked_at=item.last_checked_at,
        breaches=[IdentityBreach(**b) for b in item.known_breaches or [] if isinstance(b, dict)],
    )


def _owned(db: Db, identity_id: uuid.UUID, user_id: uuid.UUID) -> MonitoredIdentity:
    item = db.get(MonitoredIdentity, identity_id)
    if item is None or item.user_id != user_id:
        raise ApiError(404, "identity_not_found", "That address is not on your list.")
    return item


def _send_code(db: Db, item: MonitoredIdentity) -> None:
    code = f"{secrets.randbelow(1_000_000):06d}"
    item.code_digest = token_digest(code)
    item.code_expires_at = utcnow() + CODE_LIFETIME
    item.code_attempts = 0
    db.commit()
    send_email(
        db,
        item.value,
        "Qalaa: confirm this address for breach monitoring",
        f"Someone asked Qalaa to watch {item.value} for data breaches.\n\n"
        f"If that was you, enter this code on the Breach check page: {code}\n"
        "It expires in 30 minutes.\n\n"
        "If it was not you, ignore this email: the address will not be monitored.\n",
    )


def breach_summary(breaches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": str(b.get("Name")),
            "title": str(b.get("Title") or b.get("Name")),
            "breach_date": b.get("BreachDate"),
            "data_classes": [str(c) for c in (b.get("DataClasses") or [])][:12],
        }
        for b in breaches
    ]


@router.get("", response_model=IdentityStatus)
def status(db: Db, user: SessionUser) -> IdentityStatus:
    items = db.scalars(
        select(MonitoredIdentity)
        .where(MonitoredIdentity.user_id == user.id)
        .order_by(MonitoredIdentity.created_at)
    ).all()
    return IdentityStatus(
        available=bool(get_settings().hibp_api_key),
        email_available=email_enabled(),
        max_identities=MAX_IDENTITIES,
        identities=[_out(item) for item in items],
    )


@router.post("", response_model=IdentityOut, status_code=201)
def add(body: IdentityIn, request: Request, db: Db, user: SessionUser) -> IdentityOut:
    rate_limit.enforce(ADD_LIMIT, f"user:{user.id}")
    if not email_enabled():
        raise ApiError(
            503,
            "email_unavailable",
            "This server cannot send email, so it cannot confirm addresses.",
        )
    try:
        email = validate_email(body.email, check_deliverability=False).normalized.lower()
    except EmailNotValidError as exc:
        raise ApiError(422, "invalid_email", "That is not a valid email address.") from exc
    if email == user.email.lower():
        raise ApiError(
            409, "already_monitored", "Your account's own address is covered by breach monitoring."
        )
    existing = db.scalar(
        select(MonitoredIdentity).where(
            MonitoredIdentity.user_id == user.id, MonitoredIdentity.value == email
        )
    )
    if existing is not None:
        raise ApiError(409, "already_added", "That address is already on your list.")
    count = (
        db.scalar(
            select(func.count())
            .select_from(MonitoredIdentity)
            .where(MonitoredIdentity.user_id == user.id)
        )
        or 0
    )
    if count >= MAX_IDENTITIES:
        raise ApiError(
            409, "identity_limit", f"You can monitor up to {MAX_IDENTITIES} extra addresses."
        )
    item = MonitoredIdentity(user_id=user.id, kind="email", value=email)
    db.add(item)
    record_event(db, request, user, "identity_added", email)
    db.commit()
    try:
        _send_code(db, item)
    except EmailUnavailableError as exc:
        raise ApiError(
            503, "email_unavailable", "The confirmation email could not be sent."
        ) from exc
    return _out(item)


@router.post("/{identity_id}/resend", status_code=204)
def resend(identity_id: uuid.UUID, db: Db, user: SessionUser) -> None:
    rate_limit.enforce(ADD_LIMIT, f"user:{user.id}")
    item = _owned(db, identity_id, user.id)
    if item.verified_at is not None:
        return
    try:
        _send_code(db, item)
    except EmailUnavailableError as exc:
        raise ApiError(
            503, "email_unavailable", "The confirmation email could not be sent."
        ) from exc


@router.post("/{identity_id}/verify", response_model=IdentityOut)
def verify(
    identity_id: uuid.UUID, body: CodeIn, request: Request, db: Db, user: SessionUser
) -> IdentityOut:
    rate_limit.enforce(VERIFY_LIMIT, f"user:{user.id}")
    item = _owned(db, identity_id, user.id)
    if item.verified_at is not None:
        return _out(item)
    expires = item.code_expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=utcnow().tzinfo)
    if not item.code_digest or expires is None or expires < utcnow():
        raise ApiError(410, "code_expired", "That code has expired. Send a new one.")
    if item.code_attempts >= MAX_CODE_ATTEMPTS:
        raise ApiError(429, "too_many_attempts", "Too many wrong codes. Send a new one.")
    code = body.code.strip().replace(" ", "")
    if not secrets.compare_digest(token_digest(code), item.code_digest):
        item.code_attempts += 1
        db.commit()
        raise ApiError(422, "wrong_code", "That code is not right.")
    item.verified_at = utcnow()
    item.code_digest = None
    item.code_expires_at = None
    record_event(db, request, user, "identity_verified", item.value)
    db.commit()
    # First check straight away, so the person sees results now, not next week.
    if get_settings().hibp_api_key:
        with contextlib.suppress(ApiError):
            item.known_breaches = breach_summary(hibp_breaches(item.value))
            item.last_checked_at = utcnow()
            db.commit()
    return _out(item)


@router.delete("/{identity_id}", status_code=204)
def remove(identity_id: uuid.UUID, request: Request, db: Db, user: SessionUser) -> None:
    item = _owned(db, identity_id, user.id)
    record_event(db, request, user, "identity_removed", item.value)
    db.delete(item)
    db.commit()
