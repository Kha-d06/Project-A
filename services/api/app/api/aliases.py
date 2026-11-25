"""Disposable email aliases (no paid relay).

A random or chosen address on the operator's relay domain (or the person's own
DNS-verified domain) forwards to the account's verified email. Aliases can be
paused (mail is refused) or deleted (refused for good; the address is never
issued again). The operator's mail server asks /relay/aliases/resolve where
each recipient goes and does the forwarding itself: Qalaa sees addresses and
counts, never messages.

Reachable from the website (session), the browser extension (a linked
installation) and the desktop app (a linked device).
"""

import hmac
import re
import secrets
import uuid
from datetime import datetime

from fastapi import APIRouter, Header
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.api.deps import Db, SessionUser
from app.api.devices import CurrentDevice
from app.api.extension_auth import CurrentInstallation
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.models import EmailAlias, User, VerifiedDomain
from app.models.base import utcnow

router = APIRouter(tags=["aliases"])

CREATE_LIMIT = RateLimit("alias-create", max_requests=30, window_seconds=3600)
LOCAL_PART = re.compile(r"^[a-z0-9][a-z0-9._-]{0,30}[a-z0-9]$")
RESERVED = frozenset(
    {"postmaster", "abuse", "admin", "administrator", "root", "hostmaster", "webmaster",
     "noreply", "no-reply", "security", "support", "info", "mailer-daemon", "help"}
)  # fmt: skip
_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"  # no look-alikes (l/1, o/0)


class AliasIn(BaseModel):
    domain: str | None = Field(default=None, max_length=253)
    local_part: str | None = Field(default=None, max_length=32)
    label: str | None = Field(default=None, max_length=120)


class AliasPatch(BaseModel):
    paused: bool | None = None
    label: str | None = Field(default=None, max_length=120)


class AliasOut(BaseModel):
    id: uuid.UUID
    address: str
    label: str | None
    paused: bool
    created_at: datetime
    forwarded_count: int
    blocked_count: int
    last_forwarded_at: datetime | None


class AliasList(BaseModel):
    aliases: list[AliasOut]
    domains: list[str]
    forwards_to: str | None


class ResolveIn(BaseModel):
    address: str = Field(max_length=320)


class ResolveOut(BaseModel):
    action: str  # "forward" or "reject"
    to: str | None = None
    reason: str | None = None


def _out(alias: EmailAlias) -> AliasOut:
    return AliasOut(
        id=alias.id,
        address=alias.address,
        label=alias.label,
        paused=alias.paused_at is not None,
        created_at=alias.created_at,
        forwarded_count=alias.forwarded_count,
        blocked_count=alias.blocked_count,
        last_forwarded_at=alias.last_forwarded_at,
    )


def domains_for(db: Session, user: User) -> list[str]:
    """The relay's domains, then the person's own verified ones."""
    own = db.scalars(
        select(VerifiedDomain.domain).where(
            VerifiedDomain.user_id == user.id, VerifiedDomain.verified_at.is_not(None)
        )
    ).all()
    seen: dict[str, None] = {}
    for domain in [*get_settings().alias_domains, *own]:
        seen[domain.lower().strip(".")] = None
    return list(seen)


def list_aliases(db: Session, user: User) -> AliasList:
    rows = db.scalars(
        select(EmailAlias)
        .where(EmailAlias.user_id == user.id, EmailAlias.deleted_at.is_(None))
        .order_by(EmailAlias.created_at.desc())
    ).all()
    return AliasList(
        aliases=[_out(a) for a in rows],
        domains=domains_for(db, user),
        forwards_to=user.email if user.email_verified_at else None,
    )


def create_alias(db: Session, user: User, body: AliasIn) -> AliasOut:
    rate_limit.enforce(CREATE_LIMIT, f"user:{user.id}")
    if not user.email_verified_at:
        raise ApiError(
            409, "email_not_verified", "Verify your email address first: aliases forward to it."
        )
    domains = domains_for(db, user)
    if not domains:
        raise ApiError(409, "no_alias_domain", "This server has no alias domain set up yet.")
    domain = (body.domain or domains[0]).lower().strip(".")
    if domain not in domains:
        raise ApiError(
            400,
            "domain_not_allowed",
            "Use this server's alias domain or one of your verified domains.",
        )
    count = db.scalar(
        select(func.count())
        .select_from(EmailAlias)
        .where(EmailAlias.user_id == user.id, EmailAlias.deleted_at.is_(None))
    )
    if (count or 0) >= get_settings().alias_limit_per_user:
        raise ApiError(
            409,
            "alias_limit",
            "You have reached the number of aliases this server allows. Delete some first.",
        )
    label = body.label.strip() if body.label else None
    if body.local_part is not None:
        local = body.local_part.lower()
        if not LOCAL_PART.match(local) or ".." in local or local in RESERVED:
            raise ApiError(
                400, "bad_local_part", "Use 2-32 letters, digits, dots, dashes or underscores."
            )
        candidates = [local]
    else:
        candidates = ["".join(secrets.choice(_ALPHABET) for _ in range(10)) for _ in range(5)]
    for local in candidates:
        taken = db.scalar(
            select(EmailAlias.id).where(EmailAlias.local_part == local, EmailAlias.domain == domain)
        )
        if taken is None:
            alias = EmailAlias(user_id=user.id, local_part=local, domain=domain, label=label)
            db.add(alias)
            db.commit()
            return _out(alias)
    # Deleted aliases keep their address forever, so a chosen name may be gone.
    raise ApiError(409, "alias_taken", "That address is taken. Choose another.")


def _own_alias(db: Session, user: User, alias_id: uuid.UUID) -> EmailAlias:
    alias = db.get(EmailAlias, alias_id)
    if alias is None or alias.user_id != user.id or alias.deleted_at is not None:
        raise ApiError(404, "alias_not_found", "That alias doesn't exist.")
    return alias


# --- Website (session) ---------------------------------------------------------------


@router.get("/aliases", response_model=AliasList)
def get_aliases(user: SessionUser, db: Db) -> AliasList:
    return list_aliases(db, user)


@router.post("/aliases", response_model=AliasOut, status_code=201)
def post_alias(body: AliasIn, user: SessionUser, db: Db) -> AliasOut:
    return create_alias(db, user, body)


@router.patch("/aliases/{alias_id}", response_model=AliasOut)
def patch_alias(alias_id: uuid.UUID, body: AliasPatch, user: SessionUser, db: Db) -> AliasOut:
    alias = _own_alias(db, user, alias_id)
    if body.paused is not None:
        alias.paused_at = (alias.paused_at or utcnow()) if body.paused else None
    if body.label is not None:
        alias.label = body.label.strip() or None
    db.commit()
    return _out(alias)


@router.delete("/aliases/{alias_id}", status_code=204)
def delete_alias(alias_id: uuid.UUID, user: SessionUser, db: Db) -> None:
    alias = _own_alias(db, user, alias_id)
    alias.deleted_at = utcnow()
    alias.label = None  # nothing about what it was for is kept
    db.commit()


# --- Browser extension and desktop app ------------------------------------------------


def _linked_user(db: Session, user_id: uuid.UUID | None) -> User:
    user = db.get(User, user_id) if user_id else None
    if user is None or user.disabled_at is not None:
        raise ApiError(409, "not_linked", "Link this to your Qalaa account first.")
    return user


@router.get("/extension/aliases", response_model=AliasList)
def extension_aliases(installation: CurrentInstallation, db: Db) -> AliasList:
    return list_aliases(db, _linked_user(db, installation.user_id))


@router.post("/extension/aliases", response_model=AliasOut, status_code=201)
def extension_new_alias(body: AliasIn, installation: CurrentInstallation, db: Db) -> AliasOut:
    return create_alias(db, _linked_user(db, installation.user_id), body)


@router.get("/devices/aliases", response_model=AliasList)
def device_aliases(device: CurrentDevice, db: Db) -> AliasList:
    return list_aliases(db, _linked_user(db, device.user_id))


@router.post("/devices/aliases", response_model=AliasOut, status_code=201)
def device_new_alias(body: AliasIn, device: CurrentDevice, db: Db) -> AliasOut:
    return create_alias(db, _linked_user(db, device.user_id), body)


# --- The mail relay -----------------------------------------------------------------


@router.post("/relay/aliases/resolve", response_model=ResolveOut, include_in_schema=False)
def resolve(
    body: ResolveIn, db: Db, authorization: str | None = Header(default=None)
) -> ResolveOut:
    """Where the relay should send mail for `address`. Counts forwards and refusals."""
    token = get_settings().alias_relay_token
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not token or not hmac.compare_digest(supplied, token):
        raise ApiError(401, "unauthorized", "Relay token required.")
    local, _, domain = body.address.strip().lower().rpartition("@")
    local = local.split("+", 1)[0]  # sub-addressing: name+tag@ goes to name@
    alias = db.scalar(
        select(EmailAlias).where(EmailAlias.local_part == local, EmailAlias.domain == domain)
    )
    if alias is None:
        return ResolveOut(action="reject", reason="unknown")
    if alias.deleted_at is not None or alias.paused_at is not None:
        db.execute(
            update(EmailAlias)
            .where(EmailAlias.id == alias.id)
            .values(blocked_count=EmailAlias.blocked_count + 1)
        )
        db.commit()
        return ResolveOut(action="reject", reason="deleted" if alias.deleted_at else "paused")
    owner = db.get(User, alias.user_id)
    if owner is None or owner.disabled_at is not None or not owner.email_verified_at:
        return ResolveOut(action="reject", reason="unavailable")
    db.execute(
        update(EmailAlias)
        .where(EmailAlias.id == alias.id)
        .values(forwarded_count=EmailAlias.forwarded_count + 1, last_forwarded_at=utcnow())
    )
    db.commit()
    return ResolveOut(action="forward", to=owner.email)
