"""Password sharing and emergency access for the vault.

Everything shared here is encrypted in the browser to the recipient's public
key; the server only relays ciphertext and enforces the emergency-access time
delay. It can never read a shared login or a vault key.

Recipients are limited to people the user shares a family/organisation group
with, so a login can't be pushed to an arbitrary account.
"""

import base64
import binascii
import re
import uuid
from datetime import timedelta

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.api.auth import record_event
from app.api.deps import Db, SessionUser
from app.core import rate_limit
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.models import EmergencyContact, GroupMember, SharingKey, User, VaultShare
from app.models.base import utcnow

router = APIRouter(prefix="/vault", tags=["Password vault"])

SHARE_LIMIT = RateLimit("vault-share", max_requests=100, window_seconds=3600)
KEY_LIMIT = RateLimit("vault-sharing-key", max_requests=60, window_seconds=3600)

_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
MAX_CIPHERTEXT = 64 * 1024


def _is_base64(value: str) -> bool:
    if not _BASE64.fullmatch(value) or len(value) % 4:
        return False
    try:
        base64.b64decode(value, validate=True)
        return True
    except binascii.Error:
        return False


def _family_ids(db: Db, user: User) -> set[uuid.UUID]:
    """Every other user who shares at least one group with this user."""
    my_groups = select(GroupMember.group_id).where(GroupMember.user_id == user.id)
    rows = db.execute(
        select(GroupMember.user_id).where(
            GroupMember.group_id.in_(my_groups), GroupMember.user_id != user.id
        )
    ).all()
    return {row[0] for row in rows}


# --- Public keys -----------------------------------------------------------------------


class KeyIn(BaseModel):
    public_key: str = Field(max_length=500)

    @field_validator("public_key")
    @classmethod
    def valid(cls, value: str) -> str:
        if not _is_base64(value):
            raise ValueError("public_key must be base64")
        return value


class Recipient(BaseModel):
    user_id: uuid.UUID
    email: str
    public_key: str


@router.put("/sharing-key")
def set_sharing_key(body: KeyIn, request: Request, db: Db, user: SessionUser) -> dict[str, bool]:
    rate_limit.enforce(KEY_LIMIT, f"user:{user.id}")
    key = db.get(SharingKey, user.id)
    if key is None:
        db.add(SharingKey(user_id=user.id, public_key=body.public_key))
    else:
        key.public_key = body.public_key
        key.updated_at = utcnow()
    record_event(db, request, user, "vault_sharing_key_set")
    db.commit()
    return {"ok": True}


@router.get("/recipients", response_model=list[Recipient])
def list_recipients(db: Db, user: SessionUser) -> list[Recipient]:
    """Family members who have published a sharing key, so the client can encrypt to them."""
    ids = _family_ids(db, user)
    if not ids:
        return []
    rows = db.execute(
        select(User, SharingKey)
        .join(SharingKey, SharingKey.user_id == User.id)
        .where(User.id.in_(ids))
    ).all()
    return [Recipient(user_id=u.id, email=u.email, public_key=k.public_key) for u, k in rows]


# --- Sharing a login -------------------------------------------------------------------


class ShareIn(BaseModel):
    recipient_id: uuid.UUID
    ciphertext: str = Field(max_length=MAX_CIPHERTEXT)
    sender_ephemeral: str = Field(max_length=500)

    @field_validator("ciphertext", "sender_ephemeral")
    @classmethod
    def valid(cls, value: str) -> str:
        if not _is_base64(value):
            raise ValueError("must be base64")
        return value


class ShareOut(BaseModel):
    id: uuid.UUID
    sender_email: str
    ciphertext: str
    sender_ephemeral: str
    created_at: object


@router.post("/shares")
def create_share(body: ShareIn, request: Request, db: Db, user: SessionUser) -> dict[str, str]:
    rate_limit.enforce(SHARE_LIMIT, f"user:{user.id}")
    if body.recipient_id == user.id:
        raise ApiError(400, "invalid_recipient", "You can't share a login with yourself.")
    if body.recipient_id not in _family_ids(db, user):
        raise ApiError(403, "not_family", "You can only share with people in one of your groups.")
    share = VaultShare(
        sender_id=user.id,
        recipient_id=body.recipient_id,
        ciphertext=body.ciphertext,
        sender_ephemeral=body.sender_ephemeral,
    )
    db.add(share)
    record_event(db, request, user, "vault_share_sent")
    db.commit()
    return {"id": str(share.id)}


@router.get("/shares", response_model=list[ShareOut])
def list_shares(db: Db, user: SessionUser) -> list[ShareOut]:
    """Logins shared with me, waiting to be accepted into my vault."""
    rows = db.execute(
        select(VaultShare, User)
        .join(User, User.id == VaultShare.sender_id)
        .where(VaultShare.recipient_id == user.id)
    ).all()
    return [
        ShareOut(
            id=s.id,
            sender_email=u.email,
            ciphertext=s.ciphertext,
            sender_ephemeral=s.sender_ephemeral,
            created_at=s.created_at,
        )
        for s, u in rows
    ]


@router.delete("/shares/{share_id}")
def delete_share(
    share_id: uuid.UUID, request: Request, db: Db, user: SessionUser
) -> dict[str, bool]:
    """Accept (after copying into the vault client-side) or decline a received share,
    or revoke one I sent."""
    share = db.get(VaultShare, share_id)
    if share is None or user.id not in (share.recipient_id, share.sender_id):
        raise ApiError(404, "share_not_found", "That shared login no longer exists.")
    db.delete(share)
    db.commit()
    return {"ok": True}


# --- Emergency access ------------------------------------------------------------------


class EmergencyIn(BaseModel):
    grantee_id: uuid.UUID
    wait_hours: int = Field(ge=0, le=720)
    wrapped_vault_key: str = Field(max_length=MAX_CIPHERTEXT)
    sender_ephemeral: str = Field(max_length=500)

    @field_validator("wrapped_vault_key", "sender_ephemeral")
    @classmethod
    def valid(cls, value: str) -> str:
        if not _is_base64(value):
            raise ValueError("must be base64")
        return value


class EmergencyOut(BaseModel):
    id: uuid.UUID
    grantor_email: str
    grantee_email: str
    wait_hours: int
    state: str
    role: str  # "granted_by_me" | "granted_to_me"
    requested_at: object
    unlocks_at: object


def _emergency_out(
    contact: EmergencyContact, grantor: User, grantee: User, me: uuid.UUID
) -> EmergencyOut:
    unlocks_at = None
    if contact.requested_at is not None:
        unlocks_at = contact.requested_at + timedelta(hours=contact.wait_hours)
    return EmergencyOut(
        id=contact.id,
        grantor_email=grantor.email,
        grantee_email=grantee.email,
        wait_hours=contact.wait_hours,
        state=contact.state,
        role="granted_by_me" if contact.grantor_id == me else "granted_to_me",
        requested_at=contact.requested_at,
        unlocks_at=unlocks_at,
    )


@router.post("/emergency")
def grant_emergency(
    body: EmergencyIn, request: Request, db: Db, user: SessionUser
) -> dict[str, str]:
    rate_limit.enforce(SHARE_LIMIT, f"user:{user.id}")
    if body.grantee_id == user.id:
        raise ApiError(400, "invalid_grantee", "You can't name yourself as your emergency contact.")
    if body.grantee_id not in _family_ids(db, user):
        raise ApiError(403, "not_family", "Choose an emergency contact from one of your groups.")
    existing = db.execute(
        select(EmergencyContact).where(
            EmergencyContact.grantor_id == user.id, EmergencyContact.grantee_id == body.grantee_id
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.wait_hours = body.wait_hours
        existing.wrapped_vault_key = body.wrapped_vault_key
        existing.sender_ephemeral = body.sender_ephemeral
        existing.state = "active"
        existing.requested_at = None
        contact = existing
    else:
        contact = EmergencyContact(
            grantor_id=user.id,
            grantee_id=body.grantee_id,
            wait_hours=body.wait_hours,
            wrapped_vault_key=body.wrapped_vault_key,
            sender_ephemeral=body.sender_ephemeral,
            state="active",
        )
        db.add(contact)
    record_event(db, request, user, "vault_emergency_granted")
    db.commit()
    return {"id": str(contact.id)}


@router.get("/emergency", response_model=list[EmergencyOut])
def list_emergency(db: Db, user: SessionUser) -> list[EmergencyOut]:
    rows = (
        db.execute(
            select(EmergencyContact).where(
                (EmergencyContact.grantor_id == user.id) | (EmergencyContact.grantee_id == user.id)
            )
        )
        .scalars()
        .all()
    )
    out: list[EmergencyOut] = []
    for contact in rows:
        grantor = db.get(User, contact.grantor_id)
        grantee = db.get(User, contact.grantee_id)
        if grantor and grantee:
            out.append(_emergency_out(contact, grantor, grantee, user.id))
    return out


def _get_as_grantee(db: Db, contact_id: uuid.UUID, user: User) -> EmergencyContact:
    contact = db.get(EmergencyContact, contact_id)
    if contact is None or contact.grantee_id != user.id:
        raise ApiError(404, "emergency_not_found", "That emergency grant no longer exists.")
    return contact


@router.post("/emergency/{contact_id}/request")
def request_emergency(
    contact_id: uuid.UUID, request: Request, db: Db, user: SessionUser
) -> dict[str, str]:
    """A trusted contact asks to reach the grantor's vault; starts the waiting period."""
    contact = _get_as_grantee(db, contact_id, user)
    if contact.state not in ("active", "denied"):
        raise ApiError(409, "already_requested", "A request is already in progress.")
    contact.state = "requested"
    contact.requested_at = utcnow()
    record_event(db, request, user, "vault_emergency_requested")
    db.commit()
    return {"state": contact.state}


@router.post("/emergency/{contact_id}/deny")
def deny_emergency(
    contact_id: uuid.UUID, request: Request, db: Db, user: SessionUser
) -> dict[str, str]:
    """The grantor refuses a pending request."""
    contact = db.get(EmergencyContact, contact_id)
    if contact is None or contact.grantor_id != user.id:
        raise ApiError(404, "emergency_not_found", "That emergency grant no longer exists.")
    contact.state = "denied"
    contact.requested_at = None
    record_event(db, request, user, "vault_emergency_denied")
    db.commit()
    return {"state": contact.state}


@router.get("/emergency/{contact_id}/key")
def fetch_emergency_key(contact_id: uuid.UUID, db: Db, user: SessionUser) -> dict[str, str]:
    """Once the waiting period has elapsed with no denial, the grantee gets the
    grantor's vault key (still encrypted to the grantee's own key)."""
    contact = _get_as_grantee(db, contact_id, user)
    if contact.state != "requested" or contact.requested_at is None:
        raise ApiError(409, "not_requested", "Request emergency access first.")
    unlocks_at = contact.requested_at + timedelta(hours=contact.wait_hours)
    if utcnow() < unlocks_at:
        raise ApiError(
            425,
            "still_waiting",
            "The waiting period has not finished yet.",
            details={"unlocks_at": unlocks_at.isoformat()},
        )
    return {
        "wrapped_vault_key": contact.wrapped_vault_key,
        "sender_ephemeral": contact.sender_ephemeral,
    }


@router.delete("/emergency/{contact_id}")
def revoke_emergency(
    contact_id: uuid.UUID, request: Request, db: Db, user: SessionUser
) -> dict[str, bool]:
    contact = db.get(EmergencyContact, contact_id)
    if contact is None or user.id not in (contact.grantor_id, contact.grantee_id):
        raise ApiError(404, "emergency_not_found", "That emergency grant no longer exists.")
    db.delete(contact)
    record_event(db, request, user, "vault_emergency_revoked")
    db.commit()
    return {"ok": True}
