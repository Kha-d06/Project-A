"""Signing in to a Qalaa account with a passkey (WebAuthn), Wave 4.F.

Follows the OWASP Authentication Cheat Sheet's WebAuthn guidance, using
py_webauthn (BSD-3-Clause) for the verification itself:

* Challenges are 32 random bytes, stored server-side, single-use (marked used
  before verifying, so a replay fails whatever the outcome), bound to one
  purpose and, for registration, to the signed-in person; five minutes to live.
* The relying party id and allowed origins come from configuration; the
  browser's origin and the RP id hash are checked by the library.
* User verification (PIN or biometric) is required, so a passkey sign-in is
  two factors in one and doesn't also ask for the TOTP code.
* The signature counter must go up when the authenticator keeps one; a counter
  that goes backwards suggests a cloned authenticator and the sign-in is refused.
* The user handle is the account's random id, never the email address.
* Removing a passkey needs the password again; sign-in errors don't say
  whether an account or passkey exists.
"""

import json
import secrets
import uuid
from datetime import timedelta
from typing import Any, cast
from urllib.parse import urlsplit

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.api.auth import LOGIN_IP_LIMIT, record_event, start_session
from app.api.deps import Db, SessionUser
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, client_address
from app.core.security import verify_password
from app.models import AccountPasskey, User, WebAuthnChallenge
from app.models.base import utcnow
from app.schemas.auth import SessionOut

router = APIRouter(tags=["passkeys"])

CHALLENGE_TTL = timedelta(minutes=5)
MAX_PASSKEYS = 10
PASSKEY_LIMIT = RateLimit("passkey", max_requests=20, window_seconds=900)
NOT_RECOGNISED = (
    "That passkey isn't recognised. Sign in with your password, or try another passkey."
)


def relying_party() -> tuple[str, list[str]]:
    settings = get_settings()
    origins = settings.webauthn_origins or [settings.public_url.rstrip("/")]
    rp_id = settings.webauthn_rp_id or (urlsplit(settings.public_url).hostname or "localhost")
    return rp_id, origins


class OptionsOut(BaseModel):
    challenge_id: uuid.UUID
    # PublicKeyCredentialCreationOptions / RequestOptions as JSON, for navigator.credentials.
    options: dict[str, Any]


class RegisterIn(BaseModel):
    challenge_id: uuid.UUID
    credential: dict[str, Any]
    name: str = Field(min_length=1, max_length=60)


class SignInIn(BaseModel):
    challenge_id: uuid.UUID
    credential: dict[str, Any]


class RemoveIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class PasskeyOut(BaseModel):
    id: uuid.UUID
    name: str
    created_at: str
    last_used_at: str | None
    backed_up: bool


def _new_challenge(db: Session, purpose: str, user: User | None) -> WebAuthnChallenge:
    # Old challenges are cleared as new ones are made, so the table stays small.
    db.execute(
        delete(WebAuthnChallenge).where(
            WebAuthnChallenge.expires_at < utcnow() - timedelta(hours=1)
        )
    )
    row = WebAuthnChallenge(
        challenge=secrets.token_bytes(32),
        purpose=purpose,
        user_id=user.id if user else None,
        expires_at=utcnow() + CHALLENGE_TTL,
    )
    db.add(row)
    db.flush()
    return row


def _use_challenge(db: Session, challenge_id: uuid.UUID, purpose: str, user: User | None) -> bytes:
    """Marks the challenge used (once only) and returns its bytes."""
    conditions = [
        WebAuthnChallenge.id == challenge_id,
        WebAuthnChallenge.purpose == purpose,
        WebAuthnChallenge.used_at.is_(None),
        WebAuthnChallenge.expires_at > utcnow(),
    ]
    if user is not None:
        conditions.append(WebAuthnChallenge.user_id == user.id)
    result = cast(
        CursorResult[Any],
        db.execute(update(WebAuthnChallenge).where(*conditions).values(used_at=utcnow())),
    )
    if result.rowcount != 1:
        db.commit()
        raise ApiError(
            400, "challenge_expired", "This took too long or was already used. Start again."
        )
    row = db.get(WebAuthnChallenge, challenge_id)
    db.commit()
    if row is None:  # deleted between the update and here
        raise ApiError(
            400, "challenge_expired", "This took too long or was already used. Start again."
        )
    return row.challenge


def _out(p: AccountPasskey) -> PasskeyOut:
    return PasskeyOut(
        id=p.id,
        name=p.name,
        created_at=p.created_at.isoformat(),
        last_used_at=p.last_used_at.isoformat() if p.last_used_at else None,
        backed_up=p.backed_up,
    )


@router.get("/user/passkeys", response_model=list[PasskeyOut])
def list_passkeys(user: SessionUser, db: Db) -> list[PasskeyOut]:
    rows = db.scalars(
        select(AccountPasskey)
        .where(AccountPasskey.user_id == user.id)
        .order_by(AccountPasskey.created_at)
    )
    return [_out(p) for p in rows]


@router.post("/user/passkeys/options", response_model=OptionsOut)
def registration_options(user: SessionUser, db: Db) -> OptionsOut:
    rate_limit.enforce(PASSKEY_LIMIT, f"user:{user.id}")
    existing = list(db.scalars(select(AccountPasskey).where(AccountPasskey.user_id == user.id)))
    if len(existing) >= MAX_PASSKEYS:
        raise ApiError(
            409, "too_many", f"An account can have up to {MAX_PASSKEYS} passkeys. Remove one first."
        )
    rp_id, _ = relying_party()
    challenge = _new_challenge(db, "register", user)
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="Qalaa",
        user_id=user.id.bytes,
        user_name=user.email,
        challenge=challenge.challenge,
        timeout=300_000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=p.credential_id) for p in existing],
    )
    db.commit()
    return OptionsOut(challenge_id=challenge.id, options=json.loads(options_to_json(options)))


@router.post("/user/passkeys", response_model=PasskeyOut, status_code=201)
def add_passkey(body: RegisterIn, request: Request, user: SessionUser, db: Db) -> PasskeyOut:
    rate_limit.enforce(PASSKEY_LIMIT, f"user:{user.id}")
    expected = _use_challenge(db, body.challenge_id, "register", user)
    rp_id, origins = relying_party()
    try:
        verified = verify_registration_response(
            credential=body.credential,
            expected_challenge=expected,
            expected_rp_id=rp_id,
            expected_origin=origins,
            require_user_verification=True,
        )
    except InvalidRegistrationResponse as exc:
        raise ApiError(400, "passkey_invalid", f"The passkey couldn't be added ({exc}).") from exc
    if db.scalar(
        select(AccountPasskey).where(AccountPasskey.credential_id == verified.credential_id)
    ):
        raise ApiError(409, "already_added", "This passkey is already linked to an account.")
    count = db.scalar(
        select(func.count()).select_from(AccountPasskey).where(AccountPasskey.user_id == user.id)
    )
    if (count or 0) >= MAX_PASSKEYS:
        raise ApiError(
            409, "too_many", f"An account can have up to {MAX_PASSKEYS} passkeys. Remove one first."
        )
    transports = body.credential.get("response", {}).get("transports")
    passkey = AccountPasskey(
        user_id=user.id,
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        name=body.name.strip(),
        transports=",".join(t for t in transports if isinstance(t, str))[:120]
        if isinstance(transports, list)
        else None,
        backed_up=verified.credential_backed_up,
    )
    db.add(passkey)
    record_event(db, request, user, "passkey_added")
    db.commit()
    return _out(passkey)


@router.post("/user/passkeys/{passkey_id}/remove", status_code=204)
def remove_passkey(
    passkey_id: uuid.UUID, body: RemoveIn, request: Request, user: SessionUser, db: Db
) -> None:
    rate_limit.enforce(PASSKEY_LIMIT, f"user:{user.id}")
    if not verify_password(body.password, user.password_hash):
        raise ApiError(403, "wrong_credentials", "The password is not correct.")
    passkey = db.get(AccountPasskey, passkey_id)
    if passkey is None or passkey.user_id != user.id:
        raise ApiError(404, "not_found", "That passkey isn't on this account.")
    db.delete(passkey)
    record_event(db, request, user, "passkey_removed")
    db.commit()


@router.post("/auth/passkey/options", response_model=OptionsOut)
def sign_in_options(request: Request, db: Db) -> OptionsOut:
    rate_limit.enforce(LOGIN_IP_LIMIT, client_address(request))
    rp_id, _ = relying_party()
    challenge = _new_challenge(db, "login", None)
    # No allowCredentials: the browser offers the passkeys it has for this site
    # (discoverable credentials).
    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge.challenge,
        timeout=300_000,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    db.commit()
    return OptionsOut(challenge_id=challenge.id, options=json.loads(options_to_json(options)))


@router.post("/auth/passkey", response_model=SessionOut)
def sign_in(body: SignInIn, request: Request, response: Response, db: Db) -> SessionOut:
    rate_limit.enforce(LOGIN_IP_LIMIT, client_address(request))
    expected = _use_challenge(db, body.challenge_id, "login", None)
    raw_id = body.credential.get("rawId") or body.credential.get("id")
    try:
        credential_id = base64url_to_bytes(str(raw_id))
    except ValueError as exc:
        raise ApiError(401, "passkey_not_recognised", NOT_RECOGNISED) from exc
    passkey = db.scalar(select(AccountPasskey).where(AccountPasskey.credential_id == credential_id))
    user = db.get(User, passkey.user_id) if passkey else None
    if passkey is None or user is None or user.disabled_at is not None:
        raise ApiError(401, "passkey_not_recognised", NOT_RECOGNISED)
    rp_id, origins = relying_party()
    try:
        verified = verify_authentication_response(
            credential=body.credential,
            expected_challenge=expected,
            expected_rp_id=rp_id,
            expected_origin=origins,
            credential_public_key=passkey.public_key,
            credential_current_sign_count=passkey.sign_count,
            require_user_verification=True,
        )
    except InvalidAuthenticationResponse as exc:
        record_event(db, request, user, "passkey_failed")
        db.commit()
        raise ApiError(401, "passkey_not_recognised", NOT_RECOGNISED) from exc
    passkey.sign_count = verified.new_sign_count
    passkey.backed_up = verified.credential_backed_up
    passkey.last_used_at = utcnow()
    record_event(db, request, user, "signed_in_passkey")
    return start_session(db, response, user)
