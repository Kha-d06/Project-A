"""Email verification, password reset and two-step sign-in."""

import base64
import hashlib
import hmac
import io
import secrets
import time
import uuid
from datetime import timedelta

import pyotp
import zxingcpp
from fastapi import APIRouter, BackgroundTasks, Request, Response
from PIL import Image
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.api.auth import LOGIN_IP_LIMIT, record_event, start_session
from app.api.deps import Db, SessionUser
from app.core import rate_limit
from app.core.config import get_settings
from app.core.crypto import decrypt, encrypt
from app.core.db import get_session_factory
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, client_address
from app.core.security import hash_password, new_token, token_digest, verify_password
from app.models import AccountToken, AuditEvent, BackupCode, User, UserSession
from app.models.base import utcnow
from app.notify.email import EmailUnavailableError, email_enabled, send_email
from app.schemas.account import (
    ChallengeAnswer,
    CodeRequest,
    LoginChallenge,
    ResetConfirm,
    ResetRequest,
    TokenRequest,
    TwoFactorDisable,
    TwoFactorEnabled,
    TwoFactorSetup,
)
from app.schemas.auth import SessionOut

router = APIRouter(tags=["Account security"])

VERIFY_LIFETIME = timedelta(hours=48)
RESET_LIFETIME = timedelta(hours=1)
CHALLENGE_SECONDS = 300
BACKUP_CODE_COUNT = 10
RESET_LIMIT = RateLimit("password-reset", max_requests=5, window_seconds=3600)
VERIFY_SEND_LIMIT = RateLimit("verify-send", max_requests=5, window_seconds=3600)
TWO_FACTOR_LIMIT = RateLimit("two-factor", max_requests=6, window_seconds=900)
_ISSUER = "SENTINEL"


def _require_email() -> None:
    if not email_enabled():
        raise ApiError(503, "email_unavailable", "Email delivery is not configured on this server.")


def _issue_token(db: Session, user: User, purpose: str, lifetime: timedelta) -> str:
    # One live token per purpose: issuing a new link invalidates older ones.
    db.execute(
        delete(AccountToken).where(AccountToken.user_id == user.id, AccountToken.purpose == purpose)
    )
    token = new_token()
    db.add(
        AccountToken(
            token_digest=token_digest(token),
            user_id=user.id,
            purpose=purpose,
            expires_at=utcnow() + lifetime,
        )
    )
    db.flush()
    return token


def _redeem_token(db: Session, token: str, purpose: str) -> User:
    record = db.get(AccountToken, token_digest(token))
    if (
        record is None
        or record.purpose != purpose
        or record.used_at
        or record.expires_at < utcnow()
    ):
        raise ApiError(
            400, "invalid_token", "This link is invalid or has expired. Request a new one."
        )
    record.used_at = utcnow()
    user = db.get(User, record.user_id)
    if user is None or user.disabled_at is not None:
        raise ApiError(
            400, "invalid_token", "This link is invalid or has expired. Request a new one."
        )
    return user


def send_verification(db: Session, user: User) -> None:
    token = _issue_token(db, user, "verify", VERIFY_LIFETIME)
    link = f"{get_settings().public_url}/verify-email?token={token}"
    send_email(
        db,
        user.email,
        "Confirm your email address for SENTINEL",
        "Confirm that this email address belongs to you by opening this link within 48 hours:\n\n"
        f"{link}\n\nIf you did not create a SENTINEL account, you can ignore this message.\n",
    )
    db.commit()


# --- Email verification -------------------------------------------------------------


@router.post("/auth/verify-email/send", status_code=202)
def resend_verification(user: SessionUser, db: Db) -> dict[str, str]:
    _require_email()
    if user.email_verified_at:
        return {"status": "already_verified"}
    rate_limit.enforce(VERIFY_SEND_LIMIT, f"user:{user.id}")
    try:
        send_verification(db, user)
    except EmailUnavailableError as exc:
        raise ApiError(503, "email_unavailable", str(exc)) from exc
    return {"status": "sent"}


@router.post("/auth/verify-email", status_code=204)
def verify_email(body: TokenRequest, request: Request, db: Db) -> None:
    user = _redeem_token(db, body.token, "verify")
    user.email_verified_at = user.email_verified_at or utcnow()
    record_event(db, request, user, "email_verified")
    db.commit()


# --- Password reset -----------------------------------------------------------------


def _send_reset_email(email: str, ip_address: str) -> None:
    """Runs after the response is sent, so a real account and an unknown address take
    the same time to answer and cannot be told apart."""
    with get_session_factory()() as db:
        user = db.scalar(select(User).where(User.email == email))
        if user is None or user.disabled_at is not None:
            return
        token = _issue_token(db, user, "reset", RESET_LIFETIME)
        link = f"{get_settings().public_url}/reset-password?token={token}"
        try:
            send_email(
                db,
                user.email,
                "Reset your SENTINEL password",
                "Someone asked to reset the password for this SENTINEL account. If it was you, "
                f"open this link within one hour:\n\n{link}\n\nIf it was not you, ignore this "
                "message; your password has not changed.\n",
            )
        except EmailUnavailableError:
            db.rollback()
            return
        db.add(
            AuditEvent(user_id=user.id, action="password_reset_requested", ip_address=ip_address)
        )
        db.commit()


@router.post("/auth/password-reset", status_code=202)
def request_reset(body: ResetRequest, request: Request, tasks: BackgroundTasks) -> dict[str, str]:
    """Always answers the same way, so it cannot be used to learn which emails have accounts."""
    _require_email()
    rate_limit.enforce(RESET_LIMIT, client_address(request))
    rate_limit.enforce(RESET_LIMIT, body.email.lower())
    tasks.add_task(_send_reset_email, body.email.lower(), client_address(request))
    return {"status": "If an account exists for that address, a reset link is on its way."}


@router.post("/auth/password-reset/confirm", status_code=204)
def confirm_reset(body: ResetConfirm, request: Request, db: Db) -> None:
    user = _redeem_token(db, body.token, "reset")
    user.password_hash = hash_password(body.new_password)
    # Whoever may have had the old password loses every session.
    db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    # Receiving the link proves control of the inbox.
    user.email_verified_at = user.email_verified_at or utcnow()
    record_event(db, request, user, "password_reset")
    db.commit()


# --- Two-step sign-in ---------------------------------------------------------------


def _totp(user: User) -> pyotp.TOTP | None:
    secret = decrypt(user.totp_secret_encrypted) if user.totp_secret_encrypted else None
    return pyotp.TOTP(secret) if secret else None


def _check_second_factor(db: Session, user: User, code: str) -> bool:
    """An authenticator code (allowing one step of clock drift) or an unused backup code."""
    cleaned = code.replace(" ", "").replace("-", "")
    totp = _totp(user)
    if totp and cleaned.isdigit() and len(cleaned) == 6 and totp.verify(cleaned, valid_window=1):
        return True
    backup = db.get(BackupCode, token_digest(cleaned.lower()))
    if backup and backup.user_id == user.id and backup.used_at is None:
        backup.used_at = utcnow()
        return True
    return False


def _qr_data_url(text: str) -> str:
    rendered = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode).to_image(scale=6)
    image = Image.frombytes("L", (rendered.shape[1], rendered.shape[0]), bytes(rendered))
    framed = Image.new("L", (image.width + 48, image.height + 48), 255)
    framed.paste(image, (24, 24))
    buffer = io.BytesIO()
    framed.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()


@router.post("/user/2fa/setup", response_model=TwoFactorSetup)
def setup_two_factor(user: SessionUser, db: Db) -> TwoFactorSetup:
    if user.totp_enabled_at:
        raise ApiError(409, "already_enabled", "Two-step sign-in is already on.")
    secret = pyotp.random_base32()
    user.totp_secret_encrypted = encrypt(secret)
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=_ISSUER)
    return TwoFactorSetup(secret=secret, otpauth_uri=uri, qr_code=_qr_data_url(uri))


@router.post("/user/2fa/enable", response_model=TwoFactorEnabled)
def enable_two_factor(
    body: CodeRequest, request: Request, user: SessionUser, db: Db
) -> TwoFactorEnabled:
    rate_limit.enforce(TWO_FACTOR_LIMIT, f"user:{user.id}")
    totp = _totp(user)
    if user.totp_enabled_at or totp is None:
        raise ApiError(409, "not_set_up", "Start the setup again.")
    if not totp.verify(body.code.replace(" ", ""), valid_window=1):
        raise ApiError(
            400,
            "wrong_code",
            "That code is not correct. Check the time on your phone and try again.",
        )
    codes = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(BACKUP_CODE_COUNT)]
    db.execute(delete(BackupCode).where(BackupCode.user_id == user.id))
    for code in codes:
        db.add(BackupCode(code_digest=token_digest(code.replace("-", "")), user_id=user.id))
    user.totp_enabled_at = utcnow()
    record_event(db, request, user, "two_factor_enabled")
    db.commit()
    return TwoFactorEnabled(backup_codes=codes)


@router.post("/user/2fa/disable", status_code=204)
def disable_two_factor(body: TwoFactorDisable, request: Request, user: SessionUser, db: Db) -> None:
    rate_limit.enforce(TWO_FACTOR_LIMIT, f"user:{user.id}")
    if not user.totp_enabled_at:
        return
    if not verify_password(body.password, user.password_hash) or not _check_second_factor(
        db, user, body.code
    ):
        raise ApiError(403, "wrong_credentials", "The password or code is not correct.")
    user.totp_enabled_at = None
    user.totp_secret_encrypted = None
    db.execute(delete(BackupCode).where(BackupCode.user_id == user.id))
    record_event(db, request, user, "two_factor_disabled")
    db.commit()


# The challenge proves the password step succeeded; it is short-lived, signed and
# bound to one user, and carries no session power by itself.


def _sign(payload: str) -> str:
    key = hashlib.sha256(b"login-challenge:" + get_settings().secret_key.encode()).digest()
    return (
        base64.urlsafe_b64encode(hmac.new(key, payload.encode(), hashlib.sha256).digest())
        .decode()
        .rstrip("=")
    )


def issue_challenge(user: User) -> LoginChallenge:
    payload = f"{user.id}.{int(time.time()) + CHALLENGE_SECONDS}.{secrets.token_hex(8)}"
    return LoginChallenge(challenge=f"{payload}.{_sign(payload)}")


def _read_challenge(challenge: str) -> uuid.UUID:
    try:
        user_id, expires, nonce, signature = challenge.split(".")
        payload = f"{user_id}.{expires}.{nonce}"
        valid = hmac.compare_digest(signature, _sign(payload)) and int(expires) >= time.time()
        if valid:
            return uuid.UUID(user_id)
    except ValueError:
        pass
    raise ApiError(401, "challenge_expired", "Your sign-in took too long. Start again.")


@router.post("/auth/login/two-factor", response_model=SessionOut)
def complete_login(
    body: ChallengeAnswer, request: Request, response: Response, db: Db
) -> SessionOut:
    rate_limit.enforce(LOGIN_IP_LIMIT, client_address(request))
    user_id = _read_challenge(body.challenge)
    rate_limit.enforce(TWO_FACTOR_LIMIT, f"user:{user_id}")
    user = db.get(User, user_id)
    if user is None or user.disabled_at is not None or not user.totp_enabled_at:
        raise ApiError(401, "challenge_expired", "Your sign-in took too long. Start again.")
    if not _check_second_factor(db, user, body.code):
        record_event(db, request, user, "two_factor_failed")
        db.commit()
        raise ApiError(401, "wrong_code", "That code is not correct.")
    record_event(db, request, user, "signed_in")
    return start_session(db, response, user)


@router.get("/user/security")
def security_status(user: SessionUser, db: Db) -> dict[str, object]:
    unused = db.scalar(
        select(func.count())
        .select_from(BackupCode)
        .where(BackupCode.user_id == user.id, BackupCode.used_at.is_(None))
    )
    return {
        "email_enabled": email_enabled(),
        "email_verified": user.email_verified_at is not None,
        "two_factor_enabled": user.totp_enabled_at is not None,
        "backup_codes_remaining": unused or 0,
    }
