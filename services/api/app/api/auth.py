from datetime import timedelta

from fastapi import APIRouter, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import CurrentSession, Db
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, client_address
from app.core.security import (
    hash_password,
    needs_rehash,
    new_token,
    token_digest,
    verify_password,
)
from app.models import AuditEvent, User, UserSession, UserSettings
from app.models.base import utcnow
from app.schemas.auth import LoginRequest, RegisterRequest, SessionOut, UserOut

router = APIRouter(prefix="/auth", tags=["Authentication"])

REGISTER_LIMIT = RateLimit("register", max_requests=5, window_seconds=3600)
LOGIN_IP_LIMIT = RateLimit("login-ip", max_requests=20, window_seconds=300)
LOGIN_ACCOUNT_LIMIT = RateLimit("login-account", max_requests=8, window_seconds=900)


def record_event(db: Session, request: Request, user: User | None, action: str) -> None:
    db.add(
        AuditEvent(
            user_id=user.id if user else None, action=action, ip_address=client_address(request)
        )
    )


def start_session(db: Session, response: Response, user: User) -> SessionOut:
    settings = get_settings()
    token = new_token()
    session = UserSession(
        user_id=user.id,
        token_digest=token_digest(token),
        csrf_token=new_token(),
        expires_at=utcnow() + timedelta(hours=settings.session_lifetime_hours),
    )
    db.add(session)
    db.commit()
    response.set_cookie(
        settings.session_cookie_name,
        token,
        max_age=settings.session_lifetime_hours * 3600,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    return SessionOut(user=UserOut.model_validate(user), csrf_token=session.csrf_token)


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(get_settings().session_cookie_name, path="/")


@router.post("/register", response_model=SessionOut, status_code=201)
def register(body: RegisterRequest, request: Request, response: Response, db: Db) -> SessionOut:
    rate_limit.enforce(REGISTER_LIMIT, client_address(request))
    user = User(
        email=body.email.lower(),
        password_hash=hash_password(body.password),
        display_name=(body.display_name or "").strip() or None,
        settings=UserSettings(),
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ApiError(
            409, "email_taken", "An account with this email already exists. Try signing in."
        ) from exc
    record_event(db, request, user, "account_created")
    return start_session(db, response, user)


@router.post("/login", response_model=SessionOut)
def login(body: LoginRequest, request: Request, response: Response, db: Db) -> SessionOut:
    email = body.email.lower()
    rate_limit.enforce(LOGIN_IP_LIMIT, client_address(request))
    rate_limit.enforce(LOGIN_ACCOUNT_LIMIT, email)

    user = db.scalar(select(User).where(User.email == email))
    if not verify_password(body.password, user.password_hash if user else None) or user is None:
        if user:
            record_event(db, request, user, "sign_in_failed")
            db.commit()
        raise ApiError(401, "invalid_credentials", "The email or password is incorrect.")

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    record_event(db, request, user, "signed_in")
    return start_session(db, response, user)


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, session: CurrentSession, db: Db) -> None:
    if session:
        record_event(db, request, session.user, "signed_out")
        db.delete(session)
        db.commit()
    clear_session_cookie(response)


@router.get("/session", response_model=SessionOut)
def current_session(session: CurrentSession) -> SessionOut:
    if session is None:
        raise ApiError(401, "not_authenticated", "You are not signed in.")
    return SessionOut(user=UserOut.model_validate(session.user), csrf_token=session.csrf_token)
