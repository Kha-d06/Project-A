import hmac
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.errors import ApiError
from app.core.security import token_digest
from app.models import ApiKey, User, UserSession
from app.models.base import utcnow

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

Db = Annotated[Session, Depends(get_db)]


def get_current_session(request: Request, db: Db) -> UserSession | None:
    token = request.cookies.get(get_settings().session_cookie_name)
    if not token:
        return None
    session = db.scalar(
        select(UserSession).where(
            UserSession.token_digest == token_digest(token), UserSession.expires_at > utcnow()
        )
    )
    if session is None or session.user.disabled_at is not None:
        return None

    # The session cookie is sent automatically by the browser, so state-changing
    # requests must also prove they come from our own frontend.
    if request.method not in _SAFE_METHODS:
        supplied = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(supplied, session.csrf_token):
            raise ApiError(
                403, "csrf_failed", "Your session could not be verified. Reload the page and retry."
            )
    return session


CurrentSession = Annotated[UserSession | None, Depends(get_current_session)]


API_KEY_PREFIX = "snt_"
_API_KEY_TOUCH_SECONDS = 300


def _api_key_user(request: Request, db: Session) -> User | None:
    """Personal API keys, sent as "Authorization: Bearer snt_...". No CSRF check is
    needed: browsers never attach this header on their own."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.startswith(API_KEY_PREFIX):
        return None
    key = db.scalar(select(ApiKey).where(ApiKey.key_digest == token_digest(token.strip())))
    if key is None or key.revoked_at is not None:
        raise ApiError(401, "invalid_api_key", "This API key is not valid or has been revoked.")
    user = db.get(User, key.user_id)
    if user is None or user.disabled_at is not None:
        raise ApiError(401, "invalid_api_key", "This API key's account is not active.")
    now = utcnow()
    if (
        key.last_used_at is None
        or (now - key.last_used_at).total_seconds() > _API_KEY_TOUCH_SECONDS
    ):
        key.last_used_at = now
        db.commit()
    request.state.via_api_key = True
    return user


def get_optional_user(request: Request, session: CurrentSession, db: Db) -> User | None:
    if session:
        return session.user
    return _api_key_user(request, db)


def get_required_user(user: Annotated[User | None, Depends(get_optional_user)]) -> User:
    if user is None:
        raise ApiError(401, "not_authenticated", "Sign in to continue.")
    return user


def get_session_user(session: CurrentSession) -> User:
    """Signed in through the website. Required for account, key and staff actions,
    so a leaked API key cannot change passwords, delete accounts or administer."""
    if session is None:
        raise ApiError(401, "not_authenticated", "Sign in on the website to do this.")
    return session.user


OptionalUser = Annotated[User | None, Depends(get_optional_user)]
RequiredUser = Annotated[User, Depends(get_required_user)]
SessionUser = Annotated[User, Depends(get_session_user)]

# Admins can do everything moderators can. Checked on every request, on the server;
# hiding links in the interface is a convenience, not a control.
_ROLE_LEVEL = {"user": 0, "moderator": 1, "admin": 2}


def _require(level: str) -> Callable[[User], User]:
    def check(user: SessionUser) -> User:
        if _ROLE_LEVEL.get(user.role, 0) < _ROLE_LEVEL[level]:
            raise ApiError(403, "forbidden", "You do not have permission to do this.")
        return user

    return check


ModeratorUser = Annotated[User, Depends(_require("moderator"))]
AdminUser = Annotated[User, Depends(_require("admin"))]
