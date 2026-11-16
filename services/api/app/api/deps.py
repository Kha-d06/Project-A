import hmac
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.errors import ApiError
from app.core.security import token_digest
from app.models import User, UserSession
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
    if session is None:
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


def get_optional_user(session: CurrentSession) -> User | None:
    return session.user if session else None


def get_required_user(session: CurrentSession) -> User:
    if session is None:
        raise ApiError(401, "not_authenticated", "Sign in to continue.")
    return session.user


OptionalUser = Annotated[User | None, Depends(get_optional_user)]
RequiredUser = Annotated[User, Depends(get_required_user)]
