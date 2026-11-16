"""Credentials for the browser extension.

Enrollment issues a long-lived refresh token (stored as a digest, revocable) and
short-lived access tokens. Access tokens are HMAC-signed so they can be checked
without a database read, but every request still confirms the installation has
not been revoked.
"""

import base64
import hashlib
import hmac
import time
import uuid
from typing import Annotated

from fastapi import Depends, Request

from app.api.deps import Db
from app.core.config import get_settings
from app.core.errors import ApiError
from app.models import ExtensionInstallation
from app.models.base import utcnow

ACCESS_TOKEN_SECONDS = 15 * 60
_LAST_SEEN_RESOLUTION_SECONDS = 300
_PREFIX = "sxa1"


def _signature(payload: str) -> str:
    key = hashlib.sha256(b"extension-access:" + get_settings().secret_key.encode()).digest()
    digest = hmac.new(key, payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def issue_access_token(installation_id: uuid.UUID, now: float | None = None) -> str:
    expires = int((now or time.time()) + ACCESS_TOKEN_SECONDS)
    payload = f"{_PREFIX}.{installation_id}.{expires}"
    return f"{payload}.{_signature(payload)}"


def read_access_token(token: str, now: float | None = None) -> uuid.UUID | None:
    try:
        prefix, raw_id, raw_expiry, signature = token.split(".")
        installation_id = uuid.UUID(raw_id)
        expires = int(raw_expiry)
    except ValueError:
        return None
    payload = f"{prefix}.{raw_id}.{raw_expiry}"
    if prefix != _PREFIX or not hmac.compare_digest(signature, _signature(payload)):
        return None
    if expires < (now or time.time()):
        return None
    return installation_id


def _unauthorized(message: str) -> ApiError:
    return ApiError(401, "extension_unauthorized", message, headers={"WWW-Authenticate": "Bearer"})


def get_installation(request: Request, db: Db) -> ExtensionInstallation:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise _unauthorized("This request needs an extension access token.")
    installation_id = read_access_token(token.strip())
    if installation_id is None:
        raise _unauthorized("The access token is invalid or expired. Refresh it and retry.")
    installation = db.get(ExtensionInstallation, installation_id)
    if installation is None or installation.revoked_at is not None:
        raise _unauthorized("This extension has been disconnected. Enroll it again.")

    now = utcnow()
    if (now - installation.last_seen_at).total_seconds() > _LAST_SEEN_RESOLUTION_SECONDS:
        installation.last_seen_at = now
        db.commit()
    return installation


CurrentInstallation = Annotated[ExtensionInstallation, Depends(get_installation)]
