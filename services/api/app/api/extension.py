import secrets
import uuid
from datetime import timedelta

from fastapi import APIRouter, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analyzers.quick_check import QuickResult, quick_check_download, quick_check_url
from app.analyzers.urls import parse_url
from app.api.deps import Db, RequiredUser
from app.api.extension_auth import (
    ACCESS_TOKEN_SECONDS,
    CurrentInstallation,
    issue_access_token,
)
from app.core import rate_limit
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, client_address
from app.core.security import new_token, token_digest
from app.models import ExtensionEvent, ExtensionInstallation, ExtensionLinkCode, User
from app.models.base import utcnow
from app.schemas.extension import (
    AccessToken,
    CheckDownloadRequest,
    CheckUrlRequest,
    Credentials,
    EnrollRequest,
    EventReport,
    EventStored,
    ExtensionEventOut,
    ExtensionSettings,
    InstallationOut,
    LinkCodeOut,
    LinkRequest,
    QuickVerdict,
    Reason,
    RefreshRequest,
)

router = APIRouter(prefix="/extension", tags=["Browser extension"])

ENROLL_LIMIT = RateLimit("ext-enroll", max_requests=10, window_seconds=3600)
LINK_ATTEMPT_LIMIT = RateLimit("ext-link", max_requests=10, window_seconds=900)
# Generous: one check per page load, with the extension's own cache in front.
CHECK_LIMIT = RateLimit("ext-check", max_requests=1200, window_seconds=3600)
EVENT_LIMIT = RateLimit("ext-event", max_requests=300, window_seconds=3600)

LINK_CODE_LIFETIME = timedelta(minutes=10)
# No 0/O or 1/I, so a code read off a screen is typed correctly.
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CODE_LENGTH = 8


def _normalize_code(code: str) -> str:
    return "".join(char for char in code.upper() if char.isalnum())


def _redeem_link_code(db: Session, request: Request, code: str) -> User:
    rate_limit.enforce(LINK_ATTEMPT_LIMIT, client_address(request))
    link = db.get(ExtensionLinkCode, token_digest(_normalize_code(code)))
    if link is None or link.used_at is not None or link.expires_at < utcnow():
        raise ApiError(
            400,
            "invalid_link_code",
            "That code is not valid. Codes work once and expire after 10 minutes; create a "
            "new one in your dashboard.",
        )
    link.used_at = utcnow()
    user = db.get(User, link.user_id)
    if user is None:
        raise ApiError(400, "invalid_link_code", "That code is not valid.")
    return user


def _to_verdict(result: QuickResult) -> QuickVerdict:
    return QuickVerdict(
        verdict=result.verdict,
        host=result.host,
        reasons=[
            Reason(
                severity=reason.severity,
                title=reason.title,
                explanation=reason.explanation,
                source=reason.source,
                evidence={k: v for k, v in reason.evidence.items() if v is not None},
            )
            for reason in result.reasons
        ],
        sources=result.sources,
        limitations=result.limitations,
        checked_at=result.checked_at,
        cache_seconds=result.cache_seconds,
    )


# --- Extension-facing endpoints ---------------------------------------------------


@router.post("/enroll", response_model=Credentials, status_code=201)
def enroll(body: EnrollRequest, request: Request, db: Db) -> Credentials:
    """Register a new installation. Works without an account; a link code attaches one."""
    rate_limit.enforce(ENROLL_LIMIT, client_address(request))
    user = _redeem_link_code(db, request, body.link_code) if body.link_code else None
    refresh_token = new_token()
    installation = ExtensionInstallation(
        user_id=user.id if user else None,
        refresh_digest=token_digest(refresh_token),
        browser=body.browser.strip(),
        version=body.version.strip(),
    )
    db.add(installation)
    db.commit()
    return Credentials(
        installation_id=installation.id,
        refresh_token=refresh_token,
        access_token=issue_access_token(installation.id),
        expires_in=ACCESS_TOKEN_SECONDS,
        linked=user is not None,
    )


@router.post("/token", response_model=AccessToken)
def refresh_access_token(body: RefreshRequest, db: Db) -> AccessToken:
    installation = db.scalar(
        select(ExtensionInstallation).where(
            ExtensionInstallation.refresh_digest == token_digest(body.refresh_token)
        )
    )
    if installation is None or installation.revoked_at is not None:
        raise ApiError(
            401, "extension_unauthorized", "This extension has been disconnected. Enroll it again."
        )
    installation.last_seen_at = utcnow()
    db.commit()
    return AccessToken(
        access_token=issue_access_token(installation.id), expires_in=ACCESS_TOKEN_SECONDS
    )


@router.post("/link", response_model=ExtensionSettings)
def link_installation(
    body: LinkRequest, request: Request, installation: CurrentInstallation, db: Db
) -> ExtensionSettings:
    user = _redeem_link_code(db, request, body.link_code)
    installation.user_id = user.id
    db.commit()
    return extension_settings(installation, db)


@router.post("/unlink", response_model=ExtensionSettings)
def unlink_installation(installation: CurrentInstallation, db: Db) -> ExtensionSettings:
    installation.user_id = None
    db.commit()
    return extension_settings(installation, db)


@router.get("/settings", response_model=ExtensionSettings)
def extension_settings(installation: CurrentInstallation, db: Db) -> ExtensionSettings:
    user = db.get(User, installation.user_id) if installation.user_id else None
    return ExtensionSettings(
        installation_id=installation.id,
        linked=user is not None,
        account_email=user.email if user else None,
        sync_events=bool(user and user.settings.sync_extension_events),
    )


@router.post("/check-url", response_model=QuickVerdict)
def check_url(body: CheckUrlRequest, installation: CurrentInstallation, db: Db) -> QuickVerdict:
    """Nothing about the request is stored: checking a site leaves no record."""
    rate_limit.enforce(CHECK_LIMIT, f"install:{installation.id}")
    return _to_verdict(quick_check_url(db, body.url, host_only=body.mode == "host"))


@router.post("/check-download", response_model=QuickVerdict)
def check_download(
    body: CheckDownloadRequest, installation: CurrentInstallation, db: Db
) -> QuickVerdict:
    rate_limit.enforce(CHECK_LIMIT, f"install:{installation.id}")
    return _to_verdict(quick_check_download(db, body.url, body.filename))


@router.post("/report-event", response_model=EventStored)
def report_event(body: EventReport, installation: CurrentInstallation, db: Db) -> EventStored:
    rate_limit.enforce(EVENT_LIMIT, f"install:{installation.id}")
    user = db.get(User, installation.user_id) if installation.user_id else None
    if user is None or not user.settings.sync_extension_events:
        return EventStored(stored=False)
    db.add(
        ExtensionEvent(
            user_id=user.id,
            installation_id=installation.id,
            kind=body.kind,
            host=parse_url(body.url).host,
            verdict=body.verdict,
        )
    )
    db.commit()
    return EventStored(stored=True)


# --- Account-facing endpoints (dashboard) -----------------------------------------


@router.post("/link-codes", response_model=LinkCodeOut, status_code=201)
def create_link_code(user: RequiredUser, db: Db) -> LinkCodeOut:
    code = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))
    expires_at = utcnow() + LINK_CODE_LIFETIME
    db.add(
        ExtensionLinkCode(code_digest=token_digest(code), user_id=user.id, expires_at=expires_at)
    )
    db.commit()
    return LinkCodeOut(code=f"{code[:4]}-{code[4:]}", expires_at=expires_at)


@router.get("/installations", response_model=list[InstallationOut])
def list_installations(user: RequiredUser, db: Db) -> list[ExtensionInstallation]:
    return list(
        db.scalars(
            select(ExtensionInstallation)
            .where(
                ExtensionInstallation.user_id == user.id,
                ExtensionInstallation.revoked_at.is_(None),
            )
            .order_by(ExtensionInstallation.last_seen_at.desc())
        )
    )


@router.delete("/installations/{installation_id}", status_code=204)
def revoke_installation(installation_id: uuid.UUID, user: RequiredUser, db: Db) -> None:
    installation = db.get(ExtensionInstallation, installation_id)
    if installation is None or installation.user_id != user.id:
        raise ApiError(404, "installation_not_found", "This extension is not linked to you.")
    installation.revoked_at = utcnow()
    db.commit()


@router.get("/events", response_model=list[ExtensionEventOut])
def list_events(user: RequiredUser, db: Db) -> list[ExtensionEvent]:
    return list(
        db.scalars(
            select(ExtensionEvent)
            .where(ExtensionEvent.user_id == user.id)
            .order_by(ExtensionEvent.created_at.desc())
            .limit(50)
        )
    )


@router.delete("/events", status_code=204)
def clear_events(user: RequiredUser, db: Db) -> None:
    for event in db.scalars(select(ExtensionEvent).where(ExtensionEvent.user_id == user.id)):
        db.delete(event)
    db.commit()
