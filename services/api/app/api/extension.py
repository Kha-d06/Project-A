import secrets
import uuid
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.ai.assistant import AssistantUnavailableError
from app.ai.assistant import answer as assistant_answer
from app.analyzers.quick_check import QuickResult, quick_check_download, quick_check_url
from app.analyzers.url_heuristics import RULES
from app.analyzers.urls import parse_url
from app.api.deps import Db, SessionUser
from app.api.extension_auth import (
    ACCESS_TOKEN_SECONDS,
    CurrentInstallation,
    issue_access_token,
)
from app.core import rate_limit
from app.core.cache import get_cache
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, client_address
from app.core.security import new_token, token_digest
from app.groups_policy import strictest_screen_time
from app.intel.feeds import COMMUNITY, THREATFOX
from app.intel.lookup import fresh_sources
from app.intel.prefixes import build_threat_prefixes, lookup_hashes
from app.models import (
    ExtensionEvent,
    ExtensionInstallation,
    ExtensionLinkCode,
    Group,
    GroupMember,
    ScreenTimeDay,
    ThreatIndicator,
    User,
    Vault,
)
from app.models.base import utcnow
from app.schemas.extension import (
    AccessToken,
    AssistantQuestion,
    AssistantReply,
    Blocklist,
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
    ScreenTimeReport,
    ScreenTimeRule,
    ThreatHashes,
    ThreatHashQuery,
    ThreatPrefixes,
)

router = APIRouter(prefix="/extension", tags=["Browser extension"])

ENROLL_LIMIT = RateLimit("ext-enroll", max_requests=10, window_seconds=3600)
LINK_ATTEMPT_LIMIT = RateLimit("ext-link", max_requests=10, window_seconds=900)
# Generous: one check per page load, with the extension's own cache in front.
CHECK_LIMIT = RateLimit("ext-check", max_requests=1200, window_seconds=3600)
EVENT_LIMIT = RateLimit("ext-event", max_requests=300, window_seconds=3600)
# The extension reports every few minutes; this leaves room for several browsers.
SCREEN_TIME_LIMIT = RateLimit("ext-screen-time", max_requests=120, window_seconds=3600)
QUICK_CACHE_SECONDS = 120
BLOCKLIST_LIMIT = RateLimit("ext-blocklist", max_requests=30, window_seconds=3600)
ASSISTANT_LIMIT = RateLimit("ext-assistant", max_requests=60, window_seconds=3600)

# Chrome allows 5,000 dynamic rules that redirect; blocking rules have more room, but
# a compact list keeps rule updates fast. Leave headroom for the user's own block list.
BLOCKLIST_MAX_HOSTS = 4500
# Only domain indicators are blocked outright. A listed URL on a shared host
# (a file-sharing service, a hacked blog) must not block the whole host.
_BLOCKLIST_SOURCES = (THREATFOX, COMMUNITY)

# Hash-prefix lookups (app/intel/prefixes.py).
PREFIX_LIMIT = RateLimit("ext-prefixes", max_requests=30, window_seconds=3600)
HASH_LIMIT = RateLimit("ext-hashes", max_requests=1200, window_seconds=3600)
RULES_LIMIT = RateLimit("ext-rules", max_requests=30, window_seconds=3600)

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
    domains: set[str] = set()
    groups: list[str] = []
    family_policies: list[dict[str, Any]] = []
    safe_search = lock_protection = False
    if user:
        for group in db.scalars(
            select(Group)
            .join(GroupMember, GroupMember.group_id == Group.id)
            .where(GroupMember.user_id == user.id, GroupMember.apply_blocklist.is_(True))
        ):
            policies = group.policies or {}
            if group.kind == "family":
                family_policies.append(policies)
                safe_search = safe_search or bool(policies.get("safe_search"))
                lock_protection = lock_protection or bool(policies.get("lock_protection"))
            if group.blocklist or (group.kind == "family" and policies):
                domains.update(group.blocklist or [])
                groups.append(group.name)
    return ExtensionSettings(
        installation_id=installation.id,
        linked=user is not None,
        account_email=user.email if user else None,
        sync_events=bool(user and user.settings.sync_extension_events),
        family_blocklist=sorted(domains)[:2000],
        family_groups=groups,
        safe_search=safe_search,
        lock_protection=lock_protection,
        screen_time=_screen_time_rule(family_policies),
    )


def _screen_time_rule(policies: list[dict[str, Any]]) -> ScreenTimeRule | None:
    rule = strictest_screen_time(policies)
    return ScreenTimeRule(**rule) if rule else None


@router.post("/screen-time", status_code=204)
def report_screen_time(body: ScreenTimeReport, installation: CurrentInstallation, db: Db) -> None:
    """A linked browser reports how many minutes it was actively used on one local
    day. Only the number is kept, and it only ever goes up within a day, so a
    second browser or a late retry cannot lower it."""
    rate_limit.enforce(SCREEN_TIME_LIMIT, f"installation:{installation.id}")
    if installation.user_id is None:
        raise ApiError(403, "not_linked", "Link this browser to an account first.")
    # One atomic upsert: two browsers reporting at once can't collide, and the
    # day's total only ever goes up.
    now = utcnow()
    dialect = db.get_bind().dialect.name
    insert = postgresql_insert if dialect == "postgresql" else sqlite_insert
    statement = insert(ScreenTimeDay).values(
        user_id=installation.user_id, day=body.day, minutes=body.minutes, updated_at=now
    )
    db.execute(
        statement.on_conflict_do_update(
            index_elements=[ScreenTimeDay.user_id, ScreenTimeDay.day],
            set_={
                "minutes": func.max(ScreenTimeDay.minutes, statement.excluded.minutes)
                if dialect == "sqlite"
                else func.greatest(ScreenTimeDay.minutes, statement.excluded.minutes),
                "updated_at": statement.excluded.updated_at,
            },
        )
    )
    db.commit()


class ExtensionVault(BaseModel):
    """The account's encrypted vault for autofill. Ciphertext only: the extension
    decrypts it locally with the master password, which never leaves the browser."""

    user_id: uuid.UUID
    kdf: dict[str, Any]
    wrapped_key: str
    data: str
    version: int


VAULT_READ_LIMIT = RateLimit("extension-vault", max_requests=120, window_seconds=3600)


@router.get("/vault", response_model=ExtensionVault)
def extension_vault(installation: CurrentInstallation, db: Db) -> ExtensionVault:
    if installation.user_id is None:
        raise ApiError(
            403,
            "not_linked",
            "Link this browser to your Qalaa account to use your passwords here.",
        )
    rate_limit.enforce(VAULT_READ_LIMIT, f"installation:{installation.id}")
    vault = db.get(Vault, installation.user_id)
    if vault is None:
        raise ApiError(404, "vault_not_found", "You have not created a password vault yet.")
    return ExtensionVault(
        user_id=installation.user_id,
        kdf=vault.kdf,
        wrapped_key=vault.wrapped_key,
        data=vault.data,
        version=vault.version,
    )


@router.post("/check-url", response_model=QuickVerdict)
def check_url(body: CheckUrlRequest, installation: CurrentInstallation, db: Db) -> QuickVerdict:
    """Nothing about the request is stored: checking a site leaves no record."""
    rate_limit.enforce(CHECK_LIMIT, f"install:{installation.id}")
    # Most checks repeat (popular sites), so answers are shared briefly between
    # browsers. The key is a digest of the address, never the address itself.
    cache = get_cache()
    generation = cache.generation()
    key = f"qc:{generation}:{body.mode}:{token_digest(body.url)}"
    if generation >= 0 and (cached := cache.get(key)):
        return QuickVerdict.model_validate_json(cached)
    verdict = _to_verdict(quick_check_url(db, body.url, host_only=body.mode == "host"))
    if generation >= 0:
        cache.set(key, verdict.model_dump_json(), min(verdict.cache_seconds, QUICK_CACHE_SECONDS))
    return verdict


@router.post("/check-download", response_model=QuickVerdict)
def check_download(
    body: CheckDownloadRequest, installation: CurrentInstallation, db: Db
) -> QuickVerdict:
    rate_limit.enforce(CHECK_LIMIT, f"install:{installation.id}")
    return _to_verdict(quick_check_download(db, body.url, body.filename))


@router.get("/blocklist", response_model=Blocklist)
def blocklist(installation: CurrentInstallation, db: Db) -> Blocklist:
    """Most recently seen malicious domains, for blocking before a page loads.
    The extension downloads the whole list, so nothing about browsing is sent."""
    rate_limit.enforce(BLOCKLIST_LIMIT, f"install:{installation.id}")
    return build_blocklist(db)


def build_blocklist(
    db: Session, *, url_sources: tuple[str, ...] = (), max_urls: int = 0
) -> Blocklist:
    """Recent malicious domains, and optionally exact malicious URLs (phishing
    pages on shared hosts), from feeds that are currently fresh."""
    sources = fresh_sources(db, _BLOCKLIST_SOURCES)
    source_ids = [source.id for source in sources]
    hosts: list[str] = []
    if source_ids:
        rows = db.scalars(
            select(ThreatIndicator.value)
            .where(ThreatIndicator.kind == "host", ThreatIndicator.source_id.in_(source_ids))
            .order_by(ThreatIndicator.last_seen_at.desc())
            .limit(BLOCKLIST_MAX_HOSTS * 2)
        )
        for value in rows:
            host = value.strip().lower().rstrip(".")
            if host and "." in host and host not in hosts and not host.replace(".", "").isdigit():
                hosts.append(host)
            if len(hosts) >= BLOCKLIST_MAX_HOSTS:
                break
    urls: list[str] = []
    url_feeds = fresh_sources(db, url_sources) if url_sources and max_urls else []
    if url_feeds:
        urls = sorted(
            set(
                db.scalars(
                    select(ThreatIndicator.value)
                    .where(
                        ThreatIndicator.kind == "url",
                        ThreatIndicator.source_id.in_([f.id for f in url_feeds]),
                    )
                    .order_by(ThreatIndicator.last_seen_at.desc())
                    .limit(max_urls)
                )
            )
        )
    every = [*sources, *url_feeds]
    newest = max((s.last_success_at for s in every if s.last_success_at), default=None)
    return Blocklist(
        version=f"{len(hosts)}-{len(urls)}-{newest.isoformat() if newest else 'none'}",
        generated_at=utcnow(),
        hosts=sorted(hosts),
        urls=urls,
        sources=sorted({source.name for source in every}),
    )


@router.get("/url-rules")
def url_rules(installation: CurrentInstallation) -> dict[str, Any]:
    """The address heuristics (brands, look-alike letters, shorteners), so the
    extension can run them locally. The same file the server uses."""
    rate_limit.enforce(RULES_LIMIT, f"install:{installation.id}")
    return RULES


@router.get("/threat-prefixes", response_model=ThreatPrefixes)
def threat_prefixes(installation: CurrentInstallation, db: Db) -> ThreatPrefixes:
    """Every listed address and domain as a 4-byte hash prefix. Downloading the
    whole list sends nothing about browsing."""
    rate_limit.enforce(PREFIX_LIMIT, f"install:{installation.id}")
    return build_threat_prefixes(db)


@router.post("/threat-hashes", response_model=ThreatHashes)
def threat_hashes(body: ThreatHashQuery, installation: CurrentInstallation, db: Db) -> ThreatHashes:
    """Full hashes for a few prefixes. Many addresses share each prefix, so the
    server can't tell which one was visited; the extension compares the full
    hashes itself. Nothing about the request is stored or logged."""
    rate_limit.enforce(HASH_LIMIT, f"install:{installation.id}")
    return lookup_hashes(db, body.prefixes)


@router.post("/assistant", response_model=AssistantReply)
def assistant(body: AssistantQuestion, installation: CurrentInstallation) -> AssistantReply:
    """The on-screen assistant's questions. Only a summary of the site is sent here,
    never page text, form values or cookie values."""
    rate_limit.enforce(ASSISTANT_LIMIT, f"install:{installation.id}")
    try:
        result = assistant_answer(
            body.question,
            body.context.model_dump(),
            "Arabic" if body.language == "ar" else "English",
        )
    except AssistantUnavailableError as exc:
        raise ApiError(503, "assistant_unavailable", str(exc)) from exc
    return AssistantReply(answer=result.text, model=result.model)


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
def create_link_code(user: SessionUser, db: Db) -> LinkCodeOut:
    code = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))
    expires_at = utcnow() + LINK_CODE_LIFETIME
    db.add(
        ExtensionLinkCode(code_digest=token_digest(code), user_id=user.id, expires_at=expires_at)
    )
    db.commit()
    return LinkCodeOut(code=f"{code[:4]}-{code[4:]}", expires_at=expires_at)


@router.get("/installations", response_model=list[InstallationOut])
def list_installations(user: SessionUser, db: Db) -> list[ExtensionInstallation]:
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
def revoke_installation(installation_id: uuid.UUID, user: SessionUser, db: Db) -> None:
    installation = db.get(ExtensionInstallation, installation_id)
    if installation is None or installation.user_id != user.id:
        raise ApiError(404, "installation_not_found", "This extension is not linked to you.")
    installation.revoked_at = utcnow()
    db.commit()


@router.get("/events", response_model=list[ExtensionEventOut])
def list_events(user: SessionUser, db: Db) -> list[ExtensionEvent]:
    return list(
        db.scalars(
            select(ExtensionEvent)
            .where(ExtensionEvent.user_id == user.id)
            .order_by(ExtensionEvent.created_at.desc())
            .limit(50)
        )
    )


@router.delete("/events", status_code=204)
def clear_events(user: SessionUser, db: Db) -> None:
    for event in db.scalars(select(ExtensionEvent).where(ExtensionEvent.user_id == user.id)):
        db.delete(event)
    db.commit()
