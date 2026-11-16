"""Public threat-intelligence lookups. Read-only, no account needed."""

import ipaddress
import re
from datetime import timedelta

from fastapi import APIRouter, Request
from sqlalchemy import select

from app.analyzers.urls import InvalidUrlError, parse_url
from app.api.deps import Db
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, client_address
from app.intel.feeds import COMMUNITY, MALWAREBAZAAR, THREATFOX, URLHAUS
from app.intel.lookup import IndicatorMatch, find_by_host, find_indicators
from app.models import ThreatIndicator, ThreatSource
from app.models.base import utcnow
from app.schemas.intel import HashList, IndicatorOut, LookupResult, SourceFreshness

router = APIRouter(prefix="/intelligence", tags=["Threat intelligence"])

LOOKUP_LIMIT = RateLimit("intel-lookup", max_requests=120, window_seconds=3600)
HASH_LIST_LIMIT = RateLimit("intel-hash-list", max_requests=12, window_seconds=3600)
HASH_LIST_MAX = 200_000
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_OTHER_HASHES = {32: "MD5", 40: "SHA-1"}
NOT_A_GUARANTEE = (
    "Not being listed is not a guarantee: these sources only contain what has been "
    "reported. New threats appear here hours or days after they start."
)


def _sources(db: Db, keys: tuple[str, ...]) -> list[SourceFreshness]:
    cutoff = utcnow() - timedelta(hours=get_settings().feed_stale_after_hours)
    return [
        SourceFreshness(
            name=source.name,
            indicators=source.indicator_count,
            last_updated=source.last_success_at,
            fresh=bool(source.last_success_at and source.last_success_at >= cutoff),
        )
        for source in db.scalars(select(ThreatSource).where(ThreatSource.key.in_(keys)))
    ]


def _result(
    query: str,
    kind: str,
    matches: list[IndicatorMatch],
    sources: list[SourceFreshness],
) -> LookupResult:
    feed_matches = [m for m in matches if m.source_key != COMMUNITY]
    if feed_matches:
        verdict = "listed"
    elif matches:
        verdict = "community_verified"
    else:
        primary_fresh = any(
            s.fresh and not s.name.startswith("SENTINEL community") for s in sources
        )
        verdict = "not_listed" if primary_fresh else "unavailable"
    notes = [NOT_A_GUARANTEE] if verdict in ("not_listed", "community_verified") else []
    if verdict == "unavailable":
        notes.append(
            "The main threat feed is not up to date on this server, so a miss means nothing."
        )
    if any(m.source_key == COMMUNITY for m in matches):
        notes.append("Community entries come from user reports confirmed by a SENTINEL moderator.")
    return LookupResult(
        query=query,
        kind=kind,
        verdict=verdict,
        indicators=[
            IndicatorOut(
                source=m.source_name,
                kind=m.kind,
                value=m.value,
                threat=m.threat,
                tags=m.tags,
                first_seen=m.first_seen_at,
                last_seen=m.last_seen_at,
                reference=m.reference_url,
            )
            for m in matches
        ],
        sources=sources,
        notes=notes,
    )


@router.get("/domain/{domain}", response_model=LookupResult)
def lookup_domain(domain: str, request: Request, db: Db) -> LookupResult:
    rate_limit.enforce(LOOKUP_LIMIT, client_address(request))
    try:
        host = parse_url(f"http://{domain.strip()}/").host
    except InvalidUrlError as exc:
        raise ApiError(422, "invalid_domain", "Enter a domain name such as example.com.") from exc
    return _result(
        host,
        "domain",
        find_by_host(db, host),
        _sources(db, (URLHAUS, THREATFOX, COMMUNITY)),
    )


@router.get("/ip/{ip}", response_model=LookupResult)
def lookup_ip(ip: str, request: Request, db: Db) -> LookupResult:
    rate_limit.enforce(LOOKUP_LIMIT, client_address(request))
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError as exc:
        raise ApiError(422, "invalid_ip", "Enter an IPv4 or IPv6 address.") from exc
    if not address.is_global:
        raise ApiError(422, "private_ip", "Private and reserved addresses are not looked up.")
    query = str(address)
    return _result(
        query,
        "ip",
        find_by_host(db, query),
        _sources(db, (URLHAUS, THREATFOX, COMMUNITY)),
    )


@router.get("/hash/{file_hash}", response_model=LookupResult)
def lookup_hash(file_hash: str, request: Request, db: Db) -> LookupResult:
    rate_limit.enforce(LOOKUP_LIMIT, client_address(request))
    value = file_hash.strip().lower()
    if not _SHA256.match(value):
        other = _OTHER_HASHES.get(len(value))
        message = (
            f"{other} fingerprints are not supported; use the file's SHA-256."
            if other
            else "Enter a SHA-256 fingerprint (64 hexadecimal characters)."
        )
        raise ApiError(422, "invalid_hash", message)
    matches = find_indicators(db, "sha256", value)
    return _result(value, "hash", matches, _sources(db, (MALWAREBAZAAR, THREATFOX)))


@router.get("/hash-list", response_model=HashList)
def hash_list(request: Request, db: Db) -> HashList:
    """Recent known-malware SHA-256 fingerprints, for offline scanners such as
    SENTINEL Desktop. The whole list is downloaded, so nothing about the files on
    anyone's computer is sent."""
    rate_limit.enforce(HASH_LIST_LIMIT, client_address(request))
    sources = [
        source
        for source in db.scalars(
            select(ThreatSource).where(ThreatSource.key.in_((MALWAREBAZAAR, THREATFOX)))
        )
        if source.last_success_at
    ]
    values = (
        list(
            db.scalars(
                select(ThreatIndicator.value)
                .where(
                    ThreatIndicator.kind == "sha256",
                    ThreatIndicator.source_id.in_([source.id for source in sources]),
                )
                .order_by(ThreatIndicator.last_seen_at.desc())
                .limit(HASH_LIST_MAX)
            )
        )
        if sources
        else []
    )
    hashes = sorted({value for value in values if _SHA256.match(value)})
    newest = max(
        (source.last_success_at for source in sources if source.last_success_at), default=None
    )
    return HashList(
        version=f"{len(hashes)}-{newest.isoformat() if newest else 'none'}",
        generated_at=utcnow(),
        sources=[source.name for source in sources],
        sha256=hashes,
    )


@router.get("/sources", response_model=list[SourceFreshness])
def list_sources(db: Db) -> list[SourceFreshness]:
    return _sources(db, (URLHAUS, THREATFOX, MALWAREBAZAAR, COMMUNITY))
