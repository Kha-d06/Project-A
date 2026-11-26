"""Support for checking email on the device.

Email never comes to the server. Clients (the desktop mailbox scanner and the
Thunderbird add-on) download the public rule pack once a day and run every
wording, sender and header check locally. The only thing they send is the bare
links found in a message (scheme, host and path; no query string or fragment),
for a reputation check against the threat feeds. Nothing is stored and no
account is needed.
"""

import hashlib
import json
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Request, Response

from app.analyzers.message_patterns import RULES
from app.analyzers.url_heuristics import (
    BRAND_DOMAINS,
    URL_SHORTENERS,
    analyze_url_text,
    brand_name,
)
from app.analyzers.url_heuristics import (
    RULES as URL_RULES,
)
from app.analyzers.url_scan import indicator_findings
from app.analyzers.urls import InvalidUrlError, parse_url
from app.api.deps import Db
from app.core import rate_limit
from app.core.cache import get_cache
from app.core.rate_limit import RateLimit, client_address
from app.intel.feeds import THREATFOX, URLHAUS
from app.intel.lookup import fresh_sources
from app.intel.prefixes import build_threat_prefixes, lookup_hashes
from app.schemas.email import (
    BrandOut,
    LinkCheckOut,
    LinkCheckRequest,
    LinkFinding,
    LinkResult,
    RuleOut,
    RulePack,
)
from app.schemas.extension import ThreatHashes, ThreatHashQuery, ThreatPrefixes

router = APIRouter(prefix="/email", tags=["Scanning"])

# Kept for add-on versions before hash-prefix lookups; current clients don't call it.
LINKS_LIMIT = RateLimit("email-links", max_requests=600, window_seconds=3600)
# Hash-prefix lookups for mail clients (no account: the add-on and the desktop
# scanner check mail before or without linking). Per address, never stored.
PREFIX_LIMIT = RateLimit("email-prefixes", max_requests=30, window_seconds=3600)
HASH_LIMIT = RateLimit("email-hashes", max_requests=1200, window_seconds=3600)
PREFIX_CACHE_SECONDS = 600
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@lru_cache(maxsize=1)
def rule_pack() -> RulePack:
    rules = [
        RuleOut(
            category=rule.category,
            severity=rule.severity,
            title=rule.title,
            explanation=rule.explanation,
            title_ar=rule.title_ar or rule.title,
            explanation_ar=rule.explanation_ar or rule.explanation,
            patterns=[pattern.pattern for pattern in rule.patterns],
        )
        for rule in RULES
    ]
    brands = {
        brand: BrandOut(name=brand_name(brand), domains=sorted(domains))
        for brand, domains in sorted(BRAND_DOMAINS.items())
    }
    body = {
        "rules": [r.model_dump() for r in rules],
        "brands": {k: v.model_dump() for k, v in brands.items()},
        "url_rules": URL_RULES,
    }
    version = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]
    return RulePack(
        version=version,
        rules=rules,
        brands=brands,
        shorteners=sorted(URL_SHORTENERS),
        url_rules=URL_RULES,
    )


@router.get("/rules", response_model=RulePack)
def get_rules(response: Response) -> RulePack:
    """The public rule pack: wording patterns (in JavaScript-compatible syntax,
    matched case-insensitively), brand domains and link shorteners."""
    response.headers["Cache-Control"] = "public, max-age=86400"
    return rule_pack()


def bare(url: str) -> str:
    """Scheme, host and path only."""
    parts = urlsplit(url.strip())
    return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, "", ""))


@router.post("/links", response_model=LinkCheckOut)
def check_links(body: LinkCheckRequest, request: Request, db: Db) -> LinkCheckOut:
    rate_limit.enforce(LINKS_LIMIT, f"ip:{client_address(request)}")
    results: list[LinkResult] = []
    seen: set[str] = set()
    for raw in body.urls:
        try:
            url = parse_url(bare(raw))
        except (InvalidUrlError, ValueError):
            continue
        if url.normalized in seen:
            continue
        seen.add(url.normalized)
        findings = analyze_url_text(url) + indicator_findings(db, url)
        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 5))
        results.append(
            LinkResult(
                url=url.normalized,
                host=url.host,
                findings=[
                    LinkFinding(severity=f.severity, title=f.title, explanation=f.explanation)
                    for f in findings
                ],
            )
        )
    available = bool(fresh_sources(db, (URLHAUS, THREATFOX)))
    return LinkCheckOut(results=results, feed_available=available)


@router.get("/threat-prefixes", response_model=ThreatPrefixes)
def email_threat_prefixes(request: Request, response: Response, db: Db) -> ThreatPrefixes:
    """Every listed address and domain as a 4-byte SHA-256 prefix. Downloading the
    whole list sends nothing about any message."""
    rate_limit.enforce(PREFIX_LIMIT, f"ip:{client_address(request)}")
    response.headers["Cache-Control"] = f"public, max-age={PREFIX_CACHE_SECONDS}"
    cache = get_cache()
    generation = cache.generation()
    key = f"email-prefixes:{generation}"
    if generation >= 0 and (cached := cache.get(key)):
        return ThreatPrefixes.model_validate_json(cached)
    listing = build_threat_prefixes(db)
    if generation >= 0:
        cache.set(key, listing.model_dump_json(), PREFIX_CACHE_SECONDS)
    return listing


@router.post("/threat-hashes", response_model=ThreatHashes)
def email_threat_hashes(body: ThreatHashQuery, request: Request, db: Db) -> ThreatHashes:
    """Full hashes for up to 32 prefixes; the client compares them itself. The
    prefixes are shared by many addresses, and include random ones, so they
    don't say which link was in the message. Nothing is stored."""
    rate_limit.enforce(HASH_LIMIT, f"ip:{client_address(request)}")
    return lookup_hashes(db, body.prefixes)
