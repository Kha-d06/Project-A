"""Threat-list hash prefixes, for lookups that never reveal the address.

Clients (the browser extension, the Thunderbird add-on, the desktop mail
scanner) download the first 4 bytes of the SHA-256 of every listed address and
domain, compare locally, and only on a prefix match ask for the full hashes
that share it (mixed with random prefixes from the list). The same scheme as
the Safe Browsing Update API, with Qalaa's own feeds. Nothing about either
request is stored, and the routes stay out of the access log
(app/core/private_paths.py).
"""

import base64

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.intel.feeds import COMMUNITY, THREATFOX, URLHAUS
from app.intel.lookup import fresh_sources
from app.models import ThreatIndicator, ThreatSource
from app.models.base import utcnow
from app.schemas.extension import ThreatHash, ThreatHashes, ThreatPrefixes

# Feeds whose freshness decides whether a miss means anything.
PREFIX_SOURCES = (URLHAUS, THREATFOX, COMMUNITY)
# 4 bytes each: 250,000 prefixes is about 1.3 MB of base64.
PREFIX_MAX = 250_000
MAX_MATCHES = 500


def build_threat_prefixes(db: Session) -> ThreatPrefixes:
    """Like the server's own quick check, every stored address and domain counts
    (a listing is evidence even when its feed is behind); whether a miss means
    anything is told by the fresh feeds named in "sources"."""
    feeds = fresh_sources(db, PREFIX_SOURCES)
    prefixes: set[bytes] = set()
    rows = db.scalars(
        select(ThreatIndicator.value_digest)
        .where(ThreatIndicator.kind.in_(("url", "host")))
        .order_by(ThreatIndicator.last_seen_at.desc())
        .limit(PREFIX_MAX * 2)
    )
    for digest in rows:
        prefixes.add(bytes.fromhex(digest[:8]))
        if len(prefixes) >= PREFIX_MAX:
            break
    ordered = sorted(prefixes)
    newest = max((s.last_success_at for s in feeds if s.last_success_at), default=None)
    return ThreatPrefixes(
        version=f"{len(ordered)}-{newest.isoformat() if newest else 'none'}",
        generated_at=utcnow(),
        prefixes=base64.b64encode(b"".join(ordered)).decode(),
        count=len(ordered),
        sources=sorted(source.name for source in feeds),
    )


def lookup_hashes(db: Session, prefixes: list[str]) -> ThreatHashes:
    """Every listed address or domain whose digest starts with one of the prefixes."""
    # A range per prefix ("abcd1234" up to "abcd1234g"), which the digest index serves.
    conditions = [
        (ThreatIndicator.value_digest >= prefix) & (ThreatIndicator.value_digest < prefix + "g")
        for prefix in prefixes
    ]
    rows = db.execute(
        select(
            ThreatIndicator.value_digest,
            ThreatIndicator.kind,
            ThreatSource.key,
            ThreatSource.name,
            ThreatIndicator.threat,
        )
        .join(ThreatSource)
        .where(ThreatIndicator.kind.in_(("url", "host")), or_(*conditions))
        .limit(MAX_MATCHES)
    ).all()
    seen: set[tuple[str, str, str]] = set()
    matches: list[ThreatHash] = []
    for digest, kind, source_key, source_name, threat in rows:
        key = (digest, kind, source_key)
        if key not in seen:
            seen.add(key)
            matches.append(
                ThreatHash(
                    digest=digest,
                    kind=kind,
                    source=source_key,
                    source_name=source_name,
                    threat=threat,
                )
            )
    return ThreatHashes(matches=matches)
