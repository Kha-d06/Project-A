"""Import of public threat feeds into the local indicator store.

Both feeds are published by abuse.ch under CC0. Looking indicators up locally
means a scan does not disclose the user's URL or file hash to a third party.
"""

import csv
import io
import logging
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import batched
from urllib.parse import urlsplit

import httpx
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.orm import Session

from app.analyzers.urls import InvalidUrlError, indicator_digest, parse_url
from app.core.config import get_settings
from app.models import ThreatIndicator, ThreatSource
from app.models.base import utcnow

logger = logging.getLogger(__name__)

COMMUNITY = "community"
URLHAUS = "urlhaus"
MALWAREBAZAAR = "malwarebazaar"
THREATFOX = "threatfox"
# Development-only indicators on reserved domains; see app.cli load-test-fixtures.
TEST_FIXTURES = "test-fixtures"
MAX_FEED_BYTES = 80 * 1024 * 1024
_BATCH_SIZE = 500
_SHA256_LENGTH = 64


@dataclass(frozen=True)
class FeedIndicator:
    kind: str
    value: str
    threat: str | None = None
    tags: str | None = None
    reference_url: str | None = None
    first_seen_at: datetime | None = None


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def parse_urlhaus_csv(text: str) -> Iterator[FeedIndicator]:
    """Rows: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter."""
    rows = csv.reader(line for line in io.StringIO(text) if line.strip() and line[0] != "#")
    seen_hosts: set[str] = set()
    for row in rows:
        if len(row) < 8:
            continue
        try:
            parsed = parse_url(row[2])
        except InvalidUrlError:
            continue
        first_seen = _parse_timestamp(row[1])
        tags = None if row[6] in ("", "None") else row[6][:300]
        yield FeedIndicator("url", parsed.normalized, row[5] or None, tags, row[7], first_seen)
        if parsed.host not in seen_hosts:
            seen_hosts.add(parsed.host)
            yield FeedIndicator("host", parsed.host, row[5] or None, None, None, first_seen)


def parse_threatfox_csv(text: str) -> Iterator[FeedIndicator]:
    """ThreatFox recent IOCs. Columns: first_seen_utc, ioc_id, ioc_value, ioc_type,
    threat_type, fk_malware, malware_alias, malware_printable, last_seen_utc,
    confidence_level, reference, tags, anonymous, reporter."""
    # The export separates fields with ", " (comma and space).
    rows = csv.reader(
        (line for line in io.StringIO(text) if line.strip() and line[0] != "#"),
        skipinitialspace=True,
    )
    for row in rows:
        if len(row) < 12:
            continue
        value, ioc_type = row[2].strip(), row[3].strip()
        threat = row[7].strip() or row[4].strip() or None
        tags = row[11].strip()[:300] or None
        first_seen = _parse_timestamp(row[0])
        reference = f"https://threatfox.abuse.ch/ioc/{row[1].strip()}/"
        if ioc_type == "url":
            try:
                parsed = parse_url(value)
            except InvalidUrlError:
                continue
            yield FeedIndicator("url", parsed.normalized, threat, tags, reference, first_seen)
        elif ioc_type in ("domain", "ip:port"):
            host = value.rsplit(":", 1)[0] if ioc_type == "ip:port" else value
            yield FeedIndicator(
                "host", host.lower().strip("[]"), threat, tags, reference, first_seen
            )
        elif ioc_type == "sha256_hash" and len(value) == _SHA256_LENGTH:
            yield FeedIndicator("sha256", value.lower(), threat, tags, reference, first_seen)


def parse_sha256_list(text: str) -> Iterator[FeedIndicator]:
    for line in text.splitlines():
        value = line.strip().lower()
        if len(value) == _SHA256_LENGTH and all(char in "0123456789abcdef" for char in value):
            yield FeedIndicator("sha256", value, "malware")


@dataclass(frozen=True)
class Feed:
    key: str
    name: str
    url: Callable[[], str]
    parse: Callable[[str], Iterable[FeedIndicator]]


FEEDS = (
    Feed(URLHAUS, "URLhaus (abuse.ch)", lambda: get_settings().urlhaus_feed_url, parse_urlhaus_csv),
    Feed(
        THREATFOX,
        "ThreatFox (abuse.ch)",
        lambda: get_settings().threatfox_feed_url,
        parse_threatfox_csv,
    ),
    Feed(
        MALWAREBAZAAR,
        "MalwareBazaar (abuse.ch)",
        lambda: get_settings().malwarebazaar_feed_url,
        parse_sha256_list,
    ),
)


def download_feed(url: str) -> str:
    # abuse.ch may require an Auth-Key for downloads; send it when one is configured.
    key = get_settings().urlhaus_auth_key
    headers = {"Auth-Key": key} if key else {}
    with httpx.stream("GET", url, timeout=60, follow_redirects=True, headers=headers) as response:
        response.raise_for_status()
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > MAX_FEED_BYTES:
                raise ValueError("Feed is larger than the configured safety limit")
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def get_or_create_source(db: Session, key: str, name: str) -> ThreatSource:
    source = db.scalar(select(ThreatSource).where(ThreatSource.key == key))
    if source is None:
        source = ThreatSource(key=key, name=name)
        db.add(source)
        db.flush()
    return source


def indicator_host(kind: str, value: str) -> str | None:
    if kind == "host":
        return value[:255]
    if kind == "url":
        host = urlsplit(value).hostname
        return host[:255] if host else None
    return None


def store_indicators(db: Session, source: ThreatSource, indicators: Iterable[FeedIndicator]) -> int:
    """Insert new indicators and refresh last-seen on ones already known."""
    now = utcnow()
    known_rows = db.execute(
        select(ThreatIndicator.kind, ThreatIndicator.value_digest).where(
            ThreatIndicator.source_id == source.id
        )
    )
    known = {(kind, digest) for kind, digest in known_rows}
    seen: set[tuple[str, str]] = set()
    new_rows = []
    for indicator in indicators:
        identity = (indicator.kind, indicator_digest(indicator.value))
        if identity in seen:
            continue
        seen.add(identity)
        if identity not in known:
            new_rows.append(
                {
                    "source_id": source.id,
                    "kind": indicator.kind,
                    "value": indicator.value,
                    "value_digest": identity[1],
                    "host": indicator_host(indicator.kind, indicator.value),
                    "threat": indicator.threat,
                    "tags": indicator.tags,
                    "reference_url": indicator.reference_url,
                    "first_seen_at": indicator.first_seen_at,
                    "last_seen_at": now,
                }
            )

    for batch in batched(new_rows, _BATCH_SIZE):
        db.execute(insert(ThreatIndicator), list(batch))
    for digests in batched([digest for _, digest in seen & known], _BATCH_SIZE):
        db.execute(
            update(ThreatIndicator)
            .where(
                ThreatIndicator.source_id == source.id, ThreatIndicator.value_digest.in_(digests)
            )
            .values(last_seen_at=now)
        )
    return len(seen)


def remove_stale_indicators(db: Session, source: ThreatSource) -> None:
    cutoff = utcnow() - timedelta(days=get_settings().indicator_retention_days)
    db.execute(
        delete(ThreatIndicator).where(
            ThreatIndicator.source_id == source.id, ThreatIndicator.last_seen_at < cutoff
        )
    )


def sync_feed(db: Session, feed: Feed, fetch: Callable[[str], str] = download_feed) -> ThreatSource:
    source = get_or_create_source(db, feed.key, feed.name)
    source.name = feed.name
    source.last_attempt_at = utcnow()
    db.commit()
    try:
        store_indicators(db, source, feed.parse(fetch(feed.url())))
        remove_stale_indicators(db, source)
        source.indicator_count = (
            db.scalar(
                select(func.count())
                .select_from(ThreatIndicator)
                .where(ThreatIndicator.source_id == source.id)
            )
            or 0
        )
        source.last_success_at = utcnow()
        source.last_error = None
        db.commit()
    except (httpx.HTTPError, ValueError) as exc:
        db.rollback()
        logger.warning("Feed %s failed to sync: %s", feed.key, exc)
        source.last_error = f"{type(exc).__name__}: {exc}"[:500]
        db.commit()
    return source


def sync_all_feeds(db: Session) -> list[ThreatSource]:
    return [sync_feed(db, feed) for feed in FEEDS]
