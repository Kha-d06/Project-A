"""Import of public threat feeds into the local indicator store.

Both feeds are published by abuse.ch under CC0. Looking indicators up locally
means a scan does not disclose the user's URL or file hash to a third party.
"""

import csv
import io
import json
import logging
import zipfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import batched
from urllib.parse import quote, urlsplit

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
OPENPHISH = "openphish"
# Development-only indicators on reserved domains; see app.cli load-test-fixtures.
TEST_FIXTURES = "test-fixtures"
MAX_FEED_BYTES = 80 * 1024 * 1024

# abuse.ch since October 2026: the key goes in the export path (exports) or in an
# Auth-Key header (the MalwareBazaar query API). The old keyless URLs answer 410 Gone.
URLHAUS_EXPORT = "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
THREATFOX_EXPORT = "https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"


class FeedNotConfiguredError(ValueError):
    """The feed needs a setting (an abuse.ch Auth-Key) that is not set."""


def _auth_key() -> str | None:
    return get_settings().urlhaus_auth_key or None


def redact(text: str) -> str:
    """Removes the abuse.ch key from text that may contain a URL (errors, logs)."""
    key = _auth_key()
    return text.replace(key, "***") if key else text


class _RedactAuthKey(logging.Filter):
    """httpx logs every request URL; exports carry the key in the URL."""

    def filter(self, record: logging.LogRecord) -> bool:
        key = _auth_key()
        if key:
            message = record.getMessage()
            if key in message:
                record.msg, record.args = message.replace(key, "***"), ()
        return True


for _name in ("httpx", "httpcore"):
    logging.getLogger(_name).addFilter(_RedactAuthKey())


def abusech_url(configured: str, template: str) -> str:
    """The configured override, or abuse.ch's keyed export address."""
    key = _auth_key()
    url = configured or template
    if "{auth_key}" in url:
        if not key:
            raise FeedNotConfiguredError(
                "abuse.ch needs a free Auth-Key for this feed: set SENTINEL_URLHAUS_AUTH_KEY "
                "(create one at https://auth.abuse.ch/)"
            )
        url = url.replace("{auth_key}", quote(key, safe=""))
    return url


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


def parse_malwarebazaar(text: str) -> Iterator[FeedIndicator]:
    """The MalwareBazaar query API (JSON: data[].sha256_hash), or a plain list of hashes."""
    if not text.lstrip().startswith("{"):
        yield from parse_sha256_list(text)
        return
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("MalwareBazaar answered with invalid JSON") from exc
    status = payload.get("query_status")
    if status not in ("ok", "no_results"):
        raise ValueError(f"MalwareBazaar refused the request: {status}")
    for item in payload.get("data") or []:
        value = str(item.get("sha256_hash", "")).strip().lower()
        if len(value) == _SHA256_LENGTH and all(char in "0123456789abcdef" for char in value):
            threat = item.get("signature") or "malware"
            tags = ", ".join(item.get("tags") or [])[:300] or None
            reference = f"https://bazaar.abuse.ch/sample/{value}/"
            first_seen = _parse_timestamp(item.get("first_seen") or "")
            yield FeedIndicator("sha256", value, str(threat)[:200], tags, reference, first_seen)


def parse_sha256_list(text: str) -> Iterator[FeedIndicator]:
    for line in text.splitlines():
        value = line.strip().lower()
        if len(value) == _SHA256_LENGTH and all(char in "0123456789abcdef" for char in value):
            yield FeedIndicator("sha256", value, "malware")


def parse_url_list(text: str) -> Iterator[FeedIndicator]:
    """One URL per line (OpenPhish community feed). Only exact URLs are stored, never
    their hosts: phishing pages often live on shared hosting (cloud storage, form
    builders), and listing the whole host would block legitimate sites."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parsed = parse_url(line)
        except InvalidUrlError:
            continue
        yield FeedIndicator("url", parsed.normalized, "phishing")


@dataclass(frozen=True)
class Feed:
    key: str
    name: str
    url: Callable[[], str]
    parse: Callable[[str], Iterable[FeedIndicator]]


FEEDS = (
    Feed(
        URLHAUS,
        "URLhaus (abuse.ch)",
        lambda: abusech_url(get_settings().urlhaus_feed_url, URLHAUS_EXPORT),
        parse_urlhaus_csv,
    ),
    Feed(
        THREATFOX,
        "ThreatFox (abuse.ch)",
        lambda: abusech_url(get_settings().threatfox_feed_url, THREATFOX_EXPORT),
        parse_threatfox_csv,
    ),
    Feed(
        OPENPHISH,
        "OpenPhish community feed",
        lambda: get_settings().openphish_feed_url,
        parse_url_list,
    ),
    Feed(
        MALWAREBAZAAR,
        "MalwareBazaar (abuse.ch)",
        lambda: get_settings().malwarebazaar_feed_url or MALWAREBAZAAR_API,
        parse_malwarebazaar,
    ),
)


def unwrap(data: bytes) -> bytes:
    """abuse.ch serves some exports zipped: return the first file inside, size-limited."""
    if not data.startswith(b"PK\x03\x04"):
        return data
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if not members:
            return b""
        if members[0].file_size > MAX_FEED_BYTES:
            raise ValueError("Feed is larger than the configured safety limit")
        with archive.open(members[0]) as member:
            return member.read(MAX_FEED_BYTES + 1)[:MAX_FEED_BYTES]


def download_feed(url: str) -> str:
    key = _auth_key()
    headers = {"Auth-Key": key} if key else {}
    if url == MALWAREBAZAAR_API:
        # The query API: the most recent samples (last hour's worth, refreshed each sync).
        if not key:
            raise FeedNotConfiguredError(
                "MalwareBazaar needs a free abuse.ch Auth-Key: set SENTINEL_URLHAUS_AUTH_KEY "
                "(create one at https://auth.abuse.ch/)"
            )
        query = {"query": "get_recent", "selector": "time"}
        response = httpx.post(url, data=query, headers=headers, timeout=60)
        response.raise_for_status()
        return response.text[:MAX_FEED_BYTES]
    with httpx.stream("GET", url, timeout=60, follow_redirects=True, headers=headers) as response:
        response.raise_for_status()
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > MAX_FEED_BYTES:
                raise ValueError("Feed is larger than the configured safety limit")
            chunks.append(chunk)
    return unwrap(b"".join(chunks)).decode("utf-8", errors="replace")


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
    from app.core.cache import threat_data_changed

    threat_data_changed(db)
    return len(seen)


def remove_stale_indicators(db: Session, source: ThreatSource) -> None:
    cutoff = utcnow() - timedelta(days=get_settings().indicator_retention_days)
    db.execute(
        delete(ThreatIndicator).where(
            ThreatIndicator.source_id == source.id, ThreatIndicator.last_seen_at < cutoff
        )
    )
    from app.core.cache import threat_data_changed

    threat_data_changed(db)


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
    except FeedNotConfiguredError as exc:
        db.rollback()
        logger.info("Feed %s skipped: %s", feed.key, exc)
        source.last_error = str(exc)[:500]
        db.commit()
    except (httpx.HTTPError, ValueError, zipfile.BadZipFile) as exc:
        db.rollback()
        message = redact(f"{type(exc).__name__}: {exc}")
        logger.warning("Feed %s failed to sync: %s", feed.key, message)
        source.last_error = message[:500]
        db.commit()
    return source


def sync_all_feeds(db: Session) -> list[ThreatSource]:
    return [sync_feed(db, feed) for feed in FEEDS]
