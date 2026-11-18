import io
import json
import logging
import zipfile

import httpx
import pytest
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.intel import feeds
from app.intel.feeds import (
    MALWAREBAZAAR,
    MALWAREBAZAAR_API,
    URLHAUS,
    FeedNotConfiguredError,
    abusech_url,
    parse_malwarebazaar,
    sync_feed,
    unwrap,
)

KEY = "k3y-0f-abuse-ch-1234567890"
SHA = "a" * 64


def feed(key: str) -> feeds.Feed:
    return next(f for f in feeds.FEEDS if f.key == key)


def test_exports_need_a_key_and_carry_it_in_the_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "urlhaus_auth_key", None)
    with pytest.raises(FeedNotConfiguredError, match="auth.abuse.ch"):
        feed(URLHAUS).url()
    monkeypatch.setattr(get_settings(), "urlhaus_auth_key", KEY)
    assert feed(URLHAUS).url() == f"https://urlhaus-api.abuse.ch/v2/files/exports/{KEY}/recent.csv"
    assert "threatfox-api.abuse.ch/v2/files/exports/" in feed(feeds.THREATFOX).url()
    assert feed(MALWAREBAZAAR).url() == MALWAREBAZAAR_API
    # Overrides win; a key placeholder is filled in.
    assert (
        abusech_url("https://mirror.example/feed.csv", feeds.URLHAUS_EXPORT)
        == "https://mirror.example/feed.csv"
    )
    assert abusech_url("https://mirror.example/{auth_key}/f.csv", feeds.URLHAUS_EXPORT).endswith(
        f"/{KEY}/f.csv"
    )


def test_missing_key_is_reported_plainly(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "urlhaus_auth_key", None)
    source = sync_feed(db, feed(URLHAUS), fetch=lambda url: pytest.fail("must not download"))
    assert source.last_error is not None and "SENTINEL_URLHAUS_AUTH_KEY" in source.last_error
    source = sync_feed(db, feed(MALWAREBAZAAR))  # the real downloader refuses before any request
    assert "Auth-Key" in (source.last_error or "")


def test_the_key_never_reaches_errors_or_logs(
    db: Session, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(get_settings(), "urlhaus_auth_key", KEY)

    def failing(url: str) -> str:
        logging.getLogger("httpx").info("HTTP Request: GET %s", url)
        raise httpx.HTTPStatusError(
            f"Client error '404 Not Found' for url '{url}'",
            request=httpx.Request("GET", url),
            response=httpx.Response(404),
        )

    with caplog.at_level(logging.INFO):
        source = sync_feed(db, feed(URLHAUS), fetch=failing)
    assert source.last_error and "404" in source.last_error and KEY not in source.last_error
    assert KEY not in caplog.text and "***" in caplog.text


def test_malwarebazaar_api_answers_are_parsed() -> None:
    payload = {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": SHA,
                "signature": "AgentTesla",
                "tags": ["exe", "stealer"],
                "first_seen": "2026-11-18 10:00:00",
            },
            {"sha256_hash": "not-a-hash"},
        ],
    }
    [indicator] = list(parse_malwarebazaar(json.dumps(payload)))
    assert (indicator.kind, indicator.value, indicator.threat) == ("sha256", SHA, "AgentTesla")
    assert indicator.reference_url == f"https://bazaar.abuse.ch/sample/{SHA}/"
    assert list(parse_malwarebazaar(json.dumps({"query_status": "no_results"}))) == []
    with pytest.raises(ValueError, match="unknown_auth_key"):
        list(parse_malwarebazaar(json.dumps({"query_status": "unknown_auth_key"})))
    assert [i.value for i in parse_malwarebazaar(f"# header\n{SHA}\n")] == [SHA]


def test_zipped_exports_are_unwrapped() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("recent.csv", "# comment\nrow\n")
    assert unwrap(buffer.getvalue()) == b"# comment\nrow\n"
    assert unwrap(b"plain text") == b"plain text"


def test_keyed_sync_stores_indicators(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "urlhaus_auth_key", KEY)
    payload = json.dumps(
        {"query_status": "ok", "data": [{"sha256_hash": SHA, "signature": "Formbook"}]}
    )
    source = sync_feed(db, feed(MALWAREBAZAAR), fetch=lambda url: payload)
    assert source.last_error is None and source.indicator_count == 1
