from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.intel.feeds import FEEDS, parse_sha256_list, parse_urlhaus_csv, sync_feed
from app.intel.lookup import find_indicators
from app.models import ThreatIndicator
from app.models.base import utcnow
from app.scans.service import ANONYMOUS_SCAN_RETENTION, purge_expired_data

URLHAUS_SAMPLE = """\
################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3001","2026-11-15 08:12:04","http://198.51.100.7/bins/arm7","online","2026-11-15 09:00:00","malware_download","elf,mirai","https://urlhaus.abuse.ch/url/3001/","reporter1"
"3002","2026-11-14 21:40:11","https://Files.Example.net/update.exe","offline","","malware_download","None","https://urlhaus.abuse.ch/url/3002/","reporter2"
"3003","2026-11-14 21:40:11","not a url","offline","","malware_download","None","https://urlhaus.abuse.ch/url/3003/","reporter2"
"""
URLHAUS_FEED = next(feed for feed in FEEDS if feed.key == "urlhaus")


def test_urlhaus_csv_is_parsed_into_url_and_host_indicators() -> None:
    indicators = list(parse_urlhaus_csv(URLHAUS_SAMPLE))
    urls = [i for i in indicators if i.kind == "url"]
    assert [i.value for i in urls] == [
        "http://198.51.100.7/bins/arm7",
        "https://files.example.net/update.exe",
    ]
    assert urls[0].tags == "elf,mirai"
    assert urls[1].tags is None
    assert urls[0].first_seen_at is not None and urls[0].first_seen_at.year == 2026
    assert {i.value for i in indicators if i.kind == "host"} == {
        "198.51.100.7",
        "files.example.net",
    }


def test_hash_list_ignores_comments_and_junk() -> None:
    text = "# header\n" + "A" * 64 + "\nnot-a-hash\n" + "b" * 63 + "\n"
    assert [i.value for i in parse_sha256_list(text)] == ["a" * 64]


def test_sync_is_idempotent_and_records_provenance(db: Session) -> None:
    first = sync_feed(db, URLHAUS_FEED, fetch=lambda url: URLHAUS_SAMPLE)
    assert first.indicator_count == 4
    assert first.last_error is None

    again = sync_feed(db, URLHAUS_FEED, fetch=lambda url: URLHAUS_SAMPLE)
    assert again.indicator_count == 4

    match = find_indicators(db, "url", "https://files.example.net/update.exe")[0]
    assert match.source_name == "URLhaus (abuse.ch)"
    assert match.reference_url == "https://urlhaus.abuse.ch/url/3002/"
    assert match.first_seen_at is not None


def test_failed_sync_keeps_existing_data_and_records_the_error(db: Session) -> None:
    sync_feed(db, URLHAUS_FEED, fetch=lambda url: URLHAUS_SAMPLE)

    def offline(url: str) -> str:
        raise httpx.ConnectError("no route to host")

    source = sync_feed(db, URLHAUS_FEED, fetch=offline)
    assert "ConnectError" in (source.last_error or "")
    assert source.indicator_count == 4
    assert source.last_success_at is not None


def test_indicators_no_longer_in_the_feed_expire(db: Session) -> None:
    sync_feed(db, URLHAUS_FEED, fetch=lambda url: URLHAUS_SAMPLE)
    too_old = utcnow() - timedelta(days=get_settings().indicator_retention_days + 1)
    db.query(ThreatIndicator).update({ThreatIndicator.last_seen_at: too_old})
    db.commit()

    only_first_row = "\n".join(URLHAUS_SAMPLE.splitlines()[:6]) + "\n"
    source = sync_feed(db, URLHAUS_FEED, fetch=lambda url: only_first_row)
    assert source.indicator_count == 2
    assert find_indicators(db, "url", "https://files.example.net/update.exe") == []


def test_provider_status_reflects_real_configuration(client: TestClient, db: Session) -> None:
    before = {p["key"]: p for p in client.get("/api/v1/system/providers").json()}
    assert before["urlhaus"]["status"] == "awaiting_first_sync"
    assert before["threatfox"]["status"] == "awaiting_first_sync"
    assert before["urlhaus_api"]["status"] == "not_configured"
    assert before["clamav"]["status"] == "not_configured"

    sync_feed(db, URLHAUS_FEED, fetch=lambda url: URLHAUS_SAMPLE)
    after = {p["key"]: p for p in client.get("/api/v1/system/providers").json()}
    assert after["urlhaus"]["status"] == "active"
    assert "4 indicators" in after["urlhaus"]["detail"]


def test_old_anonymous_scans_are_purged(client: TestClient, db: Session) -> None:
    from app.models import ScanJob

    scan = client.post(
        "/api/v1/scans/message", json={"content": "An ordinary message to scan."}
    ).json()
    job = db.query(ScanJob).one()
    job.created_at = utcnow() - ANONYMOUS_SCAN_RETENTION - timedelta(days=1)
    db.commit()

    purge_expired_data(db)
    assert client.get(f"/api/v1/scans/{scan['id']}").status_code == 404


def test_test_fixtures_detect_but_never_vouch_for_a_link(client: TestClient, db: Session) -> None:
    from app.cli import load_test_fixtures

    assert load_test_fixtures(db) == 0
    listed = client.post(
        "/api/v1/scans/url", json={"url": "http://malware.example.net/payload.exe"}
    ).json()
    assert listed["risk"] == "known_malicious"
    assert "not real threat data" in listed["findings"][0]["source"]

    # Fixtures alone are not a reputation source, so a clean link stays inconclusive.
    clean = client.post("/api/v1/scans/url", json={"url": "https://example.org/"}).json()
    assert clean["risk"] == "inconclusive"

    statuses = {p["key"]: p for p in client.get("/api/v1/system/providers").json()}
    assert "not real threat data" in statuses["test-fixtures"]["name"]


def test_test_fixtures_are_refused_in_production(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.cli import load_test_fixtures

    monkeypatch.setattr(get_settings(), "environment", "production")
    assert load_test_fixtures(db) == 1


def test_real_sync_restores_the_feed_name(db: Session) -> None:
    from app.intel.feeds import get_or_create_source

    get_or_create_source(db, "urlhaus", "Old name")
    db.commit()
    assert (
        sync_feed(db, URLHAUS_FEED, fetch=lambda url: URLHAUS_SAMPLE).name == "URLhaus (abuse.ch)"
    )


THREATFOX_SAMPLE = """\
################################################################
# ThreatFox IOCs: recent
################################################################
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter"
"2026-11-15 10:00:00", "1001", "http://drop.example.com/x.bin", "url", "payload_delivery", "win.agent", "", "Agent", "", "75", "", "exe", "0", "r1"
"2026-11-15 11:00:00", "1002", "c2.example.org", "domain", "botnet_cc", "win.rat", "", "Some RAT", "", "100", "", "rat", "0", "r2"
"2026-11-15 12:00:00", "1003", "45.33.32.156:443", "ip:port", "botnet_cc", "win.rat", "", "Some RAT", "", "100", "", "", "0", "r2"
"2026-11-15 13:00:00", "1004", "{sha}", "sha256_hash", "payload", "win.agent", "", "Agent", "", "100", "", "", "0", "r3"
""".replace("{sha}", "c" * 64)


def test_threatfox_csv_is_parsed(db: Session) -> None:
    from app.intel.feeds import parse_threatfox_csv

    indicators = {(i.kind, i.value): i for i in parse_threatfox_csv(THREATFOX_SAMPLE)}
    assert ("url", "http://drop.example.com/x.bin") in indicators
    assert ("host", "c2.example.org") in indicators
    assert ("host", "45.33.32.156") in indicators
    assert indicators[("sha256", "c" * 64)].threat == "Agent"
    assert (
        indicators[("host", "c2.example.org")].reference_url
        == "https://threatfox.abuse.ch/ioc/1002/"
    )


def test_threatfox_alone_can_back_a_link_check(client: TestClient, db: Session) -> None:
    feed = next(feed for feed in FEEDS if feed.key == "threatfox")
    sync_feed(db, feed, fetch=lambda url: THREATFOX_SAMPLE)
    listed = client.post("/api/v1/scans/url", json={"url": "http://drop.example.com/x.bin"}).json()
    assert listed["risk"] == "known_malicious"
    clean = client.post("/api/v1/scans/url", json={"url": "https://example.org/"}).json()
    assert clean["risk"] == "no_known_threat"
    lookup = client.get("/api/v1/intelligence/ip/45.33.32.156").json()
    assert lookup["verdict"] == "listed"


def test_feed_downloads_send_the_abusech_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.intel import feeds

    seen: dict[str, str] = {}

    class FakeStream:
        def __init__(self, *args: object, **kwargs: object) -> None:
            seen.update(kwargs.get("headers") or {})  # type: ignore[arg-type]

        def __enter__(self) -> "FakeStream":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def raise_for_status(self) -> None:
            return None

        def iter_bytes(self) -> list[bytes]:
            return [b"data"]

    monkeypatch.setattr(feeds.httpx, "stream", FakeStream)
    monkeypatch.setattr(get_settings(), "urlhaus_auth_key", "abc123")
    assert feeds.download_feed("https://example.org/feed") == "data"
    assert seen == {"Auth-Key": "abc123"}
