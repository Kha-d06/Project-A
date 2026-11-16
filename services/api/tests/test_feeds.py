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
URLHAUS_FEED, MALWAREBAZAAR_FEED = FEEDS


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
