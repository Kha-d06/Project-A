"""Email is checked on the device: the server publishes the rule pack and checks
bare links only. Nothing about a message is sent or stored."""

import logging

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.mail import bare
from app.core.private_paths import PrivatePathFilter
from app.intel.feeds import MALWAREBAZAAR, FeedIndicator
from app.models import ScanJob
from tests.conftest import seed_feed

API = "/api/v1"


def test_rule_pack_is_public_and_matches_in_javascript_syntax(client: TestClient) -> None:
    response = client.get(f"{API}/email/rules")
    assert response.status_code == 200
    assert "max-age=86400" in response.headers["cache-control"]
    pack = response.json()
    assert len(pack["version"]) == 16
    assert pack["rules"] and all(rule["patterns"] for rule in pack["rules"])
    assert all(rule["title_ar"] for rule in pack["rules"])
    assert "paypal.com" in pack["brands"]["paypal"]["domains"]
    assert pack["brands"]["paypal"]["name"] == "PayPal"
    assert "bit.ly" in pack["shorteners"]
    # Python-only syntax would not compile on the clients.
    for rule in pack["rules"]:
        for pattern in rule["patterns"]:
            assert "(?P<" not in pattern and "(?i" not in pattern


def test_bare_strips_query_fragment_and_userinfo() -> None:
    assert bare("https://u:p@a.example/x/y?token=abc#top") == "https://a.example/x/y"


def test_links_checked_without_storing(client: TestClient, db: Session) -> None:
    before = db.scalar(select(func.count()).select_from(ScanJob))
    body = {
        "urls": [
            "http://paypal.com.account-verify.example/login?email=me@example.org",
            "https://example.org/newsletter",
            "https://example.org/newsletter#again",
            "not a url",
        ]
    }
    response = client.post(f"{API}/email/links", json=body)
    assert response.status_code == 200, response.text
    results = response.json()["results"]
    assert [r["url"] for r in results] == [
        "http://paypal.com.account-verify.example/login",
        "https://example.org/newsletter",
    ]
    assert results[0]["findings"] and results[1]["findings"] == []
    assert "me@example.org" not in response.text
    assert db.scalar(select(func.count()).select_from(ScanJob)) == before
    assert (
        client.post(f"{API}/email/links", json={"urls": ["https://a.example"] * 51}).status_code
        == 422
    )
    # The old endpoint that took a whole message is gone.
    assert client.post(f"{API}/email/check", json={}).status_code in (404, 405)


def test_hash_prefix_lookup_is_k_anonymous(client: TestClient, db: Session) -> None:
    listed = "abcdef12" + "0" * 56
    other = "abcdef99" + "1" * 56
    seed_feed(db, MALWAREBAZAAR, [FeedIndicator("sha256", listed), FeedIndicator("sha256", other)])
    found = client.get(f"{API}/intelligence/hash-prefix/ABCDEF").json()
    assert found["prefix"] == "abcdef"
    assert sorted(c["sha256"] for c in found["candidates"]) == sorted([listed, other])
    narrow = client.get(f"{API}/intelligence/hash-prefix/abcdef12").json()
    assert [c["sha256"] for c in narrow["candidates"]] == [listed]
    assert client.get(f"{API}/intelligence/hash-prefix/0000000").json()["candidates"] == []
    for bad in ("abc", "abcdef123", "ghijkl", listed):
        assert client.get(f"{API}/intelligence/hash-prefix/{bad}").status_code == 422


def test_private_lookups_stay_out_of_the_access_log() -> None:
    keep = PrivatePathFilter()

    def record(path: str) -> logging.LogRecord:
        return logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            "",
            0,
            '%s - "%s %s HTTP/%s" %d',
            ("203.0.113.9:5000", "GET", path, "1.1", 200),
            None,
        )

    assert not keep.filter(record("/api/v1/intelligence/hash-prefix/abcdef"))
    assert not keep.filter(record("/api/v1/email/links"))
    assert not keep.filter(record("/api/v1/extension/threat-hashes"))
    assert not keep.filter(record("/api/v1/extension/check-url"))
    assert keep.filter(record("/api/v1/extension/threat-prefixes"))
    assert keep.filter(record("/api/v1/scans/url"))


def test_public_domain_list_for_safe_dns(client: TestClient, db: Session) -> None:
    from app.intel.feeds import THREATFOX

    seed_feed(
        db,
        THREATFOX,
        [
            FeedIndicator("host", "evil-c2.example.net", "botnet_cc"),
            FeedIndicator("host", "203.0.113.9", "botnet_cc"),
        ],
    )
    response = client.get(f"{API}/intelligence/domain-list")
    assert response.status_code == 200
    body = response.json()
    # Domains only (an IP can't be blocked by DNS), and no account needed.
    assert body["hosts"] == ["evil-c2.example.net"]
    assert body["sources"]
