import time
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analyzers.urls import parse_url
from app.api.extension_auth import issue_access_token, read_access_token
from app.intel.feeds import URLHAUS, FeedIndicator
from app.main import app
from app.models import ExtensionEvent
from tests.conftest import seed_feed, sign_up

EXT = "/api/v1/extension"
LISTED = "http://malware.example.net/payload.exe"


def enroll(client: TestClient, link_code: str | None = None) -> dict:
    body = {"browser": "chrome", "version": "0.1.0", "link_code": link_code}
    response = client.post(f"{EXT}/enroll", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def bearer(credentials: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {credentials['access_token']}"}


def check(client: TestClient, credentials: dict, url: str, mode: str = "full") -> dict:
    response = client.post(
        f"{EXT}/check-url", json={"url": url, "mode": mode}, headers=bearer(credentials)
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def feed(db: Session) -> None:
    seed_feed(db, URLHAUS, [FeedIndicator("url", parse_url(LISTED).normalized, "malware_download")])


# --- Credentials ----------------------------------------------------------------------


def test_anonymous_enrollment_gives_working_credentials(client: TestClient) -> None:
    credentials = enroll(client)
    assert credentials["linked"] is False
    settings = client.get(f"{EXT}/settings", headers=bearer(credentials)).json()
    assert settings == {
        "installation_id": credentials["installation_id"],
        "linked": False,
        "account_email": None,
        "sync_events": False,
        "family_blocklist": [],
        "family_groups": [],
        "safe_search": False,
        "lock_protection": False,
    }


def test_checks_require_a_valid_access_token(client: TestClient) -> None:
    body = {"url": "https://example.org/"}
    assert client.post(f"{EXT}/check-url", json=body).status_code == 401
    forged = {"Authorization": f"Bearer sxa1.{uuid.uuid4()}.9999999999.forged"}
    assert client.post(f"{EXT}/check-url", json=body, headers=forged).status_code == 401


def test_access_tokens_expire_and_cannot_be_altered() -> None:
    installation_id = uuid.uuid4()
    token = issue_access_token(installation_id, now=1000)
    assert read_access_token(token, now=1001) == installation_id
    assert read_access_token(token, now=1000 + 15 * 60 + 1) is None
    prefix, raw_id, expiry, signature = token.split(".")
    extended = f"{prefix}.{raw_id}.{int(expiry) + 3600}.{signature}"
    assert read_access_token(extended, now=1001) is None


def test_refresh_issues_a_new_access_token(client: TestClient) -> None:
    credentials = enroll(client)
    refreshed = client.post(f"{EXT}/token", json={"refresh_token": credentials["refresh_token"]})
    assert refreshed.status_code == 200
    assert read_access_token(refreshed.json()["access_token"], now=time.time()) is not None
    bad = client.post(f"{EXT}/token", json={"refresh_token": "not-a-real-token"})
    assert bad.status_code == 401


def test_linking_with_a_one_time_code(client: TestClient) -> None:
    headers = sign_up(client)
    code = client.post(f"{EXT}/link-codes", headers=headers).json()["code"]
    assert len(code) == 9 and code[4] == "-"

    extension = TestClient(app)
    credentials = enroll(extension)
    linked = extension.post(
        f"{EXT}/link", json={"link_code": code.lower()}, headers=bearer(credentials)
    )
    assert linked.status_code == 200
    assert linked.json()["account_email"] == "amira@example.com"

    reused = extension.post(f"{EXT}/link", json={"link_code": code}, headers=bearer(credentials))
    assert reused.status_code == 400

    installations = client.get(f"{EXT}/installations").json()
    assert [i["id"] for i in installations] == [credentials["installation_id"]]


def test_revoked_installation_loses_access(client: TestClient) -> None:
    headers = sign_up(client)
    code = client.post(f"{EXT}/link-codes", headers=headers).json()["code"]
    credentials = enroll(TestClient(app), link_code=code)
    assert credentials["linked"] is True

    other = TestClient(app)
    other_headers = sign_up(other, "other@example.com")
    path = f"{EXT}/installations/{credentials['installation_id']}"
    assert other.delete(path, headers=other_headers).status_code == 404

    assert client.delete(path, headers=headers).status_code == 204
    assert client.get(f"{EXT}/settings", headers=bearer(credentials)).status_code == 401
    refreshed = client.post(f"{EXT}/token", json={"refresh_token": credentials["refresh_token"]})
    assert refreshed.status_code == 401


def test_link_code_guessing_is_rate_limited(client: TestClient) -> None:
    credentials = enroll(client)
    statuses = [
        client.post(
            f"{EXT}/link", json={"link_code": f"AAAA-AAA{n}"}, headers=bearer(credentials)
        ).status_code
        for n in range(11)
    ]
    assert statuses[:10] == [400] * 10
    assert statuses[10] == 429


# --- Verdicts -------------------------------------------------------------------------


def test_listed_url_is_dangerous_with_evidence(client: TestClient, feed: None) -> None:
    result = check(client, enroll(client), LISTED)
    assert result["verdict"] == "dangerous"
    assert result["reasons"][0]["severity"] == "critical"
    assert result["cache_seconds"] >= 3600


def test_clean_url_with_fresh_feed(client: TestClient, feed: None) -> None:
    result = check(client, enroll(client), "https://www.wikipedia.org/wiki/Phishing")
    assert result["verdict"] == "no_known_threat"
    assert result["reasons"] == []


def test_without_a_fresh_feed_the_check_is_unavailable(client: TestClient) -> None:
    result = check(client, enroll(client), "https://www.wikipedia.org/")
    assert result["verdict"] == "unavailable"
    assert "not up to date" in result["limitations"][0]


def test_lookalike_domain_is_suspicious_even_without_feeds(client: TestClient) -> None:
    assert check(client, enroll(client), "https://paypall.com/login")["verdict"] == "suspicious"


def test_privacy_mode_checks_only_the_domain(client: TestClient, feed: None) -> None:
    result = check(client, enroll(client), LISTED, mode="host")
    # The listing is for the full address; the domain alone is only weakly implicated.
    assert result["verdict"] == "no_known_threat"
    assert any("privacy mode" in limitation for limitation in result["limitations"])


def test_private_network_addresses_are_skipped(client: TestClient) -> None:
    for url in ("http://192.168.1.1/admin", "http://10.0.0.8:8080/"):
        assert check(client, enroll(client), url)["verdict"] == "skipped"


def test_disguised_download_is_flagged(client: TestClient, feed: None) -> None:
    response = client.post(
        f"{EXT}/check-download",
        json={"url": "https://files.example.org/x", "filename": "invoice.pdf.exe"},
        headers=bearer(enroll(client)),
    )
    result = response.json()
    assert result["verdict"] == "suspicious"
    assert any("cannot" in l or "does not let" in l for l in result["limitations"])  # noqa: E741


def test_checks_store_nothing(client: TestClient, db: Session, feed: None) -> None:
    check(client, enroll(client), LISTED)
    assert db.query(ExtensionEvent).count() == 0


# --- Events ---------------------------------------------------------------------------


def test_events_are_kept_only_when_the_user_opts_in(client: TestClient, db: Session) -> None:
    headers = sign_up(client)
    code = client.post(f"{EXT}/link-codes", headers=headers).json()["code"]
    credentials = enroll(TestClient(app), link_code=code)
    event = {"kind": "warning_shown", "url": f"{LISTED}?session=secret", "verdict": "dangerous"}

    first = client.post(f"{EXT}/report-event", json=event, headers=bearer(credentials))
    assert first.json() == {"stored": False}

    client.patch("/api/v1/user/settings", json={"sync_extension_events": True}, headers=headers)
    second = client.post(f"{EXT}/report-event", json=event, headers=bearer(credentials))
    assert second.json() == {"stored": True}

    events = client.get(f"{EXT}/events").json()
    assert events[0]["host"] == "malware.example.net"
    assert "secret" not in str(events)

    export = client.get("/api/v1/user/export").json()
    assert export["extension_events"][0]["host"] == "malware.example.net"
    assert client.delete(f"{EXT}/events", headers=headers).status_code == 204
    assert client.get(f"{EXT}/events").json() == []


def test_anonymous_installations_never_store_events(client: TestClient) -> None:
    event = {"kind": "proceeded", "url": LISTED, "verdict": "dangerous"}
    response = client.post(f"{EXT}/report-event", json=event, headers=bearer(enroll(client)))
    assert response.json() == {"stored": False}


def test_cached_checks_follow_new_threat_data(client: TestClient, db: Session) -> None:
    from app.core.cache import get_cache

    get_cache().bump()  # start from an empty cache
    credentials = enroll(client)
    url = "http://fresh-threat.example.net/x"
    seed_feed(db, URLHAUS, [FeedIndicator("url", parse_url(LISTED).normalized, "malware_download")])
    assert check(client, credentials, url)["verdict"] == "no_known_threat"
    assert check(client, credentials, url)["verdict"] == "no_known_threat"  # served from cache
    seed_feed(db, URLHAUS, [FeedIndicator("url", parse_url(url).normalized, "malware_download")])
    assert check(client, credentials, url)["verdict"] == "dangerous"


def test_linked_extension_reads_only_its_own_encrypted_vault(client: TestClient) -> None:
    import base64
    import os

    headers = sign_up(client)
    unlinked = enroll(TestClient(app))
    assert (
        client.get(f"{EXT}/vault", headers=bearer(unlinked)).json()["error"]["code"] == "not_linked"
    )

    code = client.post(f"{EXT}/link-codes", headers=headers).json()["code"]
    linked = enroll(TestClient(app), link_code=code)
    assert (
        client.get(f"{EXT}/vault", headers=bearer(linked)).json()["error"]["code"]
        == "vault_not_found"
    )

    stored = {
        "kdf": {
            "name": "PBKDF2-SHA256",
            "iterations": 600_000,
            "salt": base64.b64encode(os.urandom(16)).decode(),
        },
        "wrapped_key": base64.b64encode(os.urandom(60)).decode(),
        "data": base64.b64encode(os.urandom(1052)).decode(),
        "expected_version": None,
    }
    assert client.put("/api/v1/vault", json=stored, headers=headers).status_code == 200
    vault = client.get(f"{EXT}/vault", headers=bearer(linked)).json()
    assert vault["data"] == stored["data"] and vault["wrapped_key"] == stored["wrapped_key"]
    assert vault["user_id"] == client.get("/api/v1/auth/session").json()["user"]["id"]
