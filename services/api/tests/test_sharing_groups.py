import hashlib
import hmac
import json
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analyzers import safe_fetch
from app.analyzers.urls import parse_url
from app.community.service import expire_verifications
from app.core.config import get_settings
from app.intel.feeds import URLHAUS, FeedIndicator
from app.intel.lookup import find_indicators
from app.models import CommunityReport, OutboxEmail, ScanShare, User
from app.models.base import utcnow
from app.notify import webhooks
from tests.conftest import seed_feed
from tests.test_community_admin import account as _account
from tests.test_community_admin import report

API = "/api/v1"


def account(db: Session, email: str, role: str = "user") -> tuple[TestClient, dict[str, str]]:
    client, headers = _account(db, email, role)
    client.headers.update(headers)  # every request from this signed-in client carries CSRF
    return client, headers


LISTED = "http://malware.example.net/payload.exe"


def url_scan(client: TestClient, url: str = LISTED) -> dict:
    response = client.post(f"{API}/scans/url", json={"url": url})
    assert response.status_code == 202, response.text
    return response.json()


@pytest.fixture
def feed(db: Session) -> None:
    seed_feed(db, URLHAUS, [FeedIndicator("url", parse_url(LISTED).normalized, "malware_download")])


# --- Share links ----------------------------------------------------------------------


def test_public_share_hides_the_target_unless_chosen(db: Session, feed: None) -> None:
    owner, headers = account(db, "owner@example.com")
    scan = url_scan(owner)
    response = owner.post(f"{API}/scans/{scan['id']}/shares", json={}, headers=headers)
    assert response.status_code == 201, response.text
    link = response.json()["url"]
    token = link.rsplit("/", 1)[1]

    stranger = TestClient(owner.app)
    shared = stranger.get(f"{API}/shared/{token}").json()
    assert shared["risk"] == "known_malicious"
    assert shared["target"] is None and shared["details"] is None
    assert all(f["evidence"] is None for f in shared["findings"])
    assert "malware.example.net" not in json.dumps(shared)

    full = owner.post(
        f"{API}/scans/{scan['id']}/shares", json={"include_target": True}, headers=headers
    ).json()
    shared_full = stranger.get(f"{API}/shared/{full['url'].rsplit('/', 1)[1]}").json()
    assert "malware.example.net" in shared_full["target"]

    assert owner.delete(f"{API}/shares/{response.json()['id']}", headers=headers).status_code == 204
    assert stranger.get(f"{API}/shared/{token}").status_code == 404
    assert db.scalar(select(ScanShare).where(ScanShare.id == uuid.UUID(full["id"]))).views == 1


def test_share_expiry_and_ownership(db: Session, feed: None) -> None:
    owner, headers = account(db, "owner2@example.com")
    other, other_headers = account(db, "other2@example.com")
    scan = url_scan(owner)
    assert (
        other.post(f"{API}/scans/{scan['id']}/shares", json={}, headers=other_headers).status_code
        == 404
    )
    created = owner.post(f"{API}/scans/{scan['id']}/shares", json={}, headers=headers).json()
    share = db.get(ScanShare, uuid.UUID(created["id"]))
    share.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    assert owner.get(f"{API}/shared/{created['url'].rsplit('/', 1)[1]}").status_code == 404


def test_bulk_url_scan(db: Session, feed: None) -> None:
    client, headers = account(db, "bulk@example.com")
    response = client.post(
        f"{API}/scans/bulk",
        json={"urls": [LISTED, "https://example.org/", LISTED]},
        headers=headers,
    )
    assert response.status_code == 202, response.text
    scans = response.json()["scans"]
    assert len(scans) == 2
    assert scans[0]["risk"] == "known_malicious"
    bad = client.post(f"{API}/scans/bulk", json={"urls": ["javascript:alert(1)"]}, headers=headers)
    assert bad.status_code == 422


# --- Groups ---------------------------------------------------------------------------


def test_family_group_invite_share_and_activity_consent(db: Session, feed: None) -> None:
    parent, parent_headers = account(db, "parent@example.com")
    child, child_headers = account(db, "child@example.com")
    stranger, stranger_headers = account(db, "stranger@example.com")

    group = parent.post(
        f"{API}/groups", json={"name": "Home", "kind": "family"}, headers=parent_headers
    ).json()
    invite = parent.post(
        f"{API}/groups/{group['id']}/invites",
        json={"email": "child@example.com"},
        headers=parent_headers,
    ).json()
    token = invite["url"].split("invite=")[1]

    # The invite only works for the address it was sent to.
    wrong = stranger.post(
        f"{API}/groups/invites/accept", json={"token": token}, headers=stranger_headers
    )
    assert wrong.status_code == 403
    joined = child.post(
        f"{API}/groups/invites/accept", json={"token": token}, headers=child_headers
    )
    assert joined.status_code == 200, joined.text
    assert (
        child.post(
            f"{API}/groups/invites/accept", json={"token": token}, headers=child_headers
        ).status_code
        == 400
    )

    # The child's warnings are invisible until the child opts in.
    url_scan(child)
    members = {m["email"]: m for m in parent.get(f"{API}/groups").json()[0]["members"]}
    assert members["child@example.com"]["warnings_last_30_days"] is None
    child_id = members["child@example.com"]["user_id"]
    forced = parent.patch(
        f"{API}/groups/{group['id']}/members/{child_id}",
        json={"share_activity": True},
        headers=parent_headers,
    )
    assert forced.status_code == 403
    child.patch(
        f"{API}/groups/{group['id']}/members/{child_id}",
        json={"share_activity": True},
        headers=child_headers,
    )
    members = {m["email"]: m for m in parent.get(f"{API}/groups").json()[0]["members"]}
    assert members["child@example.com"]["warnings_last_30_days"] == 1

    # Sharing a result with the group.
    scan = url_scan(child)
    child.post(
        f"{API}/scans/{scan['id']}/shares",
        json={"group_id": group["id"], "note": "Got this by SMS"},
        headers=child_headers,
    )
    feed_items = parent.get(f"{API}/groups/{group['id']}/shares").json()
    assert feed_items[0]["note"] == "Got this by SMS"
    assert feed_items[0]["scan"]["risk"] == "known_malicious"
    assert stranger.get(f"{API}/groups/{group['id']}/shares").status_code == 404

    # Members cannot remove others; the owner cannot leave.
    parent_id = members["parent@example.com"]["user_id"]
    assert (
        child.delete(
            f"{API}/groups/{group['id']}/members/{parent_id}", headers=child_headers
        ).status_code
        == 403
    )
    assert (
        child.delete(
            f"{API}/groups/{group['id']}/members/{child_id}", headers=child_headers
        ).status_code
        == 204
    )


def test_group_management_needs_a_session_not_an_api_key(db: Session) -> None:
    client, headers = account(db, "keys@example.com")
    key = client.post(f"{API}/user/api-keys", json={"name": "script"}, headers=headers).json()[
        "key"
    ]
    api = TestClient(client.app)
    response = api.post(
        f"{API}/groups",
        json={"name": "X", "kind": "family"},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert response.status_code == 401


# --- Webhooks -------------------------------------------------------------------------


def test_webhook_is_signed_and_rejects_unsafe_targets(
    db: Session, feed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, headers = account(db, "hooks@example.com")
    assert (
        client.post(
            f"{API}/user/webhooks", json={"url": "http://example.com/x"}, headers=headers
        ).status_code
        == 422
    )
    created = client.post(
        f"{API}/user/webhooks",
        json={"url": "https://hooks.example.com/sentinel", "events": ["scan.dangerous"]},
        headers=headers,
    ).json()
    secret = created["secret"]
    assert secret.startswith("whsec_")
    assert "secret" not in client.get(f"{API}/user/webhooks", headers=headers).json()[0]

    sent: list[tuple[str, bytes, dict[str, str]]] = []

    def fake_post(url: str, body: bytes, headers: dict[str, str]) -> int:
        sent.append((url, body, headers))
        return 200

    monkeypatch.setattr(webhooks, "post_json", fake_post)
    url_scan(client, "https://example.org/")  # no known threat: not a "dangerous" event
    assert sent == []
    url_scan(client)
    url, body, sent_headers = sent[0]
    assert url == "https://hooks.example.com/sentinel"
    expected = hmac.new(
        secret.encode(), f"{sent_headers['X-Sentinel-Timestamp']}.".encode() + body, hashlib.sha256
    ).hexdigest()
    assert sent_headers["X-Sentinel-Signature"] == f"sha256={expected}"
    assert json.loads(body)["data"]["risk"] == "known_malicious"
    assert (
        client.get(f"{API}/user/webhooks", headers=headers).json()[0]["last_status"] == "HTTP 200"
    )


def test_webhook_delivery_refuses_private_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safe_fetch, "resolve_host", lambda host, port: ["10.0.0.5"])
    with pytest.raises(safe_fetch.UnsafeDestinationError):
        safe_fetch.post_json("https://internal.example.com/hook", b"{}", {})


def test_webhook_switches_off_after_repeated_failures(
    db: Session, feed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, headers = account(db, "flaky@example.com")
    client.post(f"{API}/user/webhooks", json={"url": "https://down.example.com/"}, headers=headers)
    monkeypatch.setattr(webhooks, "post_json", lambda url, body, headers: 500)
    for _ in range(webhooks.MAX_CONSECUTIVE_FAILURES):
        url_scan(client)
    hook = client.get(f"{API}/user/webhooks", headers=headers).json()[0]
    assert hook["active"] is False and hook["last_status"] == "HTTP 500"


# --- Community: reputation, expiry, reporter emails -----------------------------------


def test_reputation_expiry_and_reporter_email(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "email_backend", "outbox")
    reporter, _ = account(db, "reporter@example.com")
    user = db.scalar(select(User).where(User.email == "reporter@example.com"))
    user.email_verified_at = utcnow()
    db.commit()
    moderator, mod_headers = account(db, "mod@example.com", role="moderator")

    created = []
    for index in range(3):
        created.append(report(reporter, subject=f"https://scam-{index}.example.org/")["report"])
    for item in created:
        moderator.post(
            f"{API}/admin/reports/{item['id']}/review",
            json={"status": "verified", "note": "Confirmed with the bank."},
            headers=mod_headers,
        )
    new = report(reporter, subject="https://scam-new.example.org/")["report"]
    queue = moderator.get(f"{API}/admin/reports?sort=reputation", headers=mod_headers).json()
    assert queue[0]["id"] == new["id"]
    assert queue[0]["reporter_reputation"] == {"level": "trusted", "verified": 3, "rejected": 0}

    mails = db.scalars(
        select(OutboxEmail).where(OutboxEmail.recipient == "reporter@example.com")
    ).all()
    assert any("Confirmed with the bank." in mail.body for mail in mails)

    assert find_indicators(db, "host", "scam-0.example.org")
    first = db.scalar(
        select(CommunityReport).where(CommunityReport.subject == "scam-0.example.org")
    )
    assert first.verification_expires_at is not None
    first.verification_expires_at = utcnow() - timedelta(hours=1)
    db.commit()
    assert expire_verifications(db) == 1
    assert find_indicators(db, "host", "scam-0.example.org") == []
    assert find_indicators(db, "host", "scam-1.example.org")
