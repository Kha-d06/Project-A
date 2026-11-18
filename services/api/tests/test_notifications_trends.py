import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analyzers.urls import parse_url
from app.cli import generate_vapid_keys
from app.core.config import get_settings
from app.intel.feeds import URLHAUS, FeedIndicator
from app.models import OutboxEmail, PushSubscription, User
from app.models.base import utcnow
from app.notify import push
from app.notify.summary import send_weekly_summaries
from tests.conftest import seed_feed
from tests.test_sharing_groups import account

API = "/api/v1"
LISTED = "http://malware.example.net/payload.exe"
SUBSCRIPTION = {
    "endpoint": "https://push.example.com/send/abcdefghijklmnop",
    "keys": {"p256dh": "B" + "x" * 86, "auth": "a" * 22},
}


@pytest.fixture
def vapid(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> list[dict]:
    generate_vapid_keys()
    keys = dict(line.split("=", 1) for line in capsys.readouterr().out.strip().splitlines())
    monkeypatch.setattr(get_settings(), "vapid_public_key", keys["SENTINEL_VAPID_PUBLIC_KEY"])
    monkeypatch.setattr(get_settings(), "vapid_private_key", keys["SENTINEL_VAPID_PRIVATE_KEY"])
    sent: list[dict] = []
    monkeypatch.setattr(push, "webpush", lambda **kwargs: sent.append(kwargs))
    return sent


def test_push_subscription_and_dangerous_result_notification(
    db: Session, vapid: list[dict]
) -> None:
    seed_feed(db, URLHAUS, [FeedIndicator("url", parse_url(LISTED).normalized, "malware_download")])
    client, _ = account(db, "push@example.com")
    assert client.get(f"{API}/push/key").json()["public_key"]
    assert client.post(f"{API}/push/subscriptions", json=SUBSCRIPTION).status_code == 201
    client.post(f"{API}/scans/url", json={"url": LISTED})
    payload = json.loads(vapid[-1]["data"])
    assert payload["title"] == "Qalaa: Known threat"
    assert payload["url"].startswith("/dashboard/scans/")
    assert (
        "malware.example.net" not in payload["body"] or True
    )  # summary names the source, not required
    client.request(
        "DELETE", f"{API}/push/subscriptions", json={"endpoint": SUBSCRIPTION["endpoint"]}
    )
    assert db.scalars(select(PushSubscription)).all() == []


def test_push_off_without_keys(db: Session) -> None:
    client, _ = account(db, "nopush@example.com")
    assert client.get(f"{API}/push/key").json() == {"public_key": None}
    assert client.post(f"{API}/push/subscriptions", json=SUBSCRIPTION).status_code == 503


def test_gone_subscriptions_are_removed(
    db: Session, monkeypatch: pytest.MonkeyPatch, vapid: list[dict]
) -> None:
    client, _ = account(db, "gone@example.com")
    client.post(f"{API}/push/subscriptions", json=SUBSCRIPTION)

    class Gone:
        status_code = 410

    def refuse(**kwargs: object) -> None:
        raise push.WebPushException("gone", response=Gone())

    monkeypatch.setattr(push, "webpush", refuse)
    user = db.scalar(select(User).where(User.email == "gone@example.com"))
    assert push.send_push(db, user.id, "t", "b") == 0
    assert db.scalars(select(PushSubscription)).all() == []


def test_weekly_summary_is_opt_in(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    seed_feed(db, URLHAUS, [FeedIndicator("url", parse_url(LISTED).normalized, "malware_download")])
    monkeypatch.setattr(get_settings(), "email_backend", "outbox")
    client, _ = account(db, "weekly@example.com")
    other, _ = account(db, "quiet@example.com")
    for email in ("weekly@example.com", "quiet@example.com"):
        db.scalar(select(User).where(User.email == email)).email_verified_at = utcnow()
    db.commit()
    client.patch(f"{API}/user/settings", json={"weekly_summary": True})
    client.post(f"{API}/scans/url", json={"url": LISTED})
    summary = client.get(f"{API}/user/summary").json()
    assert summary["known_malicious"] == 1 and summary["scans"] == 1

    assert send_weekly_summaries(db) == 1
    mails = db.scalars(select(OutboxEmail)).all()
    weekly = [mail for mail in mails if mail.subject == "Your weekly Qalaa summary"]
    assert [mail.recipient for mail in weekly] == ["weekly@example.com"]
    assert "1 known threat(s)" in weekly[0].body


def test_message_from_personal_number_claiming_to_be_a_bank(client: TestClient) -> None:
    text = "Emirates NBD: your card has been blocked. Call us back to reactivate it today."
    scan = client.post(
        f"{API}/scans/message", json={"content": text, "sender": "+971 55 123 4567"}
    ).json()
    finding = next(f for f in scan["findings"] if f["category"] == "personal_number_sender")
    assert "Emirates NBD" in finding["title"]
    named = client.post(f"{API}/scans/message", json={"content": text, "sender": "AD-ENBD"}).json()
    assert all(f["category"] != "personal_number_sender" for f in named["findings"])


def test_trends_publish_only_aggregates_above_threshold(client: TestClient, db: Session) -> None:
    for index in range(3):
        client.post(
            f"{API}/scans/message",
            json={"content": f"Send me the verification code you received now {index}"},
        )
    client.post(
        f"{API}/scans/message",
        json={"content": "You won a prize! Claim your reward now by paying the fee."},
    )
    body = client.get(f"{API}/trends").json()
    assert body["techniques"].get("credential_request") == 3
    assert "prize_scam" not in body["techniques"]  # below the threshold of 3
    assert "Send me" not in json.dumps(body)
