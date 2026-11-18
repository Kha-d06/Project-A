import hashlib
import hmac
import json
from email.message import EmailMessage

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analyzers.urls import parse_url
from app.api import breach
from app.core.config import get_settings
from app.intel.feeds import URLHAUS, FeedIndicator
from app.models import OutboxEmail, ScanJob, User
from app.models.base import utcnow
from app.notify import channels
from tests.conftest import seed_feed
from tests.test_sharing_groups import account

API = "/api/v1"
LISTED = "http://malware.example.net/payload.exe"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, object, str]]:
    messages: list[tuple[str, object, str]] = []
    monkeypatch.setattr(
        channels, "send_telegram", lambda chat, text: messages.append(("telegram", chat, text))
    )
    monkeypatch.setattr(
        channels, "send_whatsapp", lambda to, text: messages.append(("whatsapp", to, text))
    )
    monkeypatch.setattr(
        "app.api.channels.send_telegram",
        lambda chat, text: messages.append(("telegram", chat, text)),
    )
    return messages


@pytest.fixture
def feed(db: Session) -> None:
    seed_feed(db, URLHAUS, [FeedIndicator("url", parse_url(LISTED).normalized, "malware_download")])


# --- Telegram -------------------------------------------------------------------------


def telegram(client: TestClient, text: str, secret: str = "tg-secret") -> int:
    update = {"update_id": 1, "message": {"chat": {"id": 4242}, "text": text}}
    return client.post(
        f"{API}/bots/telegram", json=update, headers={"X-Telegram-Bot-Api-Secret-Token": secret}
    ).status_code


def test_telegram_bot(
    client: TestClient, db: Session, feed: None, sent: list, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert telegram(client, LISTED) == 404  # off until configured
    monkeypatch.setattr(get_settings(), "telegram_bot_token", "123:abc")
    monkeypatch.setattr(get_settings(), "telegram_webhook_secret", "tg-secret")
    assert telegram(client, LISTED, secret="wrong") == 403

    assert telegram(client, LISTED) == 200
    channel, chat, text = sent[-1]
    assert (channel, chat) == ("telegram", 4242)
    assert "Known malicious" in text and "/scan/" in text
    scan = db.scalars(select(ScanJob).order_by(ScanJob.created_at.desc())).first()
    assert scan.user_id is None and "reply_to" not in scan.payload  # chat id discarded after reply

    assert (
        telegram(client, "عاجل: أرسل رمز التحقق الذي وصلك الآن لتفعيل حسابك وإلا سيتم إيقاف حسابك")
        == 200
    )
    assert "مشبوه" in sent[-1][2] or "ضار" in sent[-1][2]
    assert telegram(client, "/start") == 200
    assert "Send me a link" in sent[-1][2]


# --- WhatsApp -------------------------------------------------------------------------


def test_whatsapp_verification_and_signature(
    client: TestClient, feed: None, sent: list, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "whatsapp_verify_token", "verify-me")
    monkeypatch.setattr(settings, "whatsapp_app_secret", "app-secret")
    monkeypatch.setattr(settings, "whatsapp_access_token", "token")
    ok = client.get(
        f"{API}/bots/whatsapp",
        params={"hub.mode": "subscribe", "hub.verify_token": "verify-me", "hub.challenge": "1234"},
    )
    assert ok.text == "1234"
    assert (
        client.get(
            f"{API}/bots/whatsapp",
            params={"hub.mode": "subscribe", "hub.verify_token": "nope", "hub.challenge": "1"},
        ).status_code
        == 403
    )

    body = json.dumps(
        {
            "entry": [
                {
                    "changes": [
                        {
                            "value": {
                                "messages": [{"from": "971500000000", "text": {"body": LISTED}}]
                            }
                        }
                    ]
                }
            ]
        }
    ).encode()
    bad = client.post(
        f"{API}/bots/whatsapp", content=body, headers={"X-Hub-Signature-256": "sha256=00"}
    )
    assert bad.status_code == 403
    signature = "sha256=" + hmac.new(b"app-secret", body, hashlib.sha256).hexdigest()
    assert (
        client.post(
            f"{API}/bots/whatsapp", content=body, headers={"X-Hub-Signature-256": signature}
        ).status_code
        == 200
    )
    assert sent[-1][:2] == ("whatsapp", "971500000000")
    assert "Known malicious" in sent[-1][2]


# --- Email ----------------------------------------------------------------------------


def forwarded(sender: str = "amira@example.com", **headers: str) -> bytes:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "check@sentinel.example"
    message["Subject"] = "Fwd: Your parcel is waiting"
    for name, value in headers.items():
        message[name.replace("_", "-")] = value
    message.set_content(
        f"Your parcel could not be delivered. Pay the fee now at {LISTED} within 24 hours."
    )
    message.add_attachment(
        EICAR, maintype="application", subtype="octet-stream", filename="invoice.exe"
    )
    return message.as_bytes()


def test_scan_by_email(
    client: TestClient, db: Session, feed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "email_backend", "outbox")
    monkeypatch.setattr(settings, "inbound_email_token", "inbound-token")
    auth = {"Authorization": "Bearer inbound-token", "Content-Type": "message/rfc822"}
    assert (
        client.post(
            f"{API}/inbound/email", content=forwarded(), headers={"Authorization": "Bearer x"}
        ).status_code
        == 403
    )

    response = client.post(f"{API}/inbound/email", content=forwarded(), headers=auth)
    assert response.json() == {"scans": 2}
    replies = db.scalars(
        select(OutboxEmail).where(OutboxEmail.recipient == "amira@example.com")
    ).all()
    assert len(replies) == 2
    assert all(mail.subject.startswith("Qalaa result:") for mail in replies)
    assert any("Known malicious" in mail.body for mail in replies)

    # Forged senders and automatic replies are ignored, so Qalaa never mails bystanders.
    spoofed = forwarded("victim@example.org", Authentication_Results="mx.example; dmarc=fail")
    assert client.post(f"{API}/inbound/email", content=spoofed, headers=auth).json() == {"scans": 0}
    auto = forwarded("bounce@example.org", Auto_Submitted="auto-replied")
    assert client.post(f"{API}/inbound/email", content=auto, headers=auth).json() == {"scans": 0}


# --- Breach check ---------------------------------------------------------------------


def test_breach_check_only_for_your_own_address(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = account(db, "breached@example.com")
    assert client.get(f"{API}/breach/email").json()["error"]["code"] == "breach_check_unavailable"

    seen: list[str] = []

    def fake_get(url: str, params: dict, headers: dict, timeout: float) -> httpx.Response:
        seen.append(url)
        assert headers["hibp-api-key"] == "hibp-key"
        return httpx.Response(
            200,
            json=[
                {
                    "Name": "Example",
                    "Title": "Example Corp",
                    "Domain": "example.com",
                    "BreachDate": "2023-01-01",
                    "DataClasses": ["Email addresses", "Passwords"],
                    "IsVerified": True,
                }
            ],
        )

    monkeypatch.setattr(get_settings(), "hibp_api_key", "hibp-key")
    monkeypatch.setattr(breach.httpx, "get", fake_get)
    result = client.get(f"{API}/breach/email").json()
    assert result["email"] == "breached@example.com"
    assert result["breaches"][0]["data_classes"] == ["Email addresses", "Passwords"]
    assert seen[0].endswith("breached%40example.com")

    # With email delivery on, the address must be confirmed first.
    monkeypatch.setattr(get_settings(), "email_backend", "outbox")
    assert client.get(f"{API}/breach/email").json()["error"]["code"] == "email_not_verified"
    user = db.scalar(select(User).where(User.email == "breached@example.com"))
    user.email_verified_at = utcnow()
    db.commit()
    assert client.get(f"{API}/breach/email").status_code == 200


def test_no_endpoint_to_check_someone_elses_address(client: TestClient) -> None:
    assert client.get(f"{API}/breach/email", params={"email": "x@example.com"}).status_code == 401
