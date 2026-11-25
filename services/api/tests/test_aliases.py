"""Disposable email aliases: create, pause, delete, relay lookups (Wave 3)."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import EmailAlias, User, VerifiedDomain
from app.models.base import utcnow
from tests.test_devices import link_device
from tests.test_extension import EXT, bearer, enroll
from tests.test_sharing_groups import API, account

RELAY = "r" * 40


@pytest.fixture(autouse=True)
def relay(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(get_settings(), "alias_domains", ["relay.example.org"])
    monkeypatch.setattr(get_settings(), "alias_relay_token", RELAY)
    yield


def verified(db: Session, email: str) -> tuple[TestClient, User]:
    client, _ = account(db, email)
    user = db.scalars(select(User).where(User.email == email)).one()
    user.email_verified_at = utcnow()
    db.commit()
    return client, user


def resolve(client: TestClient, address: str, token: str = RELAY) -> dict:
    response = client.post(
        f"{API}/relay/aliases/resolve",
        json={"address": address},
        headers={"Authorization": f"Bearer {token}"},
    )
    return {"status": response.status_code, **(response.json() if response.content else {})}


def test_random_and_custom_aliases_forward_to_the_verified_inbox(db: Session) -> None:
    client, _ = verified(db, "amira@example.com")
    random = client.post(f"{API}/aliases", json={"label": "shop.example"})
    assert random.status_code == 201, random.text
    address = random.json()["address"]
    local, domain = address.split("@")
    assert domain == "relay.example.org" and len(local) == 10 and local.isalnum()
    custom = client.post(f"{API}/aliases", json={"local_part": "newsletters.2026"}).json()
    assert custom["address"] == "newsletters.2026@relay.example.org"

    listing = client.get(f"{API}/aliases").json()
    assert listing["forwards_to"] == "amira@example.com"
    assert listing["domains"] == ["relay.example.org"]
    assert [a["address"] for a in listing["aliases"]] == [custom["address"], address]

    anon = TestClient(client.app)
    assert resolve(anon, address) == {
        "status": 200,
        "action": "forward",
        "to": "amira@example.com",
        "reason": None,
    }
    # Sub-addressing (alias+tag@) reaches the same alias; case doesn't matter.
    assert resolve(anon, f"{local.upper()}+promo@relay.example.org")["action"] == "forward"
    assert client.get(f"{API}/aliases").json()["aliases"][1]["forwarded_count"] == 2


def test_paused_and_deleted_aliases_refuse_mail_and_are_never_reissued(db: Session) -> None:
    client, _ = verified(db, "amira@example.com")
    alias = client.post(f"{API}/aliases", json={"local_part": "shopping"}).json()
    anon = TestClient(client.app)
    assert (
        client.patch(f"{API}/aliases/{alias['id']}", json={"paused": True}).json()["paused"] is True
    )
    assert resolve(anon, alias["address"])["reason"] == "paused"
    assert client.get(f"{API}/aliases").json()["aliases"][0]["blocked_count"] == 1
    client.patch(f"{API}/aliases/{alias['id']}", json={"paused": False})
    assert resolve(anon, alias["address"])["action"] == "forward"

    assert client.delete(f"{API}/aliases/{alias['id']}").status_code == 204
    assert client.get(f"{API}/aliases").json()["aliases"] == []
    assert resolve(anon, alias["address"])["reason"] == "deleted"
    # Nobody, including someone else, can take the address again.
    other, _ = verified(db, "sam@example.com")
    assert other.post(f"{API}/aliases", json={"local_part": "shopping"}).status_code == 409
    assert db.scalars(select(EmailAlias)).one().label is None  # nothing kept about its use


def test_rules_for_names_domains_and_owners(db: Session) -> None:
    client, user = verified(db, "amira@example.com")
    for bad in ["postmaster", "a", "-dash", "two..dots", "UPPER CASE", "x" * 40]:
        assert client.post(f"{API}/aliases", json={"local_part": bad}).status_code in (400, 422), (
            bad
        )
    assert (
        client.post(f"{API}/aliases", json={"domain": "gmail.com"}).json()["error"]["code"]
        == "domain_not_allowed"
    )
    # A domain the person verified (DNS) works too.
    db.add(
        VerifiedDomain(
            user_id=user.id,
            domain="amira.example",
            token="t",
            verified_method="dns",
            verified_at=utcnow(),
        )
    )
    db.commit()
    own = client.post(f"{API}/aliases", json={"domain": "amira.example", "local_part": "bank"})
    assert own.json()["address"] == "bank@amira.example"
    # Someone else can't touch it.
    other, _ = verified(db, "sam@example.com")
    assert (
        other.patch(f"{API}/aliases/{own.json()['id']}", json={"paused": True}).status_code == 404
    )
    assert other.delete(f"{API}/aliases/{own.json()['id']}").status_code == 404


def test_an_unverified_email_gets_no_aliases(db: Session) -> None:
    client, _ = account(db, "new@example.com")
    assert client.post(f"{API}/aliases", json={}).json()["error"]["code"] == "email_not_verified"


def test_the_relay_needs_its_token_and_knows_nothing_else(db: Session) -> None:
    client, _ = verified(db, "amira@example.com")
    alias = client.post(f"{API}/aliases", json={}).json()
    anon = TestClient(client.app)
    assert resolve(anon, alias["address"], token="wrong")["status"] == 401
    assert resolve(anon, "nobody@relay.example.org")["reason"] == "unknown"


def test_the_extension_and_desktop_can_make_aliases_once_linked(db: Session) -> None:
    client, _ = verified(db, "amira@example.com")
    code = client.post(f"{API}/extension/link-codes").json()["code"]
    browser = TestClient(client.app)
    creds = bearer(enroll(browser, link_code=code))
    made = browser.post(f"{EXT}/aliases", json={"label": "news.example"}, headers=creds)
    assert made.status_code == 201, made.text
    assert (
        browser.get(f"{EXT}/aliases", headers=creds).json()["aliases"][0]["label"] == "news.example"
    )
    loner = TestClient(client.app)
    assert (
        loner.post(f"{EXT}/aliases", json={}, headers=bearer(enroll(loner))).json()["error"]["code"]
        == "not_linked"
    )

    device, auth = link_device(db, client)
    from_desktop = device.post(f"{API}/devices/aliases", json={}, headers=auth)
    assert from_desktop.status_code == 201, from_desktop.text
    assert len(device.get(f"{API}/devices/aliases", headers=auth).json()["aliases"]) == 2


def test_creation_is_capped(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _ = verified(db, "amira@example.com")
    monkeypatch.setattr(get_settings(), "alias_limit_per_user", 2)
    assert client.post(f"{API}/aliases", json={}).status_code == 201
    assert client.post(f"{API}/aliases", json={}).status_code == 201
    assert client.post(f"{API}/aliases", json={}).json()["error"]["code"] == "alias_limit"
