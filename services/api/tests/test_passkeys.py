"""Signing in to an account with a passkey (WebAuthn, Wave 4.F), with a software authenticator."""

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.main import app
from app.models import AccountPasskey, AuditEvent, User, WebAuthnChallenge
from app.models.base import utcnow
from tests.conftest import PASSWORD
from tests.test_sharing_groups import account
from tests.webauthn_soft import SoftAuthenticator, unb64url

API = "/api/v1"


def add_passkey(client: TestClient, device: SoftAuthenticator, name: str = "Laptop") -> dict:
    opts = client.post(f"{API}/user/passkeys/options").json()
    response = client.post(
        f"{API}/user/passkeys",
        json={
            "challenge_id": opts["challenge_id"],
            "credential": device.register(opts["options"]),
            "name": name,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def passkey_sign_in(device: SoftAuthenticator, **kwargs: object) -> tuple[TestClient, object]:
    fresh = TestClient(app)
    opts = fresh.post(f"{API}/auth/passkey/options").json()
    response = fresh.post(
        f"{API}/auth/passkey",
        json={
            "challenge_id": opts["challenge_id"],
            "credential": device.sign_in(opts["options"], **kwargs),
        },
    )  # type: ignore[arg-type]
    return fresh, response


def test_add_a_passkey_then_sign_in_with_it(db: Session) -> None:
    client, _ = account(db, "pk@example.com")
    opts = client.post(f"{API}/user/passkeys/options").json()["options"]
    user = db.scalars(select(User).where(User.email == "pk@example.com")).one()
    assert unb64url(opts["user"]["id"]) == user.id.bytes, (
        "the user handle is the random id, not the email"
    )
    assert opts["authenticatorSelection"]["userVerification"] == "required"
    assert opts["authenticatorSelection"]["residentKey"] == "required"

    device = SoftAuthenticator()
    added = add_passkey(client, device)
    assert added["name"] == "Laptop" and added["backed_up"] is True
    assert [p["name"] for p in client.get(f"{API}/user/passkeys").json()] == ["Laptop"]

    fresh, response = passkey_sign_in(device)
    assert response.status_code == 200, response.text  # type: ignore[attr-defined]
    assert fresh.get(f"{API}/auth/session").json()["user"]["email"] == "pk@example.com"
    events = db.scalars(select(AuditEvent.action).where(AuditEvent.user_id == user.id)).all()
    assert "passkey_added" in events and "signed_in_passkey" in events


def test_a_passkey_sign_in_counts_as_two_factors(db: Session) -> None:
    client, _ = account(db, "pk2fa@example.com")
    device = SoftAuthenticator()
    add_passkey(client, device)
    db.execute(
        update(User).where(User.email == "pk2fa@example.com").values(totp_enabled_at=utcnow())
    )
    db.commit()
    _, response = passkey_sign_in(device)
    assert response.status_code == 200, response.text  # type: ignore[attr-defined]
    assert "challenge" not in response.json()  # type: ignore[attr-defined]


def test_challenges_are_single_use_and_expire(db: Session) -> None:
    client, _ = account(db, "pkonce@example.com")
    device = SoftAuthenticator()
    opts = client.post(f"{API}/user/passkeys/options").json()
    body = {
        "challenge_id": opts["challenge_id"],
        "credential": device.register(opts["options"]),
        "name": "One",
    }
    assert client.post(f"{API}/user/passkeys", json=body).status_code == 201
    assert (
        client.post(f"{API}/user/passkeys", json=body).json()["error"]["code"]
        == "challenge_expired"
    )

    sign = TestClient(app)
    login = sign.post(f"{API}/auth/passkey/options").json()
    db.execute(update(WebAuthnChallenge).values(expires_at=utcnow() - timedelta(seconds=1)))
    db.commit()
    late = sign.post(
        f"{API}/auth/passkey",
        json={
            "challenge_id": login["challenge_id"],
            "credential": device.sign_in(login["options"]),
        },
    )
    assert late.status_code == 400 and late.json()["error"]["code"] == "challenge_expired"


def test_another_persons_registration_challenge_cant_be_used(db: Session) -> None:
    alice, _ = account(db, "pk-alice@example.com")
    bob, _ = account(db, "pk-bob@example.com")
    opts = alice.post(f"{API}/user/passkeys/options").json()
    device = SoftAuthenticator()
    response = bob.post(
        f"{API}/user/passkeys",
        json={
            "challenge_id": opts["challenge_id"],
            "credential": device.register(opts["options"]),
            "name": "Stolen",
        },
    )
    assert response.json()["error"]["code"] == "challenge_expired"


def test_wrong_origin_and_missing_user_verification_are_refused(db: Session) -> None:
    client, _ = account(db, "pkuv@example.com")
    device = SoftAuthenticator()
    opts = client.post(f"{API}/user/passkeys/options").json()
    bad = client.post(
        f"{API}/user/passkeys",
        json={
            "challenge_id": opts["challenge_id"],
            "credential": device.register(opts["options"], origin="https://evil.example"),
            "name": "x",
        },
    )
    assert bad.status_code == 400 and bad.json()["error"]["code"] == "passkey_invalid"
    opts = client.post(f"{API}/user/passkeys/options").json()
    no_uv = client.post(
        f"{API}/user/passkeys",
        json={
            "challenge_id": opts["challenge_id"],
            "credential": device.register(opts["options"], uv=False),
            "name": "x",
        },
    )
    assert no_uv.status_code == 400
    add_passkey(client, device)
    _, phished = passkey_sign_in(device, origin="https://qalaa-login.example")
    assert phished.status_code == 401  # type: ignore[attr-defined]
    _, unverified = passkey_sign_in(device, uv=False)
    assert unverified.status_code == 401  # type: ignore[attr-defined]


def test_a_counter_going_backwards_suggests_a_clone(db: Session) -> None:
    client, _ = account(db, "pkclone@example.com")
    device = SoftAuthenticator()
    add_passkey(client, device)
    _, first = passkey_sign_in(device, count=5)
    assert first.status_code == 200  # type: ignore[attr-defined]
    _, cloned = passkey_sign_in(device, count=3)
    assert cloned.status_code == 401  # type: ignore[attr-defined]
    assert db.scalars(select(AccountPasskey.sign_count)).one() == 5


def test_unknown_passkeys_and_disabled_accounts_get_the_same_answer(db: Session) -> None:
    _, unknown = passkey_sign_in(SoftAuthenticator())
    assert unknown.status_code == 401  # type: ignore[attr-defined]
    message = unknown.json()["error"]["message"]  # type: ignore[attr-defined]
    client, _ = account(db, "pkoff@example.com")
    device = SoftAuthenticator()
    add_passkey(client, device)
    db.execute(update(User).where(User.email == "pkoff@example.com").values(disabled_at=utcnow()))
    db.commit()
    _, disabled = passkey_sign_in(device)
    assert disabled.status_code == 401 and disabled.json()["error"]["message"] == message  # type: ignore[attr-defined]


def test_removing_a_passkey_needs_the_password(db: Session) -> None:
    client, _ = account(db, "pkdel@example.com")
    device = SoftAuthenticator()
    added = add_passkey(client, device)
    assert (
        client.post(
            f"{API}/user/passkeys/{added['id']}/remove", json={"password": "wrong password!"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"{API}/user/passkeys/{added['id']}/remove", json={"password": PASSWORD}
        ).status_code
        == 204
    )
    assert client.get(f"{API}/user/passkeys").json() == []
    _, after = passkey_sign_in(device)
    assert after.status_code == 401  # type: ignore[attr-defined]
    other, _ = account(db, "pkdel2@example.com")
    mine = add_passkey(other, SoftAuthenticator())
    assert (
        client.post(
            f"{API}/user/passkeys/{mine['id']}/remove", json={"password": PASSWORD}
        ).status_code
        == 404
    )


def test_the_same_passkey_cant_be_added_twice(db: Session) -> None:
    client, _ = account(db, "pkdup@example.com")
    device = SoftAuthenticator()
    add_passkey(client, device)
    opts = client.post(f"{API}/user/passkeys/options").json()
    excluded = {c["id"] for c in opts["options"]["excludeCredentials"]}
    assert excluded, "existing passkeys are excluded so the browser doesn't make a duplicate"
    dup = client.post(
        f"{API}/user/passkeys",
        json={
            "challenge_id": opts["challenge_id"],
            "credential": device.register(opts["options"]),
            "name": "again",
        },
    )
    assert dup.status_code == 409
