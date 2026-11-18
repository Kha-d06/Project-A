"""Password sharing and emergency access: the server only relays ciphertext,
limits recipients to family, and enforces the emergency-access time delay."""

import base64
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import EmergencyContact, Group, GroupMember, User
from app.models.base import utcnow
from tests.test_sharing_groups import API, account


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def user_id(db: Session, email: str) -> uuid.UUID:
    return db.execute(select(User.id).where(User.email == email)).scalar_one()


def make_family(db: Session, *emails: str) -> None:
    """Put the given accounts in one family group (direct inserts)."""
    group = Group(id=uuid.uuid4(), name="Home", kind="family")
    db.add(group)
    db.flush()
    for i, email in enumerate(emails):
        db.add(
            GroupMember(
                group_id=group.id, user_id=user_id(db, email), role="owner" if i == 0 else "member"
            )
        )
    db.commit()


def key(client, headers=None) -> None:
    assert (
        client.put(
            f"{API}/vault/sharing-key", json={"public_key": b64("pub-" + str(uuid.uuid4()))}
        ).status_code
        == 200
    )


def test_sharing_is_limited_to_family(db: Session) -> None:
    alice, _ = account(db, "share-a@example.com")
    bob, _ = account(db, "share-b@example.com")
    stranger, _ = account(db, "share-x@example.com")
    make_family(db, "share-a@example.com", "share-b@example.com")
    key(alice)
    key(bob)
    key(stranger)

    bob_id = str(user_id(db, "share-b@example.com"))
    stranger_id = str(user_id(db, "share-x@example.com"))

    # Alice can see Bob as a recipient but not the stranger.
    recipients = {r["email"] for r in alice.get(f"{API}/vault/recipients").json()}
    assert "share-b@example.com" in recipients
    assert "share-x@example.com" not in recipients

    payload = {
        "recipient_id": bob_id,
        "ciphertext": b64("secret-login"),
        "sender_ephemeral": b64("eph"),
    }
    assert alice.post(f"{API}/vault/shares", json=payload).status_code == 200
    # Sharing with a non-family account is refused.
    assert (
        alice.post(f"{API}/vault/shares", json={**payload, "recipient_id": stranger_id}).json()[
            "error"
        ]["code"]
        == "not_family"
    )
    # Sharing with yourself is refused.
    assert (
        alice.post(
            f"{API}/vault/shares",
            json={**payload, "recipient_id": str(user_id(db, "share-a@example.com"))},
        ).json()["error"]["code"]
        == "invalid_recipient"
    )


def test_share_delivery_and_removal(db: Session) -> None:
    alice, _ = account(db, "d-a@example.com")
    bob, _ = account(db, "d-b@example.com")
    make_family(db, "d-a@example.com", "d-b@example.com")
    key(alice)
    key(bob)
    bob_id = str(user_id(db, "d-b@example.com"))

    alice.post(
        f"{API}/vault/shares",
        json={"recipient_id": bob_id, "ciphertext": b64("login"), "sender_ephemeral": b64("eph")},
    )
    shares = bob.get(f"{API}/vault/shares").json()
    assert len(shares) == 1
    assert shares[0]["sender_email"] == "d-a@example.com"
    assert shares[0]["ciphertext"] == b64("login")
    # Alice sees nothing in her own inbox.
    assert alice.get(f"{API}/vault/shares").json() == []
    # Bob accepts (deletes after copying locally).
    assert bob.delete(f"{API}/vault/shares/{shares[0]['id']}").status_code == 200
    assert bob.get(f"{API}/vault/shares").json() == []


def test_emergency_access_waits_then_unlocks(db: Session) -> None:
    owner, _ = account(db, "em-o@example.com")
    trusted, _ = account(db, "em-t@example.com")
    make_family(db, "em-o@example.com", "em-t@example.com")
    key(owner)
    key(trusted)
    trusted_id = str(user_id(db, "em-t@example.com"))

    grant = owner.post(
        f"{API}/vault/emergency",
        json={
            "grantee_id": trusted_id,
            "wait_hours": 48,
            "wrapped_vault_key": b64("vault-key"),
            "sender_ephemeral": b64("eph"),
        },
    )
    assert grant.status_code == 200
    contact_id = grant.json()["id"]

    # The trusted contact sees the grant and starts a request.
    listed = trusted.get(f"{API}/vault/emergency").json()
    assert any(c["role"] == "granted_to_me" and c["state"] == "active" for c in listed)
    assert (
        trusted.post(f"{API}/vault/emergency/{contact_id}/request").json()["state"] == "requested"
    )

    # The waiting period has not elapsed: the key is withheld.
    assert trusted.get(f"{API}/vault/emergency/{contact_id}/key").status_code == 425

    # Move the request back in time so the wait has elapsed.
    contact = db.get(EmergencyContact, uuid.UUID(contact_id))
    contact.requested_at = utcnow() - timedelta(hours=49)
    db.commit()

    key_response = trusted.get(f"{API}/vault/emergency/{contact_id}/key")
    assert key_response.status_code == 200
    assert key_response.json()["wrapped_vault_key"] == b64("vault-key")


def test_emergency_grantor_can_deny(db: Session) -> None:
    owner, _ = account(db, "deny-o@example.com")
    trusted, _ = account(db, "deny-t@example.com")
    make_family(db, "deny-o@example.com", "deny-t@example.com")
    key(owner)
    key(trusted)
    trusted_id = str(user_id(db, "deny-t@example.com"))
    contact_id = owner.post(
        f"{API}/vault/emergency",
        json={
            "grantee_id": trusted_id,
            "wait_hours": 0,
            "wrapped_vault_key": b64("k"),
            "sender_ephemeral": b64("e"),
        },
    ).json()["id"]
    trusted.post(f"{API}/vault/emergency/{contact_id}/request")
    # Owner denies before the (zero-hour) wait is acted on.
    assert owner.post(f"{API}/vault/emergency/{contact_id}/deny").json()["state"] == "denied"
    # A denied request no longer yields a key.
    assert trusted.get(f"{API}/vault/emergency/{contact_id}/key").status_code == 409
    # The trusted contact cannot deny on the owner's behalf.
    assert trusted.post(f"{API}/vault/emergency/{contact_id}/deny").status_code == 404
