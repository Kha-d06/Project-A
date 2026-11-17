import base64
import os

from sqlalchemy.orm import Session

from app.models import Vault
from tests.conftest import PASSWORD
from tests.test_sharing_groups import API, account


def b64(size: int) -> str:
    return base64.b64encode(os.urandom(size)).decode()


def body(expected: int | None, **changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "kdf": {"name": "PBKDF2-SHA256", "iterations": 600_000, "salt": b64(16)},
        "wrapped_key": b64(60),
        "data": b64(500),
        "expected_version": expected,
    }
    payload.update(changes)
    return payload


def test_vault_round_trip_and_version_conflicts(db: Session) -> None:
    owner, _ = account(db, "vault1@example.com")
    assert owner.get(f"{API}/vault").json()["error"]["code"] == "vault_not_found"

    first = body(None)
    created = owner.put(f"{API}/vault", json=first)
    assert created.status_code == 200, created.text
    assert created.json()["version"] == 1
    stored = owner.get(f"{API}/vault").json()
    assert stored["data"] == first["data"] and stored["wrapped_key"] == first["wrapped_key"]

    # A second "create" from another tab must not overwrite the first vault.
    assert owner.put(f"{API}/vault", json=body(None)).json()["error"]["code"] == "vault_conflict"
    updated = owner.put(f"{API}/vault", json={**first, "data": b64(800), "expected_version": 1})
    assert updated.json()["version"] == 2
    stale = owner.put(f"{API}/vault", json={**first, "expected_version": 1})
    assert stale.status_code == 409 and stale.json()["error"]["details"]["version"] == 2

    # Other accounts never see it.
    other, _ = account(db, "vault2@example.com")
    assert other.get(f"{API}/vault").status_code == 404


def test_vault_rejects_weak_settings_and_non_ciphertext(db: Session) -> None:
    owner, _ = account(db, "vault3@example.com")
    weak = body(None, kdf={"name": "PBKDF2-SHA256", "iterations": 1000, "salt": b64(16)})
    assert owner.put(f"{API}/vault", json=weak).status_code == 422
    short_salt = body(None, kdf={"name": "PBKDF2-SHA256", "iterations": 600_000, "salt": b64(4)})
    assert owner.put(f"{API}/vault", json=short_salt).status_code == 422
    assert owner.put(f"{API}/vault", json=body(None, wrapped_key=b64(32))).status_code == 422
    assert owner.put(f"{API}/vault", json=body(None, data="not base64!")).status_code == 422
    assert owner.put(f"{API}/vault", json=body(None, data=b64(8))).status_code == 422
    unknown = body(None, kdf={"name": "MD5", "iterations": 600_000, "salt": b64(16)})
    assert owner.put(f"{API}/vault", json=unknown).status_code == 422


def test_vault_delete_needs_the_account_password(db: Session) -> None:
    owner, _ = account(db, "vault4@example.com")
    owner.put(f"{API}/vault", json=body(None))
    wrong = owner.post(f"{API}/vault/delete", json={"password": "guess"})
    assert wrong.status_code == 403
    assert owner.post(f"{API}/vault/delete", json={"password": PASSWORD}).status_code == 204
    assert owner.get(f"{API}/vault").status_code == 404
    assert db.query(Vault).count() == 0


def test_vault_needs_a_session(db: Session) -> None:
    owner, _ = account(db, "vault5@example.com")
    owner.headers.pop("x-csrf-token", None)
    owner.headers.pop("X-CSRF-Token", None)
    assert owner.put(f"{API}/vault", json=body(None)).status_code in (401, 403)
