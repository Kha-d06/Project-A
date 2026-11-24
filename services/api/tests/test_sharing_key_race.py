"""Publishing a sharing key is idempotent under concurrency.

The vault page can send several PUT /vault/sharing-key requests at once (one
per open tab, or a re-render). A read-then-insert raced: both requests saw no
row and the second insert hit the primary key (CI stack job, run 79).
"""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.db import get_session_factory
from app.models import SharingKey
from tests.test_sharing_groups import API, account
from tests.test_vault_share import b64, user_id

CONCURRENT = 8


def test_simultaneous_first_publishes_all_succeed(db: Session) -> None:
    client, _ = account(db, "race-key@example.com")
    keys = [b64(f"pub-{i}") for i in range(CONCURRENT)]
    start = threading.Barrier(CONCURRENT)

    def publish(public_key: str) -> int:
        start.wait()
        return client.put(f"{API}/vault/sharing-key", json={"public_key": public_key}).status_code

    with ThreadPoolExecutor(CONCURRENT) as pool:
        statuses = list(pool.map(publish, keys))

    assert statuses == [200] * CONCURRENT
    owner = user_id(db, "race-key@example.com")
    with get_session_factory()() as fresh:
        rows = fresh.scalars(select(SharingKey).where(SharingKey.user_id == owner)).all()
        assert len(rows) == 1
        # Last writer wins, and it is one of the keys that was sent.
        assert rows[0].public_key in keys


def test_republishing_replaces_the_key_and_keeps_created_at(db: Session) -> None:
    client, _ = account(db, "race-key-2@example.com")
    assert (
        client.put(f"{API}/vault/sharing-key", json={"public_key": b64("first")}).status_code == 200
    )
    owner = user_id(db, "race-key-2@example.com")
    with get_session_factory()() as fresh:
        first = fresh.get(SharingKey, owner)
        assert first is not None
        created = first.created_at
    assert (
        client.put(f"{API}/vault/sharing-key", json={"public_key": b64("second")}).status_code
        == 200
    )
    with get_session_factory()() as fresh:
        row = fresh.get(SharingKey, owner)
        assert row is not None and row.public_key == b64("second")
        assert row.created_at == created and row.updated_at >= created
        assert (
            fresh.scalar(
                select(func.count()).select_from(SharingKey).where(SharingKey.user_id == owner)
            )
            == 1
        )


def test_simultaneous_first_vault_saves_give_one_vault_and_conflicts(db: Session) -> None:
    from tests.test_vault import body

    client, _ = account(db, "race-vault@example.com")
    start = threading.Barrier(CONCURRENT)

    def save(_: int) -> tuple[int, str | None]:
        start.wait()
        response = client.put(f"{API}/vault", json=body(None))
        error = (
            response.json().get("error", {}).get("code") if response.status_code != 200 else None
        )
        return response.status_code, error

    with ThreadPoolExecutor(CONCURRENT) as pool:
        results = list(pool.map(save, range(CONCURRENT)))

    # Exactly one creates it; the rest get the ordinary conflict, never a 500.
    assert sorted(status for status, _ in results) == [200] + [409] * (CONCURRENT - 1)
    assert all(code == "vault_conflict" for status, code in results if status == 409)


def test_simultaneous_screen_time_reports_keep_the_highest(db: Session) -> None:
    from fastapi.testclient import TestClient

    from tests.test_extension import EXT, bearer, enroll

    child, _ = account(db, "race-minutes@example.com")
    code = child.post(f"{API}/extension/link-codes").json()["code"]
    browser = TestClient(child.app)
    headers = bearer(enroll(browser, link_code=code))
    minutes = list(range(10, 10 + CONCURRENT))
    start = threading.Barrier(CONCURRENT)

    def report(value: int) -> int:
        start.wait()
        response = browser.post(
            f"{EXT}/screen-time", json={"day": "2026-11-24", "minutes": value}, headers=headers
        )
        return response.status_code

    with ThreadPoolExecutor(CONCURRENT) as pool:
        assert list(pool.map(report, minutes)) == [204] * CONCURRENT

    from app.models import ScreenTimeDay

    owner = user_id(db, "race-minutes@example.com")
    with get_session_factory()() as fresh:
        rows = fresh.scalars(select(ScreenTimeDay).where(ScreenTimeDay.user_id == owner)).all()
        assert [row.minutes for row in rows] == [max(minutes)]


def test_vault_created_elsewhere_between_read_and_insert_is_a_conflict(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Forces the Postgres interleaving: FOR UPDATE finds no row, another device
    commits its vault, then this request inserts."""
    from app.models import Vault
    from tests.test_vault import body

    client, _ = account(db, "race-vault-2@example.com")
    owner = user_id(db, "race-vault-2@example.com")
    real_get = Session.get

    def get_then_lose_the_race(
        self: Session, entity: object, ident: object, **kwargs: object
    ) -> object:
        found = real_get(self, entity, ident, **kwargs)  # type: ignore[arg-type]
        if entity is Vault and found is None:
            with get_session_factory()() as other:
                theirs = body(None)
                other.add(
                    Vault(
                        user_id=owner,
                        kdf=theirs["kdf"],
                        wrapped_key=theirs["wrapped_key"],
                        data=theirs["data"],
                        version=1,
                    )
                )
                other.commit()
        return found

    monkeypatch.setattr(Session, "get", get_then_lose_the_race)
    response = client.put(f"{API}/vault", json=body(None))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "vault_conflict"
