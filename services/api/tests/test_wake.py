import asyncio
import uuid

import pytest
import redis

from app.core import wake
from app.core.config import get_settings


def _redis_store() -> wake.RedisWakeStore:
    store = wake.RedisWakeStore(get_settings().redis_url)
    try:
        store._sync.ping()
    except redis.RedisError:
        pytest.skip("Redis is not available")
    return store


def test_redis_wake_flag_is_taken_once() -> None:
    store = _redis_store()
    key = f"device-wake:test-{uuid.uuid4()}"
    assert asyncio.run(store.take(key)) is False
    store.set(key)
    assert asyncio.run(store.take(key)) is True
    assert asyncio.run(store.take(key)) is False  # consumed


def test_wait_returns_as_soon_as_woken(monkeypatch: pytest.MonkeyPatch) -> None:
    store = wake.MemoryWakeStore()
    monkeypatch.setattr(wake, "get_wake_store", lambda: store)
    monkeypatch.setattr(wake, "CHECK_EVERY_SECONDS", 0.01)

    async def scenario() -> tuple[bool, bool]:
        waiting = asyncio.create_task(wake.wait("dev-1", 5))
        await asyncio.sleep(0.05)
        wake.notify("dev-1")
        woken = await asyncio.wait_for(waiting, 1)
        timed_out = await wake.wait("dev-1", 0.05)
        return woken, timed_out

    assert asyncio.run(scenario()) == (True, False)
