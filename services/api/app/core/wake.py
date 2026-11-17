"""Wake a waiting device as soon as it has a new command.

The device holds one long request open (`GET /devices/wait`, up to ~25 seconds).
When the website queues a command, `notify(device_id)` sets a short-lived flag;
the waiting request sees it within a second and returns, and the device fetches
its commands. Without this, a command waits for the next 30-second heartbeat.

The flag lives in Redis (shared by every API process), or in memory when the
server runs with the in-memory rate-limit backend (tests, single process). It
never touches the database while waiting.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from functools import lru_cache
from typing import Protocol

import redis
import redis.asyncio as aioredis

from app.core.config import get_settings

FLAG_TTL_SECONDS = 60
CHECK_EVERY_SECONDS = 1.0


class WakeStore(Protocol):
    def set(self, key: str) -> None: ...
    async def take(self, key: str) -> bool: ...


class MemoryWakeStore:
    def __init__(self) -> None:
        self._flags: dict[str, float] = {}

    def set(self, key: str) -> None:
        self._flags[key] = time.monotonic() + FLAG_TTL_SECONDS

    async def take(self, key: str) -> bool:
        expires = self._flags.pop(key, None)
        return expires is not None and expires > time.monotonic()


class RedisWakeStore:
    def __init__(self, url: str) -> None:
        self._sync = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
        self._url = url

    def set(self, key: str) -> None:
        self._sync.set(key, "1", ex=FLAG_TTL_SECONDS)

    async def take(self, key: str) -> bool:
        client = aioredis.Redis.from_url(self._url, socket_timeout=2, socket_connect_timeout=2)
        try:
            return bool(await client.getdel(key))
        finally:
            await client.aclose()


@lru_cache
def get_wake_store() -> WakeStore:
    settings = get_settings()
    if settings.rate_limit_backend == "memory":
        return MemoryWakeStore()
    return RedisWakeStore(settings.redis_url)


def _key(device_id: object) -> str:
    return f"device-wake:{device_id}"


def notify(device_id: object) -> None:
    # A missed wake only delays the command until the next heartbeat.
    with contextlib.suppress(redis.RedisError):
        get_wake_store().set(_key(device_id))


async def wait(device_id: object, seconds: float) -> bool:
    """True as soon as the device has been woken; False after `seconds`."""
    store = get_wake_store()
    deadline = time.monotonic() + seconds
    while True:
        try:
            if await store.take(_key(device_id)):
                return True
        except redis.RedisError:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        await asyncio.sleep(min(CHECK_EVERY_SECONDS, remaining))
