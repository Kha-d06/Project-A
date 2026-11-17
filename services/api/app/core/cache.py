"""A small shared cache for hot, read-only answers (extension checks).

Entries are tagged with the current "threat data generation", which is bumped
whenever indicators change (feed sync, moderator decisions), so a cached answer
never outlives the data it was computed from. Cache failures are ignored: the
answer is simply computed again.
"""

import contextlib
import time
from functools import lru_cache
from typing import Protocol

import redis
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.config import get_settings

GENERATION_KEY = "intel:generation"


class Cache(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ttl: int) -> None: ...
    def generation(self) -> int: ...
    def bump(self) -> None: ...


class MemoryCache:
    def __init__(self) -> None:
        self._data: dict[str, tuple[float, str]] = {}
        self._generation = 0

    def get(self, key: str) -> str | None:
        item = self._data.get(key)
        return item[1] if item and item[0] > time.monotonic() else None

    def set(self, key: str, value: str, ttl: int) -> None:
        self._data[key] = (time.monotonic() + ttl, value)

    def generation(self) -> int:
        return self._generation

    def bump(self) -> None:
        self._generation += 1
        self._data.clear()


class RedisCache:
    def __init__(self, url: str) -> None:
        self._client = redis.Redis.from_url(
            url, socket_timeout=1, socket_connect_timeout=1, decode_responses=True
        )

    def get(self, key: str) -> str | None:
        with contextlib.suppress(redis.RedisError):
            value = self._client.get(key)
            return str(value) if value is not None else None
        return None

    def set(self, key: str, value: str, ttl: int) -> None:
        with contextlib.suppress(redis.RedisError):
            self._client.set(key, value, ex=ttl)

    def generation(self) -> int:
        with contextlib.suppress(redis.RedisError, ValueError, TypeError):
            return int(self._client.get(GENERATION_KEY) or 0)
        return -1  # unknown: callers skip the cache

    def bump(self) -> None:
        with contextlib.suppress(redis.RedisError):
            self._client.incr(GENERATION_KEY)


@lru_cache
def get_cache() -> Cache:
    settings = get_settings()
    return (
        MemoryCache() if settings.rate_limit_backend == "memory" else RedisCache(settings.redis_url)
    )


def threat_data_changed(db: Session | None = None) -> None:
    """Invalidate cached answers. With a session, this happens after it commits,
    so no request can cache the old data under the new generation."""
    if db is None:
        get_cache().bump()
    else:
        db.info["threat_data_changed"] = True


@event.listens_for(Session, "after_commit")
def _after_commit(session: Session) -> None:
    if session.info.pop("threat_data_changed", False):
        get_cache().bump()
