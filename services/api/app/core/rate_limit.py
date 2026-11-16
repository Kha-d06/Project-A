"""Fixed-window rate limiting.

These limits protect shared infrastructure and third-party quotas. They apply to
everyone equally and are not tied to any plan or payment.
"""

import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol

import redis
from fastapi import Request

from app.core.config import get_settings
from app.core.errors import ApiError


@dataclass(frozen=True)
class RateLimit:
    name: str
    max_requests: int
    window_seconds: int


class CounterStore(Protocol):
    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        """Count a hit and return (hits in the current window, seconds until it resets)."""


class MemoryCounterStore:
    def __init__(self) -> None:
        self._windows: dict[str, tuple[int, float]] = {}

    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        now = time.monotonic()
        count, expires_at = self._windows.get(key, (0, now + window_seconds))
        if expires_at <= now:
            count, expires_at = 0, now + window_seconds
        self._windows[key] = (count + 1, expires_at)
        return count + 1, max(1, int(expires_at - now))

    def reset(self) -> None:
        self._windows.clear()


class RedisCounterStore:
    def __init__(self, url: str) -> None:
        self._client = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)

    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        pipeline = self._client.pipeline()
        pipeline.incr(key)
        pipeline.expire(key, window_seconds, nx=True)
        pipeline.ttl(key)
        count, _, ttl = pipeline.execute()
        return int(count), max(1, int(ttl))


@lru_cache
def get_counter_store() -> CounterStore:
    settings = get_settings()
    if settings.rate_limit_backend == "memory":
        return MemoryCounterStore()
    return RedisCounterStore(settings.redis_url)


def client_address(request: Request) -> str:
    if get_settings().trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def enforce(limit: RateLimit, subject: str) -> None:
    key = f"ratelimit:{limit.name}:{subject}"
    try:
        count, retry_after = get_counter_store().increment(key, limit.window_seconds)
    except redis.RedisError as exc:
        # Failing open would remove abuse protection exactly when the system is degraded.
        raise ApiError(
            503,
            "rate_limiter_unavailable",
            "The service is temporarily unable to accept requests. Please try again shortly.",
        ) from exc
    if count > limit.max_requests:
        raise ApiError(
            429,
            "rate_limited",
            f"Too many requests. Please wait {retry_after} seconds and try again.",
            details={"retry_after_seconds": retry_after},
            headers={"Retry-After": str(retry_after)},
        )
