"""Sliding-window rate limiting.

Each limit counts requests in fixed windows, but judges a request by the
current window's count plus the previous window's count weighted by how much
of it still overlaps the last `window_seconds`. Plain fixed windows let a
client send the whole allowance at the end of one window and again at the
start of the next: twice the limit within seconds.

These limits protect shared infrastructure and third-party quotas. They apply to
everyone equally and are not tied to any plan or payment.
"""

import contextlib
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

    def peek(self, key: str) -> int:
        """Current count for a key, without changing it."""


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

    def peek(self, key: str) -> int:
        count, expires_at = self._windows.get(key, (0, 0.0))
        return count if expires_at > time.monotonic() else 0

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

    def peek(self, key: str) -> int:
        value = self._client.get(key)
        return int(value) if value is not None else 0


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


_HIT_COUNTER_TTL_SECONDS = 48 * 3600


def _hour_bucket(offset_hours: int = 0) -> str:
    return time.strftime("%Y%m%d%H", time.gmtime(time.time() - offset_hours * 3600))


def record_rejection(limit_name: str) -> None:
    """Count rejected requests per limit and hour, for the admin abuse overview."""
    # Monitoring must never turn a 429 into a 500.
    with contextlib.suppress(redis.RedisError):
        get_counter_store().increment(
            f"ratelimit-hits:{limit_name}:{_hour_bucket()}", _HIT_COUNTER_TTL_SECONDS
        )


def rejection_counts(limit_names: list[str], hours: int = 24) -> dict[str, int]:
    """Rejections per limit over the last `hours`. Reads without incrementing."""
    store = get_counter_store()
    totals: dict[str, int] = {}
    for name in limit_names:
        keys = [f"ratelimit-hits:{name}:{_hour_bucket(offset)}" for offset in range(hours)]
        totals[name] = sum(store.peek(key) for key in keys)
    return totals


def _now() -> float:
    return time.time()


def sliding_count(previous: int, current: int, elapsed_fraction: float) -> float:
    """Requests in the last window: all of this window, the overlapping part of the last."""
    return current + previous * (1.0 - elapsed_fraction)


def enforce(limit: RateLimit, subject: str) -> None:
    window = limit.window_seconds
    now = _now()
    index = int(now // window)
    base = f"ratelimit:{limit.name}:{subject}"
    store = get_counter_store()
    try:
        # Kept for two windows so the next window can still weigh it.
        current, _ = store.increment(f"{base}:{index}", window * 2)
        previous = store.peek(f"{base}:{index - 1}")
    except redis.RedisError as exc:
        # Failing open would remove abuse protection exactly when the system is degraded.
        raise ApiError(
            503,
            "rate_limiter_unavailable",
            "The service is temporarily unable to accept requests. Please try again shortly.",
        ) from exc
    elapsed = (now - index * window) / window
    count = sliding_count(previous, current, elapsed)
    retry_after = max(1, int((index + 1) * window - now))
    if count > limit.max_requests * get_settings().rate_limit_multiplier:
        record_rejection(limit.name)
        raise ApiError(
            429,
            "rate_limited",
            f"Too many requests. Please wait {retry_after} seconds and try again.",
            details={"retry_after_seconds": retry_after},
            headers={"Retry-After": str(retry_after)},
        )
