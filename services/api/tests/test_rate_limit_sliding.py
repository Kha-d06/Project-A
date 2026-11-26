"""Sliding-window rate limits: no double allowance across a window boundary (P1-11)."""

import pytest

from app.core import rate_limit
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, sliding_count

LIMIT = RateLimit("test-sliding", max_requests=10, window_seconds=60)


def hits(n: int, subject: str = "client") -> int:
    allowed = 0
    for _ in range(n):
        try:
            rate_limit.enforce(LIMIT, subject)
            allowed += 1
        except ApiError as exc:
            assert exc.status_code == 429
    return allowed


def test_the_allowance_is_not_doubled_across_a_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"t": 60 * 1000 + 58.0}  # two seconds before a window ends
    monkeypatch.setattr(rate_limit, "_now", lambda: clock["t"])
    assert hits(10) == 10
    clock["t"] += 4  # two seconds into the next window
    # A fixed window would allow ten more here; the sliding estimate counts the
    # last window almost in full.
    assert hits(1) == 0
    clock["t"] += 30  # about half of the old window has slid out
    # 1 refused + 10 * (1 - 32/60) still overlapping leaves room for 4 more.
    # (Refused requests count too, so a client that keeps hammering stays out.)
    assert hits(10) == 4
    clock["t"] += 120  # long after: a fresh allowance
    assert hits(10) == 10


def test_within_one_window_it_behaves_like_before(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rate_limit, "_now", lambda: 60 * 2000 + 5.0)
    assert hits(12, "other") == 10


def test_retry_after_points_at_the_window_end(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rate_limit, "_now", lambda: 60 * 3000 + 45.0)
    hits(10, "third")
    with pytest.raises(ApiError) as caught:
        rate_limit.enforce(LIMIT, "third")
    assert caught.value.details == {"retry_after_seconds": 15}


def test_sliding_count() -> None:
    assert sliding_count(10, 0, 0.0) == 10
    assert sliding_count(10, 3, 0.5) == 8
    assert sliding_count(10, 3, 1.0) == 3


def test_forwarded_address_is_read_from_the_right(monkeypatch: pytest.MonkeyPatch) -> None:
    """A client can't choose its own rate-limit identity by sending X-Forwarded-For."""
    from starlette.requests import Request

    from app.core.config import get_settings
    from app.core.rate_limit import client_address

    def request(forwarded: str | None) -> Request:
        headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
        return Request({"type": "http", "headers": headers, "client": ("10.0.0.2", 1234)})

    settings = get_settings()
    monkeypatch.setattr(settings, "trust_forwarded_for", True)
    monkeypatch.setattr(settings, "forwarded_hops", 1)
    # Caddy alone appends the real address after anything the client claimed.
    assert client_address(request("6.6.6.6, 203.0.113.9")) == "203.0.113.9"
    assert client_address(request("203.0.113.9")) == "203.0.113.9"
    # A CDN in front of Caddy: two hops.
    monkeypatch.setattr(settings, "forwarded_hops", 2)
    assert client_address(request("6.6.6.6, 203.0.113.9, 198.51.100.1")) == "203.0.113.9"
    assert client_address(request("203.0.113.9")) == "203.0.113.9"
    # Not trusted: the socket's peer.
    monkeypatch.setattr(settings, "trust_forwarded_for", False)
    assert client_address(request("6.6.6.6")) == "10.0.0.2"
