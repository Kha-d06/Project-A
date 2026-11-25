"""Every pattern that runs on message text finishes quickly on hostile input (P1-6).

Messages come from strangers (inbound email, bots, the extension), so a
pattern with catastrophic backtracking is a denial of service. Each pattern is
timed against long inputs built from its own words and from runs of the
characters its classes accept.
"""

import json
import os
import re
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.analyzers import message_patterns as mp

BUDGET_SECONDS = 0.25
LENGTH = 20_000

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (f"rule{index}.{n}", pattern)
    for index, rule in enumerate(mp.RULES)
    for n, pattern in enumerate(rule.patterns)
] + [("URL", mp.URL_PATTERN), ("EMAIL", mp.EMAIL_PATTERN), ("PHONE", mp.PHONE_PATTERN)]


def hostile_inputs(source: str) -> Iterator[str]:
    fragments = set(re.findall(r"[A-Za-z]{2,}", source))
    fragments |= {"a", "A", "1", "-", ".", " ", "_", "@", "/", "a.", "1 ", "a-", "x@", "+1"}
    for fragment in sorted(fragments)[:60]:
        yield (fragment * (LENGTH // len(fragment) + 1))[:LENGTH] + "!"
        yield ((fragment + " ") * (LENGTH // (len(fragment) + 1) + 1))[:LENGTH] + "!"


@pytest.mark.parametrize(("name", "pattern"), PATTERNS, ids=[n for n, _ in PATTERNS])
def test_pattern_is_linear_enough(name: str, pattern: re.Pattern[str]) -> None:
    for text in hostile_inputs(pattern.pattern):
        started = time.perf_counter()
        pattern.search(text)
        elapsed = time.perf_counter() - started
        assert elapsed < BUDGET_SECONDS, f"{name} took {elapsed:.2f}s on {text[:20]!r}…"


def test_bounded_url_and_email_patterns_still_find_real_ones() -> None:
    text = (
        "Pay at secure-login.paypal.com.verify-account.top/x or www.example.org, "
        "mail amira.k+test@mail.example.co today"
    )
    assert [m.group(0) for m in mp.URL_PATTERN.finditer(text)] == [
        "secure-login.paypal.com.verify-account.top/x",
        "www.example.org,",
        "mail.example.co",
    ]
    assert mp.EMAIL_PATTERN.findall(text) == ["amira.k+test@mail.example.co"]


FIXTURE = (
    Path(__file__).resolve().parents[3] / "apps/thunderbird/test/fixtures/server-patterns.json"
)


def test_pattern_fixture_for_clients_is_current() -> None:
    """Clients refuse unsafe pattern shapes; their test checks every pattern we send passes.

    Regenerate with UPDATE_FIXTURES=1 when the rules change.
    """
    patterns = [pattern.pattern for rule in mp.RULES for pattern in rule.patterns]
    text = json.dumps(patterns, ensure_ascii=False, indent=1) + "\n"
    if os.environ.get("UPDATE_FIXTURES"):
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(text, encoding="utf-8")
    assert FIXTURE.read_text(encoding="utf-8") == text
