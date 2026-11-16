"""Operator commands, e.g. `python -m app.cli sync-feeds`."""

import argparse
import sys

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_session_factory
from app.intel.feeds import (
    TEST_FIXTURES,
    FeedIndicator,
    get_or_create_source,
    store_indicators,
    sync_all_feeds,
)
from app.models.base import utcnow

# Indicators on reserved example domains (RFC 2606), so they can never match a real
# site. They let the full pipeline be exercised on a machine without internet access.
FIXTURE_SOURCE_NAME = "Development test fixtures (not real threat data)"
FIXTURE_INDICATORS = [
    FeedIndicator("url", "http://malware.example.net/payload.exe", "malware_download", "test"),
    FeedIndicator("host", "malware.example.net", "malware_download"),
]


def sync_feeds(db: Session) -> int:
    sources = sync_all_feeds(db)
    for source in sources:
        if source.last_error:
            print(f"{source.name}: FAILED - {source.last_error}")
        else:
            print(f"{source.name}: {source.indicator_count:,} indicators")
    return 1 if any(source.last_error for source in sources) else 0


def load_test_fixtures(db: Session) -> int:
    if get_settings().environment == "production":
        print("Refusing to load test fixtures in production.", file=sys.stderr)
        return 1
    # Kept apart from the real feeds: a match is reported as evidence, but fixtures
    # never count as a completed reputation check, so they cannot produce a
    # "no known threat" verdict for a real link.
    source = get_or_create_source(db, TEST_FIXTURES, FIXTURE_SOURCE_NAME)
    source.indicator_count = store_indicators(db, source, FIXTURE_INDICATORS)
    source.last_success_at = utcnow()
    db.commit()
    print(f"Loaded {source.indicator_count} test indicators as '{FIXTURE_SOURCE_NAME}'.")
    print("Real feeds are unaffected. Run sync-feeds with internet access to load them.")
    return 0


COMMANDS = {"sync-feeds": sync_feeds, "load-test-fixtures": load_test_fixtures}


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    parser.add_argument("command", choices=sorted(COMMANDS))
    args = parser.parse_args()
    with get_session_factory()() as db:
        return COMMANDS[args.command](db)


if __name__ == "__main__":
    sys.exit(main())
