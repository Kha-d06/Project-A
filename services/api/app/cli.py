"""Operator commands, e.g. `python -m app.cli sync-feeds`."""

import argparse
import sys

from sqlalchemy import select
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
from app.models import User
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


def set_role(db: Session, email: str, role: str) -> int:
    """Grant a role. The first administrator has to be created this way."""
    if role not in ("user", "moderator", "admin"):
        print("Role must be user, moderator or admin.", file=sys.stderr)
        return 1
    user = db.scalar(select(User).where(User.email == email.lower()))
    if user is None:
        print(f"No account with email {email}.", file=sys.stderr)
        return 1
    user.role = role
    db.commit()
    print(f"{user.email} is now {role}.")
    return 0


COMMANDS = {"sync-feeds": sync_feeds, "load-test-fixtures": load_test_fixtures}


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in COMMANDS:
        commands.add_parser(name)
    role = commands.add_parser("set-role", help="Give an account the user, moderator or admin role")
    role.add_argument("email")
    role.add_argument("role")
    args = parser.parse_args()
    with get_session_factory()() as db:
        if args.command == "set-role":
            return set_role(db, args.email, args.role)
        return COMMANDS[args.command](db)


if __name__ == "__main__":
    sys.exit(main())
