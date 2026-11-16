"""Operator commands: `python -m app.cli sync-feeds`."""

import argparse
import sys

from app.core.db import get_session_factory
from app.intel.feeds import sync_all_feeds


def main() -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    parser.add_subparsers(dest="command", required=True).add_parser(
        "sync-feeds", help="Download the public threat feeds into the local indicator store"
    )
    parser.parse_args()

    with get_session_factory()() as db:
        sources = sync_all_feeds(db)
    for source in sources:
        if source.last_error:
            print(f"{source.name}: FAILED - {source.last_error}")
        else:
            print(f"{source.name}: {source.indicator_count:,} indicators")
    return 1 if any(source.last_error for source in sources) else 0


if __name__ == "__main__":
    sys.exit(main())
