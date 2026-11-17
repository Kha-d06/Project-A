"""Operator commands, e.g. `python -m app.cli sync-feeds`."""

import argparse
import sys

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_session_factory
from app.core.security import hash_password
from app.intel.feeds import (
    TEST_FIXTURES,
    FeedIndicator,
    get_or_create_source,
    store_indicators,
    sync_all_feeds,
)
from app.models import User, UserSettings
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


def create_admin(db: Session, email: str, password: str) -> int:
    """Create (or promote) an account, make it an administrator, and turn on the
    site-assessment feature. For setting up a test or first-run instance."""
    if len(password) < 10 or len(set(password)) < 4:  # noqa: PLR2004
        print("Use a password of at least 10 characters with some variety.", file=sys.stderr)
        return 1
    # Same rules as the sign-in form, so the account can actually sign in.
    try:
        email = validate_email(email.strip(), check_deliverability=False).normalized.lower()
    except EmailNotValidError as exc:
        print(f"That email cannot be used to sign in: {exc}", file=sys.stderr)
        return 1
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(email=email, password_hash=hash_password(password), settings=UserSettings())
        db.add(user)
        action = "created"
    else:
        user.password_hash = hash_password(password)
        action = "updated"
    user.role = "admin"
    user.email_verified_at = utcnow()  # so email-gated features work without a mail server
    user.assessment_enabled_at = utcnow()
    db.commit()
    print(f"Admin account {action}: {email} (role=admin, site assessment enabled).")
    return 0


COMMANDS = {"sync-feeds": sync_feeds, "load-test-fixtures": load_test_fixtures}


def add_brand_reference(brand: str, domains: str, url: str) -> int:
    """Render a brand's real sign-in page and store its visual hash."""
    from app.analyzers.page_render import RenderingUnavailableError, render_page
    from app.analyzers.visual import Reference, dhash, reference_file, save_reference

    try:
        result = render_page(url)
    except RenderingUnavailableError as exc:
        print(f"Could not render {url}: {exc}. Set SENTINEL_BROWSER_RENDERING=true.")
        return 1
    if not result.screenshot:
        print("The page rendered but no screenshot was taken.")
        return 1
    owned = frozenset(d.strip().lower() for d in domains.split(",") if d.strip())
    save_reference(Reference(brand.lower(), owned, dhash(result.screenshot), url))
    print(f"Saved a visual reference for {brand} to {reference_file()}.")
    return 0


def generate_vapid_keys() -> int:
    """Print a new VAPID key pair for Web Push, in the format the settings expect."""
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_numbers().private_value.to_bytes(32, "big")
    public = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    print(f"SENTINEL_VAPID_PUBLIC_KEY={b64(public)}")
    print(f"SENTINEL_VAPID_PRIVATE_KEY={b64(private)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in COMMANDS:
        commands.add_parser(name)
    role = commands.add_parser("set-role", help="Give an account the user, moderator or admin role")
    role.add_argument("email")
    role.add_argument("role")
    admin = commands.add_parser(
        "create-admin", help="Create or promote an admin account (for a test or first-run instance)"
    )
    admin.add_argument("email")
    admin.add_argument("password")
    reference = commands.add_parser(
        "add-brand-reference", help="Store the look of a brand's real sign-in page"
    )
    reference.add_argument("brand")
    reference.add_argument("domains", help="Comma-separated domains the brand owns")
    reference.add_argument("url", help="Address of the real sign-in page")
    commands.add_parser("generate-vapid-keys", help="Create a key pair for Web Push")
    args = parser.parse_args()
    if args.command == "generate-vapid-keys":
        return generate_vapid_keys()
    if args.command == "add-brand-reference":
        return add_brand_reference(args.brand, args.domains, args.url)
    with get_session_factory()() as db:
        if args.command == "set-role":
            return set_role(db, args.email, args.role)
        if args.command == "create-admin":
            return create_admin(db, args.email, args.password)
        return COMMANDS[args.command](db)


if __name__ == "__main__":
    sys.exit(main())
