"""Proving that an account controls a domain before Qalaa will scan it.

Two methods, the same ones Google Search Console and certificate authorities
use:

* a DNS TXT record containing the token, at the domain or at
  `_sentinel-challenge.<domain>`;
* a file at `https://<domain>/.well-known/sentinel-verification.txt` whose
  contents are the token.

Ownership is checked when the domain is added and again at the start of every
scan, so a domain that changes hands or whose token is removed can no longer be
assessed.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Literal

from app.analyzers import safe_fetch

TOKEN_PREFIX = "qalaa-site-verification"  # noqa: S105 - a public label, not a secret
CHALLENGE_SUBDOMAIN = "_qalaa-challenge"
VERIFICATION_PATH = "/.well-known/qalaa-verification.txt"
# Names used before the product was renamed; sites verified with them keep working.
LEGACY_CHALLENGE_SUBDOMAIN = "_sentinel-challenge"
LEGACY_VERIFICATION_PATH = "/.well-known/sentinel-verification.txt"

# A function that returns the TXT records for a name (so tests can supply fakes).
TxtResolver = Callable[[str], list[str]]


def new_token() -> str:
    return f"{TOKEN_PREFIX}={secrets.token_hex(16)}"


def dns_resolver(name: str) -> list[str]:
    """TXT records for a name, or [] if none / the name does not resolve."""
    import dns.resolver  # imported lazily so unit tests need no network

    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=8)
    except Exception:  # noqa: BLE001 - any resolver error means "no records"
        return []
    records: list[str] = []
    for answer in answers:
        # A TXT record is one or more quoted strings; join them.
        records.append(b"".join(getattr(answer, "strings", [])).decode("utf-8", "replace"))
    return records


def has_mx(name: str) -> bool:
    import dns.resolver

    try:
        return bool(dns.resolver.resolve(name, "MX", lifetime=8))
    except Exception:  # noqa: BLE001
        return False


def dnssec_enabled(name: str) -> bool | None:
    import dns.resolver

    try:
        answer = dns.resolver.resolve(name, "DNSKEY", lifetime=8)
        return bool(answer)
    except Exception:  # noqa: BLE001
        return False


def _file_fetcher(domain: str, path: str) -> tuple[int | None, str]:
    hop = safe_fetch.fetch_resource(f"https://{domain}{path}")
    body = (hop.body or b"")[:4096].decode("utf-8", "replace")
    return hop.status, body


def verify(
    domain: str,
    token: str,
    *,
    resolver: TxtResolver | None = None,
    file_fetcher: Callable[[str, str], tuple[int | None, str]] | None = None,
) -> Literal["dns", "file"] | None:
    """Return the method that proved ownership, or None if neither did."""
    resolver = resolver or dns_resolver
    for name in (
        domain,
        f"{CHALLENGE_SUBDOMAIN}.{domain}",
        f"{LEGACY_CHALLENGE_SUBDOMAIN}.{domain}",
    ):
        if any(token == record.strip() for record in resolver(name)):
            return "dns"
    fetch = file_fetcher or _file_fetcher
    for path in (VERIFICATION_PATH, LEGACY_VERIFICATION_PATH):
        try:
            status, body = fetch(domain, path)
        except Exception:  # noqa: BLE001, S112 - unreachable file is just "not verified"
            continue
        if status == 200 and token == body.strip():
            return "file"
    return None
