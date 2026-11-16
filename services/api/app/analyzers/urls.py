"""URL parsing and normalization shared by the analyzers and the indicator store."""

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

import tldextract

MAX_URL_LENGTH = 2048

# Use the suffix list bundled with tldextract; never fetch it at runtime.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class InvalidUrlError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedUrl:
    normalized: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    has_credentials: bool
    registrable_domain: str
    subdomain: str
    domain_label: str
    is_ip_address: bool


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def parse_url(raw: str) -> ParsedUrl:
    candidate = raw.strip()
    if not candidate:
        raise InvalidUrlError("Enter a link to check.")
    if len(candidate) > MAX_URL_LENGTH:
        raise InvalidUrlError(f"Links longer than {MAX_URL_LENGTH} characters are not supported.")
    if any(ord(char) < 0x20 or char == " " for char in candidate):
        raise InvalidUrlError("The link contains spaces or control characters.")
    if not _SCHEME_PATTERN.match(candidate) or "://" not in candidate[:12]:
        # People paste "example.com/path" far more often than a full URL.
        candidate = f"http://{candidate}"

    try:
        parts: SplitResult = urlsplit(candidate)
        port = parts.port
    except ValueError as exc:
        raise InvalidUrlError("This does not look like a valid link.") from exc

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidUrlError("Only http:// and https:// links can be checked.")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host or ("." not in host and not _is_ip(host)):
        raise InvalidUrlError("The link needs a full domain name, such as example.com.")

    is_ip = _is_ip(host)
    try:
        ascii_host = host if is_ip else host.encode("idna").decode()
    except UnicodeError as exc:
        raise InvalidUrlError("The domain name in this link is not valid.") from exc

    if port == _DEFAULT_PORTS[scheme]:
        port = None
    netloc_host = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    netloc = f"{netloc_host}:{port}" if port else netloc_host
    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))

    extracted = _extract(ascii_host)
    registrable = ascii_host if is_ip else (extracted.top_domain_under_public_suffix or ascii_host)
    return ParsedUrl(
        normalized=normalized,
        scheme=scheme,
        host=ascii_host,
        port=port,
        path=parts.path or "/",
        query=parts.query,
        has_credentials=parts.username is not None,
        registrable_domain=registrable,
        subdomain="" if is_ip else extracted.subdomain,
        domain_label=ascii_host if is_ip else extracted.domain,
        is_ip_address=is_ip,
    )


def indicator_digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
