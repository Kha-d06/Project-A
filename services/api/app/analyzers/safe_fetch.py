"""Outbound requests to user-supplied URLs.

Everything here assumes the URL is hostile. The rules:

* only http/https, only a short list of web ports;
* the hostname is resolved once, every returned address must be public, and the
  connection is made to that exact address (so a second, different DNS answer
  cannot redirect us to an internal service — DNS rebinding);
* redirects are followed manually and each hop goes through the same validation;
* response bodies are not read, except for the final page when a caller asks for
  it (website analysis), and then only up to MAX_BODY_BYTES of HTML. Nothing that
  is read is ever executed.
"""

import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
MAX_REDIRECTS = 6
HOP_TIMEOUT_SECONDS = 6
TOTAL_TIMEOUT_SECONDS = 20
USER_AGENT = "Mozilla/5.0 (compatible; SENTINEL-Scanner/0.1; link safety check)"
MAX_BODY_BYTES = 2 * 1024 * 1024
_HTML_TYPES = ("text/html", "application/xhtml+xml")

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class UnsafeDestinationError(Exception):
    """The destination is one we refuse to contact."""


class ResolutionError(Exception):
    """The hostname could not be resolved."""


def _embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if address.ipv4_mapped:
        return address.ipv4_mapped
    if address.sixtofour:
        return address.sixtofour
    if address.teredo:
        return address.teredo[1]
    return None


def is_forbidden_address(address: IpAddress) -> bool:
    if isinstance(address, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(address)
        if embedded is not None:
            return is_forbidden_address(embedded)
    return (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def resolve_host(host: str, port: int) -> list[str]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ResolutionError(f"{host} does not resolve") from exc
    return list(dict.fromkeys(str(record[4][0]) for record in records))


def resolve_public_addresses(host: str, port: int) -> list[str]:
    """Resolve a host and insist that every address it maps to is public."""
    if port not in ALLOWED_PORTS:
        raise UnsafeDestinationError(f"Port {port} is not a standard web port")
    addresses = resolve_host(host, port)
    if not addresses:
        raise ResolutionError(f"{host} does not resolve")
    for address in addresses:
        if is_forbidden_address(ipaddress.ip_address(address.split("%")[0])):
            raise UnsafeDestinationError(
                f"{host} resolves to a private or reserved address ({address})"
            )
    return addresses


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_address: str) -> None:
        super().__init__(host, port, timeout=HOP_TIMEOUT_SECONDS)
        self._pinned_address = pinned_address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_address, self.port), timeout=HOP_TIMEOUT_SECONDS
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_address: str) -> None:
        super().__init__(
            host, port, timeout=HOP_TIMEOUT_SECONDS, context=ssl.create_default_context()
        )
        self._pinned_address = pinned_address
        self._tls_context = ssl.create_default_context()

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._pinned_address, self.port), timeout=HOP_TIMEOUT_SECONDS
        )
        # Certificate validation still uses the hostname the user gave us.
        self.sock = self._tls_context.wrap_socket(raw, server_hostname=self.host)


@dataclass
class Hop:
    url: str
    host: str
    address: str | None = None
    status: int | None = None
    location: str | None = None
    tls: dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    body_truncated: bool = False
    error: str | None = None


@dataclass
class RedirectTrace:
    hops: list[Hop] = field(default_factory=list)
    # Set when we stopped early: "unsafe_destination", "unresolved", "tls_error",
    # "connection_error", "redirect_loop", "too_many_redirects", "timeout",
    # "unsupported_scheme".
    stopped: str | None = None
    stopped_detail: str | None = None

    @property
    def final_url(self) -> str | None:
        return self.hops[-1].url if self.hops else None

    @property
    def reached_destination(self) -> bool:
        return self.stopped is None and bool(self.hops) and self.hops[-1].status is not None


def _certificate_summary(certificate: dict[str, Any]) -> dict[str, Any]:
    def flatten(name: Any) -> dict[str, str]:
        return {key: value for group in name for key, value in group}

    issuer = flatten(certificate.get("issuer", ()))
    subject = flatten(certificate.get("subject", ()))
    return {
        "subject": subject.get("commonName"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "valid_from": certificate.get("notBefore"),
        "valid_until": certificate.get("notAfter"),
    }


_BODY_CHUNK_BYTES = 64 * 1024
BODY_READ_SECONDS = 10


def _read_capped(response: http.client.HTTPResponse) -> tuple[bytes, bool]:
    """Read at most MAX_BODY_BYTES, and stop after BODY_READ_SECONDS even if the
    server trickles data slowly enough to stay under the per-read socket timeout."""
    deadline = time.monotonic() + BODY_READ_SECONDS
    chunks: list[bytes] = []
    size = 0
    while size <= MAX_BODY_BYTES and time.monotonic() < deadline:
        chunk = response.read(_BODY_CHUNK_BYTES)
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)[:MAX_BODY_BYTES], True


def _request_hop(url: str, read_body: bool = False, any_type: bool = False) -> Hop:
    parts = urlsplit(url)
    host = parts.hostname or ""
    hop = Hop(url=url, host=host)
    port = parts.port or (443 if parts.scheme == "https" else 80)

    addresses = resolve_public_addresses(host, port)
    hop.address = addresses[0]

    connection: http.client.HTTPConnection
    if parts.scheme == "https":
        connection = _PinnedHTTPSConnection(host, port, hop.address)
    else:
        connection = _PinnedHTTPConnection(host, port, hop.address)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    try:
        connection.request(
            "GET",
            path,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        hop.status = response.status
        hop.location = response.getheader("Location")
        hop.headers = {name.lower(): value[:500] for name, value in response.getheaders()[:60]}
        content_type = hop.headers.get("content-type", "").lower()
        is_redirect = hop.status in (301, 302, 303, 307, 308)
        if read_body and not is_redirect and (any_type or content_type.startswith(_HTML_TYPES)):
            hop.body, hop.body_truncated = _read_capped(response)
        if isinstance(connection.sock, ssl.SSLSocket):
            certificate = connection.sock.getpeercert()
            if certificate:
                hop.tls = _certificate_summary(certificate)
    finally:
        connection.close()
    return hop


def fetch_resource(url: str) -> Hop:
    """One GET request, any content type, body capped. Redirects are returned, not
    followed, so the caller (the isolated browser) requests the next hop through
    this same function and it is validated again."""
    if urlsplit(url).scheme not in ("http", "https"):
        raise UnsafeDestinationError("Only web addresses can be fetched")
    return _request_hop(url, read_body=True, any_type=True)


def trace_redirects(url: str, read_final_body: bool = False) -> RedirectTrace:
    """Follow a URL's redirect chain. Page content is read only if asked, and only HTML."""
    trace = RedirectTrace()
    seen: set[str] = set()
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    current = url

    def stop(reason: str, detail: str) -> RedirectTrace:
        trace.stopped, trace.stopped_detail = reason, detail
        return trace

    for _ in range(MAX_REDIRECTS + 1):
        scheme = urlsplit(current).scheme
        if scheme not in ("http", "https"):
            return stop("unsupported_scheme", f"Redirect to a non-web address ({scheme}:)")
        if current in seen:
            return stop("redirect_loop", "The link redirects back to itself")
        if time.monotonic() > deadline:
            return stop("timeout", "Following the redirects took too long")
        seen.add(current)

        try:
            hop = _request_hop(current, read_body=read_final_body)
        except UnsafeDestinationError as exc:
            trace.hops.append(Hop(url=current, host=urlsplit(current).hostname or ""))
            return stop("unsafe_destination", str(exc))
        except ResolutionError as exc:
            trace.hops.append(Hop(url=current, host=urlsplit(current).hostname or ""))
            return stop("unresolved", str(exc))
        except ssl.SSLCertVerificationError as exc:
            trace.hops.append(Hop(url=current, host=urlsplit(current).hostname or ""))
            return stop("tls_error", exc.verify_message or "Certificate could not be verified")
        except (OSError, http.client.HTTPException) as exc:
            trace.hops.append(Hop(url=current, host=urlsplit(current).hostname or ""))
            return stop("connection_error", type(exc).__name__)

        trace.hops.append(hop)
        is_redirect = hop.status in (301, 302, 303, 307, 308) and hop.location
        if not is_redirect:
            return trace
        current = urljoin(current, hop.location or "")

    return stop("too_many_redirects", f"More than {MAX_REDIRECTS} redirects")


def post_json(url: str, body: bytes, headers: dict[str, str]) -> int:
    """POST to a user-supplied address (webhooks) under the same rules as fetching:
    public addresses only, allowed ports, a pinned connection and a short timeout.
    Redirects are not followed. Returns the HTTP status."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeDestinationError("Only web addresses can receive webhooks")
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    address = resolve_public_addresses(host, port)[0]
    connection: http.client.HTTPConnection = (
        _PinnedHTTPSConnection(host, port, address)
        if parts.scheme == "https"
        else _PinnedHTTPConnection(host, port, address)
    )
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    try:
        connection.request(
            "POST",
            path,
            body=body,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
                "Connection": "close",
                **headers,
            },
        )
        response = connection.getresponse()
        response.read(4096)
        return response.status
    finally:
        connection.close()
