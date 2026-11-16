import ipaddress
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.analyzers import safe_fetch
from app.analyzers.safe_fetch import (
    UnsafeDestinationError,
    is_forbidden_address,
    resolve_public_addresses,
    trace_redirects,
)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.4.1",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata endpoint
        "0.0.0.0",  # noqa: S104
        "224.0.0.1",
        "240.0.0.1",
        "100.64.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "2002:7f00:0001::",  # 6to4 wrapping 127.0.0.1
    ],
)
def test_internal_addresses_are_forbidden(address: str) -> None:
    assert is_forbidden_address(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(address: str) -> None:
    assert not is_forbidden_address(ipaddress.ip_address(address))


def test_host_with_any_private_record_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    # A rebinding-style answer: one public record, one internal.
    monkeypatch.setattr(
        safe_fetch, "resolve_host", lambda host, port: ["93.184.216.34", "10.0.0.1"]
    )
    with pytest.raises(UnsafeDestinationError):
        resolve_public_addresses("rebind.example", 443)


def test_non_web_ports_are_rejected() -> None:
    for port in (22, 25, 5432, 6379):
        with pytest.raises(UnsafeDestinationError):
            resolve_public_addresses("example.com", port)


def test_loopback_urls_are_never_contacted() -> None:
    for url in ("http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/latest/meta-data/"):
        trace = trace_redirects(url)
        assert trace.stopped == "unsafe_destination"
        assert trace.hops[0].status is None


class _RedirectingHandler(BaseHTTPRequestHandler):
    routes: dict[str, str] = {}

    def do_GET(self) -> None:
        target = self.routes.get(self.path)
        if target:
            self.send_response(302)
            self.send_header("Location", target)
        else:
            self.send_response(200)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def local_site(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """A loopback web server, with the SSRF policy relaxed just enough to reach it."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectingHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def loopback_only(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return not address.is_loopback

    monkeypatch.setattr(safe_fetch, "is_forbidden_address", loopback_only)
    monkeypatch.setattr(safe_fetch, "ALLOWED_PORTS", frozenset({port}))
    monkeypatch.setattr(safe_fetch, "resolve_host", lambda host, port: ["127.0.0.1"])
    yield f"http://site.test:{port}"
    server.shutdown()
    server.server_close()


def test_redirect_chain_is_followed_and_recorded(local_site: str) -> None:
    _RedirectingHandler.routes = {"/start": "/middle", "/middle": "/end"}
    trace = trace_redirects(f"{local_site}/start")
    assert trace.stopped is None
    assert [hop.status for hop in trace.hops] == [302, 302, 200]
    assert trace.final_url == f"{local_site}/end"


def test_redirect_loop_is_detected(local_site: str) -> None:
    _RedirectingHandler.routes = {"/a": "/b", "/b": "/a"}
    assert trace_redirects(f"{local_site}/a").stopped == "redirect_loop"


def test_endless_redirects_are_cut_off(local_site: str) -> None:
    _RedirectingHandler.routes = {f"/{n}": f"/{n + 1}" for n in range(20)}
    trace = trace_redirects(f"{local_site}/0")
    assert trace.stopped == "too_many_redirects"
    assert len(trace.hops) == safe_fetch.MAX_REDIRECTS + 1


def test_redirect_to_internal_address_is_refused(
    local_site: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Each hop is validated again: the second host resolves to a private address.
    def resolver(host: str, port: int) -> list[str]:
        return ["127.0.0.1"] if host == "site.test" else ["10.0.0.7"]

    def only_local_site(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return not address.is_loopback

    monkeypatch.setattr(safe_fetch, "resolve_host", resolver)
    monkeypatch.setattr(safe_fetch, "is_forbidden_address", only_local_site)
    port = local_site.rsplit(":", 1)[1]
    _RedirectingHandler.routes = {"/go": f"http://intranet.test:{port}/admin"}

    trace = trace_redirects(f"{local_site}/go")
    assert trace.stopped == "unsafe_destination"
    assert trace.hops[-1].status is None


def test_redirect_to_non_web_scheme_is_refused(local_site: str) -> None:
    _RedirectingHandler.routes = {"/go": "file:///etc/passwd"}
    assert trace_redirects(f"{local_site}/go").stopped == "unsupported_scheme"
