"""Rendering a page in an isolated headless browser.

Scripts run here, so the page is treated as hostile:
* the browser has no network of its own: every request is intercepted and
  fulfilled by safe_fetch.fetch_resource, which applies the full SSRF policy
  (public addresses only, pinned connections, port allowlist) to every hop;
* only GET requests are allowed; form posts, beacons and the like are refused;
* WebSockets, service workers, downloads, permission prompts and WebRTC are
  disabled;
* a fresh browser context per page, a hard time budget, and caps on the number
  and total size of resources.
Nothing is ever sent to the page that would identify the person who asked.
"""

import logging
import time
from dataclasses import dataclass, field

from app.analyzers.safe_fetch import (
    USER_AGENT,
    ResolutionError,
    UnsafeDestinationError,
    fetch_resource,
)
from app.core.config import get_settings

logger = logging.getLogger(__name__)

RENDER_SECONDS = 20
MAX_RESOURCES = 150
MAX_TOTAL_BYTES = 15 * 1024 * 1024
_HOP_HEADERS_DROPPED = {
    "content-length",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "set-cookie",
}
_LAUNCH_ARGS = [
    "--no-sandbox",  # the worker container is the sandbox; see docs/security.md
    "--dns-prefetch-disable",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
]


class RenderingUnavailableError(Exception):
    pass


@dataclass
class RenderResult:
    final_url: str
    html: str
    title: str
    requests: int = 0
    refused: list[str] = field(default_factory=list)
    truncated: bool = False


def rendering_enabled() -> bool:
    return get_settings().browser_rendering


def render_page(url: str) -> RenderResult:
    if not rendering_enabled():
        raise RenderingUnavailableError("Isolated page rendering is not enabled on this server")
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import Route, sync_playwright
    except ImportError as exc:
        raise RenderingUnavailableError("The headless browser is not installed") from exc

    state = {"requests": 0, "bytes": 0}
    refused: list[str] = []
    deadline = time.monotonic() + RENDER_SECONDS

    def handle(route: Route) -> None:
        request = route.request
        if request.method not in ("GET", "HEAD"):
            refused.append(f"{request.method} {request.url[:120]}")
            route.abort("blockedbyclient")
            return
        if (
            state["requests"] >= MAX_RESOURCES
            or state["bytes"] >= MAX_TOTAL_BYTES
            or time.monotonic() > deadline
        ):
            route.abort("blockedbyclient")
            return
        state["requests"] += 1
        try:
            hop = fetch_resource(request.url)
        except (UnsafeDestinationError, ResolutionError) as exc:
            refused.append(f"{request.url[:120]} ({exc})")
            route.abort("blockedbyclient")
            return
        except OSError:
            route.abort("failed")
            return
        body = hop.body or b""
        state["bytes"] += len(body)
        headers = {k: v for k, v in hop.headers.items() if k not in _HOP_HEADERS_DROPPED}
        route.fulfill(status=hop.status or 502, headers=headers, body=body)

    settings = get_settings()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True, executable_path=settings.browser_executable, args=_LAUNCH_ARGS
            )
            try:
                context = browser.new_context(
                    user_agent=USER_AGENT,
                    service_workers="block",
                    accept_downloads=False,
                    java_script_enabled=True,
                    permissions=[],
                    viewport={"width": 1280, "height": 900},
                )
                context.set_default_timeout(RENDER_SECONDS * 1000)
                page = context.new_page()
                page.route("**/*", handle)
                page.route_web_socket("**/*", lambda ws: ws.close())
                page.goto(url, wait_until="load", timeout=RENDER_SECONDS * 1000)
                # Give scripts a moment to build the page, within the overall budget.
                page.wait_for_timeout(min(2000, max(0, int((deadline - time.monotonic()) * 1000))))
                return RenderResult(
                    final_url=page.url,
                    html=page.content()[: 4 * 1024 * 1024],
                    title=page.title()[:200],
                    requests=state["requests"],
                    refused=refused[:20],
                    truncated=state["requests"] >= MAX_RESOURCES
                    or state["bytes"] >= MAX_TOTAL_BYTES,
                )
            finally:
                browser.close()
    except PlaywrightError as exc:
        logger.info("Rendering failed: %s", str(exc).splitlines()[0][:200])
        raise RenderingUnavailableError("The page could not be rendered") from exc
