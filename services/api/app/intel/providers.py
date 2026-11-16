"""Adapters for external services queried during a scan.

Each adapter either returns real data or raises ProviderUnavailableError with a
reason that is shown to the user. Nothing here ever substitutes a made-up answer.
"""

import socket
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from app.core.config import get_settings

_TIMEOUT_SECONDS = 8
_CLAMAV_CHUNK_BYTES = 64 * 1024
_CLAMAV_TIMEOUT_SECONDS = 60


class ProviderUnavailableError(Exception):
    pass


# --- URLhaus live lookup ------------------------------------------------------------


@dataclass(frozen=True)
class UrlhausResult:
    listed: bool
    threat: str | None = None
    status: str | None = None
    date_added: str | None = None
    reference: str | None = None
    tags: tuple[str, ...] = ()


def urlhaus_lookup(url: str) -> UrlhausResult:
    auth_key = get_settings().urlhaus_auth_key
    if not auth_key:
        raise ProviderUnavailableError(
            "Live URLhaus lookups need a free abuse.ch Auth-Key, which is not configured"
        )
    try:
        response = httpx.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": auth_key},
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        body: dict[str, Any] = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ProviderUnavailableError(f"URLhaus did not answer ({type(exc).__name__})") from exc

    status = body.get("query_status")
    if status == "no_results":
        return UrlhausResult(listed=False)
    if status != "ok":
        raise ProviderUnavailableError(f"URLhaus rejected the lookup ({status})")
    return UrlhausResult(
        listed=True,
        threat=body.get("threat"),
        status=body.get("url_status"),
        date_added=body.get("date_added"),
        reference=body.get("urlhaus_reference"),
        tags=tuple(body.get("tags") or ()),
    )


# --- Domain registration date (RDAP) ------------------------------------------------


def domain_registration_date(domain: str) -> datetime:
    """Registration date from the registry's RDAP service, via the rdap.org redirector."""
    try:
        response = httpx.get(
            f"{get_settings().rdap_base_url}/domain/{domain}",
            timeout=_TIMEOUT_SECONDS,
            follow_redirects=True,
            headers={"Accept": "application/rdap+json"},
        )
    except httpx.HTTPError as exc:
        raise ProviderUnavailableError(
            f"The registry lookup did not answer ({type(exc).__name__})"
        ) from exc
    if response.status_code == httpx.codes.NOT_FOUND:
        raise ProviderUnavailableError("The registry for this domain does not publish RDAP records")
    try:
        response.raise_for_status()
        events = response.json().get("events", [])
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        raise ProviderUnavailableError("The registry returned an unreadable answer") from exc

    for event in events:
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            try:
                return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                break
    raise ProviderUnavailableError("The registry record does not include a registration date")


# --- ClamAV -------------------------------------------------------------------------


@dataclass(frozen=True)
class ClamavResult:
    infected: bool
    signature: str | None = None


def clamav_scan(path: Path) -> ClamavResult:
    """Stream a file to clamd (INSTREAM). The file is never executed or written elsewhere."""
    settings = get_settings()
    if not settings.clamav_host:
        raise ProviderUnavailableError("No ClamAV service is configured")
    try:
        with socket.create_connection(
            (settings.clamav_host, settings.clamav_port), timeout=_CLAMAV_TIMEOUT_SECONDS
        ) as connection:
            connection.sendall(b"zINSTREAM\0")
            with path.open("rb") as sample:
                while chunk := sample.read(_CLAMAV_CHUNK_BYTES):
                    connection.sendall(struct.pack("!I", len(chunk)) + chunk)
            connection.sendall(struct.pack("!I", 0))
            reply = b""
            while not reply.endswith(b"\0"):
                received = connection.recv(4096)
                if not received:
                    break
                reply += received
    except OSError as exc:
        raise ProviderUnavailableError(f"ClamAV is not reachable ({type(exc).__name__})") from exc

    text = reply.rstrip(b"\0").decode(errors="replace").strip()
    if text.endswith("OK"):
        return ClamavResult(infected=False)
    if text.endswith("FOUND"):
        return ClamavResult(infected=True, signature=text.removeprefix("stream:").strip()[:-6])
    raise ProviderUnavailableError(f"ClamAV could not scan the file ({text[:120]})")
