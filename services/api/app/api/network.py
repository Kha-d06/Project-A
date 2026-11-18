"""Internet-side exposure check for the home network scanner.

The desktop scanner can see that a router *has* a port forwarding, but not
whether it is actually reachable from the internet. This endpoint answers that,
and only that, by attempting a plain TCP connection to a small set of ports —
**on the caller's own public IP address only**. It never probes an address the
caller did not connect from, and it requires explicit consent on each call.

No result is stored. The response is a list of which of the checked ports are
open from the outside, so the owner can close the ones they didn't mean to open.
"""

import asyncio
import contextlib
import ipaddress

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.api.auth import record_event
from app.api.deps import Db, SessionUser
from app.core import rate_limit
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, client_address

router = APIRouter(prefix="/network", tags=["Home network"])

EXPOSURE_LIMIT = RateLimit("network-exposure", max_requests=10, window_seconds=3600)

# The ports worth checking from the outside: remote-control and file-sharing
# services that should almost never be reachable from the internet at home.
CHECK_PORTS: list[tuple[int, str, str]] = [
    (21, "ftp", "File transfer, often with weak logins."),
    (22, "ssh", "Remote login. Fine if deliberate and key-protected."),
    (23, "telnet", "Unencrypted remote control. Close this."),
    (80, "http", "A web service is reachable from the internet."),
    (443, "https", "A web service is reachable from the internet."),
    (445, "smb", "Windows file sharing exposed to the internet. Close this."),
    (3389, "rdp", "Windows Remote Desktop exposed to the internet. Close this."),
    (5555, "adb", "Android debugging exposed to the internet. Close this."),
    (5900, "vnc", "Remote screen control exposed to the internet. Close this."),
    (8080, "http-alt", "A web or admin service is reachable from the internet."),
]


class ExposureRequest(BaseModel):
    consent: bool = Field(
        description="Must be true: the caller confirms this is their own network."
    )


class OpenPort(BaseModel):
    port: int
    service: str
    note: str


class ExposureResult(BaseModel):
    address: str
    checked: int
    open_ports: list[OpenPort]
    message: str


async def _is_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """A single TCP connect attempt; True only on a completed handshake."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return True
    except (TimeoutError, OSError):
        return False


@router.post("/exposure", response_model=ExposureResult)
async def check_exposure(
    body: ExposureRequest,
    request: Request,
    db: Db,
    user: SessionUser,
) -> ExposureResult:
    if not body.consent:
        raise ApiError(
            400, "consent_required", "Confirm that this is your own network before checking."
        )

    rate_limit.enforce(EXPOSURE_LIMIT, client_address(request))

    address = client_address(request)
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as err:
        raise ApiError(
            400,
            "no_public_ip",
            "Could not determine your public address. "
            "This check only works over a direct connection.",
        ) from err

    # Only ever probe a real, public address — never a private/NAT/loopback one.
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        raise ApiError(
            400,
            "not_public",
            "Your connection shows a private address, so there's nothing to check from the "
            "internet. That usually means your network is not directly exposed.",
        )

    results = await asyncio.gather(*[_is_open(address, port) for port, _, _ in CHECK_PORTS])
    open_ports = [
        OpenPort(port=port, service=service, note=note)
        for (port, service, note), is_open in zip(CHECK_PORTS, results, strict=True)
        if is_open
    ]

    record_event(db, request, user, "network.exposure", f"{len(open_ports)} open")

    if open_ports:
        message = (
            f"{len(open_ports)} port(s) on your network are reachable from the internet. "
            "Review each one and close any you didn't intend to open."
        )
    else:
        message = "None of the checked ports are reachable from the internet."
    return ExposureResult(
        address=address, checked=len(CHECK_PORTS), open_ports=open_ports, message=message
    )
