"""Self-hosted WireGuard VPN: devices, their configuration, and server sync.

- The browser generates each device's key pair and sends only the public key.
  The private key goes straight into the configuration the person downloads or
  scans, so the server cannot decrypt anyone's traffic captured elsewhere.
- The wireguard container polls `/vpn/sync` with a shared token. It reports
  its public key and per-peer traffic, and receives the list of allowed peers.
  A server that has not checked in for two minutes is shown as offline.
"""

import base64
import binascii
import hmac
import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Header, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from app.api.auth import record_event
from app.api.deps import Db, SessionUser
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.models import VpnPeer, VpnServer
from app.models.base import utcnow

router = APIRouter(prefix="/vpn", tags=["VPN"])

ADD_LIMIT = RateLimit("vpn-add", max_requests=20, window_seconds=3600)
SYNC_LIMIT = RateLimit("vpn-sync", max_requests=1200, window_seconds=3600)
SERVER_ONLINE_WINDOW = timedelta(minutes=2)
CONNECTED_WINDOW = timedelta(minutes=3)


def _check_key(value: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError("must be a base64 WireGuard key") from exc
    if len(raw) != 32 or len(value) != 44:
        raise ValueError("must be a 32-byte WireGuard key")
    return value


class PeerIn(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=80)]
    public_key: str

    _key = field_validator("public_key")(classmethod(lambda cls, v: _check_key(v)))


class PeerOut(BaseModel):
    id: Any
    name: str
    address: str
    created_at: Any
    last_handshake_at: Any
    connected: bool
    received_bytes: int
    sent_bytes: int


class VpnStatus(BaseModel):
    enabled: bool
    server_online: bool
    max_devices: int
    devices: list[PeerOut]


class PeerConfig(BaseModel):
    """Everything except the private key, which the browser adds itself."""

    peer: PeerOut
    address: str
    dns: str
    server_public_key: str
    endpoint: str
    allowed_ips: str


class PeerStats(BaseModel):
    public_key: str
    latest_handshake: int = Field(ge=0)
    received_bytes: int = Field(ge=0)
    sent_bytes: int = Field(ge=0)


class SyncIn(BaseModel):
    public_key: str
    peers: list[PeerStats] = Field(default_factory=list, max_length=100_000)

    _key = field_validator("public_key")(classmethod(lambda cls, v: _check_key(v)))


class SyncPeer(BaseModel):
    public_key: str
    address: str


def _enabled() -> bool:
    return bool(get_settings().vpn_endpoint)


def _require_enabled() -> None:
    if not _enabled():
        raise ApiError(
            404,
            "vpn_disabled",
            "This SENTINEL server does not run a VPN. Its operator can turn it on.",
        )


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _server(db: Db) -> VpnServer | None:
    server = db.get(VpnServer, 1)
    if server is None:
        return None
    last = _aware(server.last_sync_at)
    return server if last and utcnow() - last < SERVER_ONLINE_WINDOW else None


def _peer_out(peer: VpnPeer) -> PeerOut:
    handshake = _aware(peer.last_handshake_at)
    return PeerOut(
        id=peer.id,
        name=peer.name,
        address=peer.address,
        created_at=peer.created_at,
        last_handshake_at=handshake,
        connected=bool(handshake and utcnow() - handshake < CONNECTED_WINDOW),
        received_bytes=peer.received_bytes,
        sent_bytes=peer.sent_bytes,
    )


def _next_address(db: Db) -> str:
    network = ipaddress.ip_network(get_settings().vpn_subnet, strict=False)
    used = set(db.scalars(select(VpnPeer.address)).all())
    hosts = network.hosts()
    server_address = next(hosts)  # the first address belongs to the server
    for host in hosts:
        if str(host) not in used and host != server_address:
            return str(host)
    raise ApiError(
        409, "vpn_full", "The VPN has no free addresses left. Ask the operator to widen the subnet."
    )


@router.get("", response_model=VpnStatus)
def vpn_status(db: Db, user: SessionUser) -> VpnStatus:
    peers = db.scalars(
        select(VpnPeer).where(VpnPeer.user_id == user.id).order_by(VpnPeer.created_at)
    ).all()
    return VpnStatus(
        enabled=_enabled(),
        server_online=_enabled() and _server(db) is not None,
        max_devices=get_settings().vpn_max_peers_per_user,
        devices=[_peer_out(peer) for peer in peers],
    )


@router.post("/devices", response_model=PeerConfig, status_code=201)
def add_device(body: PeerIn, request: Request, db: Db, user: SessionUser) -> PeerConfig:
    _require_enabled()
    rate_limit.enforce(ADD_LIMIT, f"user:{user.id}")
    settings = get_settings()
    server = _server(db)
    if server is None:
        raise ApiError(
            503, "vpn_offline", "The VPN server is not running right now. Try again later."
        )
    count = (
        db.scalar(select(func.count()).select_from(VpnPeer).where(VpnPeer.user_id == user.id)) or 0
    )
    if count >= settings.vpn_max_peers_per_user:
        raise ApiError(
            409,
            "vpn_device_limit",
            f"You can add up to {settings.vpn_max_peers_per_user} VPN devices. Remove one first.",
        )
    if db.scalar(select(VpnPeer.id).where(VpnPeer.public_key == body.public_key)) is not None:
        raise ApiError(409, "vpn_key_in_use", "That key is already in use. Generate a new one.")
    peer = VpnPeer(
        user_id=user.id,
        name=body.name.strip(),
        public_key=body.public_key,
        address=_next_address(db),
    )
    db.add(peer)
    record_event(db, request, user, "vpn_device_added", peer.name)
    db.commit()
    return PeerConfig(
        peer=_peer_out(peer),
        address=f"{peer.address}/32",
        dns=settings.vpn_dns,
        server_public_key=server.public_key,
        endpoint=settings.vpn_endpoint or "",
        # All traffic through the tunnel. ::/0 is included even though the tunnel
        # carries no IPv6, so IPv6 traffic is dropped instead of leaking around it.
        allowed_ips="0.0.0.0/0, ::/0",
    )


@router.delete("/devices/{peer_id}", status_code=204)
def remove_device(peer_id: str, request: Request, db: Db, user: SessionUser) -> None:
    peer = next(
        (
            p
            for p in db.scalars(select(VpnPeer).where(VpnPeer.user_id == user.id))
            if str(p.id) == peer_id
        ),
        None,
    )
    if peer is None:
        raise ApiError(404, "not_found", "That VPN device does not exist.")
    record_event(db, request, user, "vpn_device_removed", peer.name)
    db.delete(peer)
    db.commit()


@router.post("/sync", response_model=list[SyncPeer], include_in_schema=False)
def sync(
    body: SyncIn, db: Db, authorization: Annotated[str | None, Header()] = None
) -> list[SyncPeer]:
    token = get_settings().vpn_sync_token
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not _enabled() or not token or not hmac.compare_digest(supplied.encode(), token.encode()):
        raise ApiError(401, "unauthorized", "Not allowed.")
    rate_limit.enforce(SYNC_LIMIT, "vpn-server")
    server = db.get(VpnServer, 1)
    if server is None:
        db.add(VpnServer(id=1, public_key=body.public_key, last_sync_at=utcnow()))
    else:
        server.public_key = body.public_key
        server.last_sync_at = utcnow()
    peers = db.scalars(select(VpnPeer)).all()
    stats = {item.public_key: item for item in body.peers}
    for peer in peers:
        reported = stats.get(peer.public_key)
        if reported is None:
            continue
        if reported.latest_handshake:
            peer.last_handshake_at = datetime.fromtimestamp(reported.latest_handshake, UTC)
        # WireGuard counters reset when the interface restarts; keep the larger total.
        peer.received_bytes = max(peer.received_bytes, reported.received_bytes)
        peer.sent_bytes = max(peer.sent_bytes, reported.sent_bytes)
    db.commit()
    return [SyncPeer(public_key=peer.public_key, address=peer.address) for peer in peers]
