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
from sqlalchemy.orm import Session

from app.api.auth import record_event
from app.api.deps import Db, SessionUser
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.models import User, VpnPeer, VpnServer
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
    month_bytes: int = 0
    monthly_limit_bytes: int | None = None
    paused: bool = False
    # "active", "paused" or "limit_reached": whether the server lets it connect.
    state: str = "active"


class PeerUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    paused: bool | None = None
    # Monthly allowance in gigabytes (decimal GB); 0 removes the limit.
    monthly_limit_gb: float | None = Field(default=None, ge=0, le=100_000)


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
            "This Qalaa server does not run a VPN. Its operator can turn it on.",
        )


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _server(db: Session) -> VpnServer | None:
    server = db.get(VpnServer, 1)
    if server is None:
        return None
    last = _aware(server.last_sync_at)
    return server if last and utcnow() - last < SERVER_ONLINE_WINDOW else None


def _month(now: datetime | None = None) -> str:
    return (now or utcnow()).strftime("%Y-%m")


def _month_usage(peer: VpnPeer) -> int:
    return peer.month_bytes if peer.usage_month == _month() else 0


def _state(peer: VpnPeer) -> str:
    if peer.paused:
        return "paused"
    if peer.monthly_limit_bytes and _month_usage(peer) >= peer.monthly_limit_bytes:
        return "limit_reached"
    return "active"


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
        month_bytes=_month_usage(peer),
        monthly_limit_bytes=peer.monthly_limit_bytes,
        paused=peer.paused,
        state=_state(peer),
    )


def _next_address(db: Session) -> str:
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
    config = create_peer(db, user, body.name, body.public_key)
    record_event(db, request, user, "vpn_device_added", config.peer.name)
    db.commit()
    return config


def create_peer(db: Session, user: User, name: str, public_key: str) -> PeerConfig:
    """Adds a VPN device for `user` (not committed). Raises ApiError when the VPN is
    offline, the account is at its device limit, or the key is already in use."""
    _require_enabled()
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
    if db.scalar(select(VpnPeer.id).where(VpnPeer.public_key == public_key)) is not None:
        raise ApiError(409, "vpn_key_in_use", "That key is already in use. Generate a new one.")
    peer = VpnPeer(
        user_id=user.id,
        name=name.strip()[:80],
        public_key=public_key,
        address=_next_address(db),
    )
    db.add(peer)
    db.flush()
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


def _owned_peer(db: Db, peer_id: str, user_id: object) -> VpnPeer:
    peer = next(
        (
            p
            for p in db.scalars(select(VpnPeer).where(VpnPeer.user_id == user_id))
            if str(p.id) == peer_id
        ),
        None,
    )
    if peer is None:
        raise ApiError(404, "not_found", "That VPN device does not exist.")
    return peer


@router.patch("/devices/{peer_id}", response_model=PeerOut)
def update_device(
    peer_id: str, body: PeerUpdate, request: Request, db: Db, user: SessionUser
) -> PeerOut:
    peer = _owned_peer(db, peer_id, user.id)
    if body.name is not None:
        peer.name = body.name.strip()
    if body.paused is not None and body.paused != peer.paused:
        peer.paused = body.paused
        record_event(
            db,
            request,
            user,
            "vpn_device_paused" if body.paused else "vpn_device_resumed",
            peer.name,
        )
    if body.monthly_limit_gb is not None:
        peer.monthly_limit_bytes = int(body.monthly_limit_gb * 1_000_000_000) or None
        record_event(db, request, user, "vpn_device_limit", peer.name)
    db.commit()
    return _peer_out(peer)


@router.delete("/devices/{peer_id}", status_code=204)
def remove_device(peer_id: str, request: Request, db: Db, user: SessionUser) -> None:
    peer = _owned_peer(db, peer_id, user.id)
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
    month = _month()
    for peer in peers:
        reported = stats.get(peer.public_key)
        if reported is None:
            # Not on the server (new, paused or over its limit): its counters start
            # again from zero when it is next added.
            peer.counter_received = 0
            peer.counter_sent = 0
            continue
        if reported.latest_handshake:
            peer.last_handshake_at = datetime.fromtimestamp(reported.latest_handshake, UTC)
        received = _delta(reported.received_bytes, peer.counter_received)
        sent = _delta(reported.sent_bytes, peer.counter_sent)
        peer.counter_received = reported.received_bytes
        peer.counter_sent = reported.sent_bytes
        peer.received_bytes += received
        peer.sent_bytes += sent
        if peer.usage_month != month:
            peer.usage_month = month
            peer.month_bytes = 0
        peer.month_bytes += received + sent
    db.commit()
    # Paused devices and those over their monthly allowance are left out, so the
    # server removes them (wg syncconf) until they are resumed or the month ends.
    return [
        SyncPeer(public_key=peer.public_key, address=peer.address)
        for peer in peers
        if _state(peer) == "active"
    ]


def _delta(current: int, previous: int) -> int:
    """Bytes since the last sync. A smaller counter means the interface restarted."""
    return current - previous if current >= previous else current
