"""Devices allowed to connect to the self-hosted WireGuard VPN.

Only public keys are stored. Each device's private key is generated in the
browser and never reaches the server."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class VpnPeer(Base):
    __tablename__ = "vpn_peers"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(80))
    # Base64 of a 32-byte Curve25519 public key.
    public_key: Mapped[str] = mapped_column(String(44), unique=True)
    # The device's address inside the tunnel, e.g. 10.13.13.7.
    address: Mapped[str] = mapped_column(String(45), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    # Reported by the VPN server: last successful handshake and bytes moved.
    last_handshake_at: Mapped[datetime | None] = mapped_column(default=None)
    received_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    sent_bytes: Mapped[int] = mapped_column(BigInteger, default=0)


class VpnServer(Base):
    """The WireGuard server's public key and when it last checked in (one row)."""

    __tablename__ = "vpn_server"

    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    public_key: Mapped[str] = mapped_column(String(44))
    last_sync_at: Mapped[datetime] = mapped_column(default=utcnow)
