"""End-to-end-encrypted password sharing and emergency access.

The server never sees any shared secret. Each user publishes an ECDH public
key; to share a login the sender encrypts it to the recipient's public key in
the browser and the server only relays the ciphertext. Emergency access works
the same way: the grantor wraps their vault key to a trusted contact's public
key ahead of time, and the server only enforces the time delay before handing
that ciphertext over.
"""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow

EMERGENCY_STATES = ("invited", "active", "requested", "denied")


def _one_of(column: str, values: tuple[str, ...]) -> str:
    joined = ", ".join(f"'{v}'" for v in values)
    return f"{column} in ({joined})"


class SharingKey(Base):
    """A user's public key for receiving shared logins (ECDH P-256, base64 SPKI)."""

    __tablename__ = "sharing_keys"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    public_key: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)


class VaultShare(Base):
    """One login shared from sender to recipient, encrypted to the recipient."""

    __tablename__ = "vault_shares"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    sender_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    recipient_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # The login payload (JSON), encrypted to the recipient's public key. Opaque here.
    ciphertext: Mapped[str] = mapped_column(Text)
    # Sender's ephemeral ECDH public key for this share (base64 SPKI).
    sender_ephemeral: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class EmergencyContact(Base):
    """A trusted contact who can reach the grantor's vault after a time delay."""

    __tablename__ = "emergency_contacts"
    __table_args__ = (
        CheckConstraint(_one_of("state", EMERGENCY_STATES), name="emergency_state_valid"),
        UniqueConstraint("grantor_id", "grantee_id", name="uq_emergency_pair"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    grantor_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    grantee_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # Hours the grantee must wait after requesting before access unlocks.
    wait_hours: Mapped[int] = mapped_column(Integer, default=48)
    state: Mapped[str] = mapped_column(String(12), default="invited")
    # The grantor's vault key, wrapped to the grantee's public key. Opaque here.
    wrapped_vault_key: Mapped[str] = mapped_column(Text)
    sender_ephemeral: Mapped[str] = mapped_column(String(500))
    requested_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
