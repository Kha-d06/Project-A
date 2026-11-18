"""Extra email addresses a person asks Qalaa to watch for data breaches.

An address is monitored only after its owner proves they receive mail there
(a one-time code), so nobody can monitor someone else's address."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class MonitoredIdentity(Base):
    __tablename__ = "monitored_identities"
    __table_args__ = (UniqueConstraint("user_id", "value", name="uq_monitored_identity"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(10), default="email")
    value: Mapped[str] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    verified_at: Mapped[datetime | None]
    # Digest of the confirmation code; cleared once confirmed.
    code_digest: Mapped[str | None] = mapped_column(String(64))
    code_expires_at: Mapped[datetime | None]
    code_attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    last_checked_at: Mapped[datetime | None]
    # Breach names already reported for this address, and the full current list.
    known_breaches: Mapped[list[Any]] = mapped_column(default=list)
