import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class ExtensionInstallation(Base):
    """One enrolled copy of the browser extension. Anonymous unless linked to a user."""

    __tablename__ = "extension_installations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    refresh_digest: Mapped[str] = mapped_column(String(64), unique=True)
    browser: Mapped[str] = mapped_column(String(40))
    version: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    revoked_at: Mapped[datetime | None]


class ExtensionLinkCode(Base):
    """Short-lived, single-use code a signed-in user gives to the extension to link it."""

    __tablename__ = "extension_link_codes"

    code_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]


class ExtensionEvent(Base):
    """A protection event the user chose to sync. Only the host is kept, never the full URL."""

    __tablename__ = "extension_events"
    __table_args__ = (Index("ix_extension_events_user_id_created_at", "user_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("extension_installations.id", ondelete="CASCADE")
    )
    kind: Mapped[str] = mapped_column(String(30))
    host: Mapped[str] = mapped_column(String(255))
    verdict: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
