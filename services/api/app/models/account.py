import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class AccountToken(Base):
    """Single-use links sent by email (verification, password reset). Stored as digests."""

    __tablename__ = "account_tokens"

    token_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    purpose: Mapped[str] = mapped_column(String(20))
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]


class BackupCode(Base):
    """One-time codes for signing in when the authenticator app is unavailable."""

    __tablename__ = "backup_codes"

    code_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    used_at: Mapped[datetime | None]


class OutboxEmail(Base):
    """Development and test mail sink: messages are stored here instead of sent."""

    __tablename__ = "outbox_emails"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    recipient: Mapped[str] = mapped_column(String(320), index=True)
    subject: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
