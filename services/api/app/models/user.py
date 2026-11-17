import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(80))
    role: Mapped[str] = mapped_column(String(20), default="user")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    # Set by an administrator; a disabled account cannot sign in.
    disabled_at: Mapped[datetime | None]
    email_verified_at: Mapped[datetime | None]
    # Authenticator-app secret, encrypted with a key derived from SENTINEL_SECRET_KEY.
    totp_secret_encrypted: Mapped[str | None] = mapped_column(String(255))
    totp_enabled_at: Mapped[datetime | None]
    # Security-assessment (owned-site scanning) entitlement, granted by an admin.
    # Null means the feature is off for this account.
    assessment_enabled_at: Mapped[datetime | None]
    assessment_domain_limit: Mapped[int] = mapped_column(default=3)
    assessment_monthly_limit: Mapped[int] = mapped_column(default=20)

    @property
    def assessment_enabled(self) -> bool:
        return self.assessment_enabled_at is not None

    settings: Mapped["UserSettings"] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False
    )
    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class UserSettings(Base):
    __tablename__ = "user_settings"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    # When off, scans submitted while signed in are not attached to the account.
    save_scan_history: Mapped[bool] = mapped_column(default=True)
    # Off by default: linked extensions only record warnings to the account if asked to.
    sync_extension_events: Mapped[bool] = mapped_column(default=False, server_default="false")
    # Opt-in: a weekly email summarising warnings and scans.
    weekly_summary: Mapped[bool] = mapped_column(default=False, server_default="false")
    # Opt-in: re-check the account's email address for new breaches every week.
    breach_monitoring: Mapped[bool] = mapped_column(default=False, server_default="false")
    # Names of breaches already reported, so only new ones are announced.
    known_breaches: Mapped[list[Any]] = mapped_column(default=list)

    user: Mapped[User] = relationship(back_populates="settings")


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_digest: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(index=True)

    user: Mapped[User] = relationship(back_populates="sessions")
