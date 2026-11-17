"""Devices running SENTINEL apps (desktop, Android) linked to an account, and the
commands the account holder sends them from the website."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow

DEVICE_PLATFORMS = ("windows", "macos", "linux", "android")
COMMAND_KINDS = ("quick_scan", "full_scan", "folder_scan", "quarantine", "update_signatures")
COMMAND_STATUSES = ("queued", "sent", "running", "done", "failed", "expired")


def _one_of(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint(_one_of("platform", DEVICE_PLATFORMS), name="platform_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(80))
    platform: Mapped[str] = mapped_column(String(20))
    app_version: Mapped[str] = mapped_column(String(20))
    token_digest: Mapped[str] = mapped_column(String(64), unique=True)
    # Set on the device itself: whether scans may be started from the website.
    allow_remote: Mapped[bool] = mapped_column(Boolean, default=False)
    # Protection status the device reports with each heartbeat (no file contents).
    status: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Folders the device offers for remote folder scans: [{"id": ..., "label": ...}].
    folders: Mapped[list[Any]] = mapped_column(default=list)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    revoked_at: Mapped[datetime | None]


class DeviceCommand(Base):
    __tablename__ = "device_commands"
    __table_args__ = (
        CheckConstraint(_one_of("kind", COMMAND_KINDS), name="kind_valid"),
        CheckConstraint(_one_of("status", COMMAND_STATUSES), name="status_valid"),
        Index("ix_device_commands_device_id_status", "device_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String(20))
    args: Mapped[dict[str, Any]] = mapped_column(default=dict)
    status: Mapped[str] = mapped_column(String(10), default="queued")
    result: Mapped[dict[str, Any] | None]
    # Live counts while running: {"scanned": 120, "found": 0, "total": 400, "at": "..."}
    progress: Mapped[dict[str, Any] | None]
    error: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
