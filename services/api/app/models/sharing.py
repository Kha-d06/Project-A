"""Shared report links, family and organisation groups, and webhooks."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow

GROUP_KINDS = ("family", "organisation")
GROUP_ROLES = ("owner", "admin", "member")
WEBHOOK_EVENTS = ("scan.completed", "scan.dangerous")


def _one_of(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


class ScanShare(Base):
    """A read-only link to one scan result. Either public (anyone with the link)
    or shared with a group (members only)."""

    __tablename__ = "scan_shares"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True
    )
    created_by_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    # Public links: the token's digest. Null for group shares.
    token_digest: Mapped[str | None] = mapped_column(String(64), unique=True)
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), index=True
    )
    # The submitted address, file name or message excerpt is hidden unless the
    # person sharing chooses to include it.
    include_target: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str | None] = mapped_column(String(300))
    views: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]


class Group(Base):
    __tablename__ = "groups"
    __table_args__ = (CheckConstraint(_one_of("kind", GROUP_KINDS), name="kind_valid"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    # Domains the owners and admins suggest blocking. Applied only in the browsers
    # of members who turned it on themselves.
    blocklist: Mapped[list[Any]] = mapped_column(default=list)
    # Rules set by owners and admins (see app/groups_policy.py). Like the block list,
    # they apply only to members who chose to follow the group's rules.
    policies: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default="{}")


class GroupMember(Base):
    __tablename__ = "group_members"
    __table_args__ = (CheckConstraint(_one_of("role", GROUP_ROLES), name="role_valid"),)

    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    role: Mapped[str] = mapped_column(String(10), default="member")
    # Opt-in, by the member themselves: let the group's owners and admins see
    # counts of this member's warnings (never the sites or messages).
    share_activity: Mapped[bool] = mapped_column(Boolean, default=False)
    # Opt-in, by the member: apply the group's block list in their linked browsers.
    apply_blocklist: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    joined_at: Mapped[datetime] = mapped_column(default=utcnow)


class GroupInvite(Base):
    __tablename__ = "group_invites"
    __table_args__ = (CheckConstraint(_one_of("role", GROUP_ROLES), name="role_valid"),)

    token_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), index=True
    )
    email: Mapped[str] = mapped_column(String(320))
    role: Mapped[str] = mapped_column(String(10), default="member")
    invited_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    accepted_at: Mapped[datetime | None]


class Webhook(Base):
    """Signed notifications to a URL of the user's choosing when their scans finish."""

    __tablename__ = "webhooks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    url: Mapped[str] = mapped_column(Text)
    # Encrypted at rest; shown to the user once, when the webhook is created.
    secret_encrypted: Mapped[str] = mapped_column(Text)
    events: Mapped[list[Any]] = mapped_column(default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_delivery_at: Mapped[datetime | None]
    last_status: Mapped[str | None] = mapped_column(String(120))
    consecutive_failures: Mapped[int] = mapped_column(default=0)
