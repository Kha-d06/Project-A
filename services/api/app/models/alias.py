"""Disposable email aliases: an address that forwards to the account's inbox.

The operator's own mail server receives and forwards the mail; Qalaa only
says where an alias goes (app/api/aliases.py, relay endpoint). Message bodies
and headers never reach Qalaa. A deleted alias is kept as a tombstone so its
address can never be issued again (to anyone) and stays rejected.
"""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class EmailAlias(Base):
    __tablename__ = "email_aliases"
    __table_args__ = (UniqueConstraint("local_part", "domain", name="uq_email_alias_address"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    local_part: Mapped[str] = mapped_column(String(64))
    domain: Mapped[str] = mapped_column(String(253))
    # What it's for, e.g. the site it was made for ("shop.example").
    label: Mapped[str | None] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    paused_at: Mapped[datetime | None]
    deleted_at: Mapped[datetime | None]
    forwarded_count: Mapped[int] = mapped_column(default=0)
    blocked_count: Mapped[int] = mapped_column(default=0)
    last_forwarded_at: Mapped[datetime | None]

    @property
    def address(self) -> str:
        return f"{self.local_part}@{self.domain}"
