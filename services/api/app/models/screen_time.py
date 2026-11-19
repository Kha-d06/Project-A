"""Daily browsing minutes reported by a linked browser extension, for family
screen time. Only a number per local day is kept: never sites, pages or times."""

import uuid
from datetime import date, datetime

from sqlalchemy import ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class ScreenTimeDay(Base):
    __tablename__ = "screen_time_days"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    # The day in the device's own local time, as the extension reports it.
    day: Mapped[date] = mapped_column(primary_key=True)
    minutes: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)
