import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow

REPORT_CATEGORIES = (
    "website",
    "scam_message",
    "job_offer",
    "fraudulent_app",
    "phone_number",
    "social_account",
)
REPORT_STATUSES = ("pending", "verified", "rejected", "duplicate")


def _one_of(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


class CommunityReport(Base):
    """A user's report of a scam. Unverified until a moderator reviews it."""

    __tablename__ = "community_reports"
    __table_args__ = (
        CheckConstraint(_one_of("category", REPORT_CATEGORIES), name="category_valid"),
        CheckConstraint(_one_of("status", REPORT_STATUSES), name="status_valid"),
        Index("ix_community_reports_status_created_at", "status", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # Null for anonymous reports, and kept null even if the reporter later deletes
    # their account, so the report survives without pointing at anyone.
    reporter_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    # Lets an anonymous reporter check on their report without an account.
    tracking_digest: Mapped[str | None] = mapped_column(String(64), unique=True)
    category: Mapped[str] = mapped_column(String(20))
    subject: Mapped[str] = mapped_column(String(500))
    # Normalised form of the subject, for duplicate detection.
    subject_key: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)

    status: Mapped[str] = mapped_column(String(20), default="pending")
    duplicate_of_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("community_reports.id", ondelete="SET NULL")
    )
    moderator_note: Mapped[str | None] = mapped_column(Text)
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_at: Mapped[datetime | None]
    # A verification is not forever: scam sites move and numbers get reassigned.
    # When this passes, the indicator is withdrawn until a moderator verifies again.
    verification_expires_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
