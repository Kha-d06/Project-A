import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow

INDICATOR_KINDS = ("url", "host", "sha256", "phone")


class ThreatSource(Base):
    """A feed we import indicators from, with the outcome of its latest refresh."""

    __tablename__ = "threat_sources"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(40), unique=True)
    name: Mapped[str] = mapped_column(String(80))
    last_attempt_at: Mapped[datetime | None]
    last_success_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)
    indicator_count: Mapped[int] = mapped_column(default=0)

    indicators: Mapped[list["ThreatIndicator"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint("source_id", "kind", "value_digest"),
        Index("ix_threat_indicators_kind_value_digest", "kind", "value_digest"),
        # k-anonymous hash lookups: "value LIKE 'abc123%'" over SHA-256 rows only.
        Index(
            "ix_threat_indicators_sha256_prefix",
            "value",
            postgresql_where=text("kind = 'sha256'"),
            postgresql_ops={"value": "text_pattern_ops"},
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("threat_sources.id", ondelete="CASCADE")
    )
    kind: Mapped[str] = mapped_column(String(10))
    value: Mapped[str] = mapped_column(Text)
    # URLs can exceed index size limits, so lookups go through a fixed-length digest.
    value_digest: Mapped[str] = mapped_column(String(64))
    # Host part of url and host indicators, so a domain lookup finds every listed
    # address on it.
    host: Mapped[str | None] = mapped_column(String(255), index=True)
    threat: Mapped[str | None] = mapped_column(String(80))
    tags: Mapped[str | None] = mapped_column(String(300))
    reference_url: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime | None]
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)

    source: Mapped[ThreatSource] = relationship(back_populates="indicators")
