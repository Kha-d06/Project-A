import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow

SCAN_TYPES = ("url", "message", "file")
SCAN_STATUSES = ("queued", "processing", "completed", "failed", "inconclusive")
RISK_LEVELS = ("known_malicious", "suspicious", "no_known_threat", "inconclusive")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _one_of(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        CheckConstraint(_one_of("scan_type", SCAN_TYPES), name="scan_type_valid"),
        CheckConstraint(_one_of("status", SCAN_STATUSES), name="status_valid"),
        CheckConstraint(f"risk IS NULL OR {_one_of('risk', RISK_LEVELS)}", name="risk_valid"),
        Index("ix_scan_jobs_user_id_created_at", "user_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    scan_type: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="queued")

    # Short label shown in history lists: the URL, the file name, or a message excerpt.
    target: Mapped[str] = mapped_column(String(300))
    # What the analyzer needs to do its work. Cleared of bulky or sensitive content
    # (message text, storage paths) once the scan finishes.
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict)

    risk: Mapped[str | None] = mapped_column(String(20))
    confidence: Mapped[str | None] = mapped_column(String(10))
    summary: Mapped[str | None] = mapped_column(Text)
    checks: Mapped[list[Any]] = mapped_column(default=list)
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    recommendations: Mapped[list[Any]] = mapped_column(default=list)
    limitations: Mapped[list[Any]] = mapped_column(default=list)
    error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None]
    completed_at: Mapped[datetime | None]

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="Finding.position"
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (CheckConstraint(_one_of("severity", SEVERITIES), name="severity_valid"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int]
    severity: Mapped[str] = mapped_column(String(10))
    category: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(200))
    explanation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)
    source: Mapped[str] = mapped_column(String(80))

    scan: Mapped[ScanJob] = relationship(back_populates="findings")
