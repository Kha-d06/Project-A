"""Security assessments of websites an account has proven it owns.

The hard rule of this feature: SENTINEL only ever probes a domain the account
has verified it controls, and verification is checked again at scan time. A
verified domain that changes hands, or whose token is removed, can no longer be
scanned. The checks themselves are read-only (see app/assess/checks.py)."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow

VERIFY_METHODS = ("dns", "file")
SCHEDULES = ("off", "weekly", "monthly")
ASSESSMENT_STATUSES = ("queued", "running", "completed", "failed")
# Worst finding severity seen, used as the headline. Never "secure": the best
# outcome is "no_issues", meaning nothing was found by the checks that ran.
ASSESSMENT_RESULTS = ("critical", "high", "medium", "low", "no_issues", "inconclusive")


def _one_of(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


class VerifiedDomain(Base):
    __tablename__ = "verified_domains"
    __table_args__ = (
        CheckConstraint(
            f"verified_method IS NULL OR {_one_of('verified_method', VERIFY_METHODS)}",
            name="verify_method_valid",
        ),
        Index("ix_verified_domains_user_domain", "user_id", "domain", unique=True),
        CheckConstraint(_one_of("schedule", SCHEDULES), name="schedule_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # The registrable host, lower-cased, e.g. "example.com". No scheme or path.
    domain: Mapped[str] = mapped_column(String(253))
    # The exact token the owner must publish, in DNS TXT or the well-known file.
    token: Mapped[str] = mapped_column(String(80))
    verified_method: Mapped[str | None] = mapped_column(String(10))
    verified_at: Mapped[datetime | None]
    last_checked_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    # Automatic re-assessment: "off", "weekly" or "monthly". The owner is emailed
    # when a scheduled result is worse than the previous one.
    schedule: Mapped[str] = mapped_column(String(10), default="off", server_default="off")
    next_run_at: Mapped[datetime | None]

    assessments: Mapped[list["Assessment"]] = relationship(
        back_populates="domain_ref", cascade="all, delete-orphan"
    )


class Assessment(Base):
    __tablename__ = "assessments"
    __table_args__ = (
        CheckConstraint(_one_of("status", ASSESSMENT_STATUSES), name="assessment_status_valid"),
        CheckConstraint(
            f"result IS NULL OR {_one_of('result', ASSESSMENT_RESULTS)}",
            name="assessment_result_valid",
        ),
        Index("ix_assessments_user_created", "user_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("verified_domains.id", ondelete="CASCADE")
    )
    # Denormalised so a finished report still reads clearly if the domain is removed.
    domain: Mapped[str] = mapped_column(String(253))
    status: Mapped[str] = mapped_column(String(20), default="queued")
    result: Mapped[str | None] = mapped_column(String(20))
    summary: Mapped[str | None] = mapped_column(Text)
    # [{severity, category, title, explanation, evidence, recommendation}]
    findings: Mapped[list[Any]] = mapped_column(default=list)
    # [{key, label, status, detail}] — every check attempted, findings or not.
    checks: Mapped[list[Any]] = mapped_column(default=list)
    pages_checked: Mapped[int] = mapped_column(Integer, default=0)
    # Light active tests, run only when the owner confirmed them for this scan.
    active_probes: Mapped[bool] = mapped_column(default=False, server_default="false")
    scheduled: Mapped[bool] = mapped_column(default=False, server_default="false")
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]

    domain_ref: Mapped["VerifiedDomain"] = relationship(back_populates="assessments")
