"""Scheduled re-assessments and "your site got worse" emails.

A verified domain can be re-assessed weekly or monthly. Scheduled runs use the
same rules as one started by hand: ownership is confirmed again first, they count
towards the monthly limit, and they never run the active tests (those need the
owner to confirm each time).

When an assessment finishes, it is compared with the previous completed one for
the same domain. If new issues appeared or the overall result got worse, the owner
gets a plain-text email listing what changed.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assess import runner
from app.core.config import get_settings
from app.models import Assessment, User, VerifiedDomain
from app.notify.email import EmailUnavailableError, send_email

logger = logging.getLogger(__name__)

INTERVALS = {"weekly": timedelta(days=7), "monthly": timedelta(days=30)}
_RANK = {"no_issues": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def next_run(schedule: str, now: datetime | None = None) -> datetime | None:
    interval = INTERVALS.get(schedule)
    if interval is None:
        return None
    return (now or datetime.now(UTC)) + interval


def entitled(user: User) -> bool:
    return user.role == "admin" or user.assessment_enabled_at is not None


def dispatch(db: Session, assessment_id: uuid.UUID) -> None:
    """Run inline (tests, single-process setups) or hand to the isolated scan worker."""
    if get_settings().run_scans_inline:
        runner.run_assessment(db, assessment_id)
        after_assessment(db, assessment_id)
        return
    from app.workers.tasks import run_assessment_task

    run_assessment_task.delay(str(assessment_id))


def run_due(db: Session, now: datetime | None = None) -> int:
    """Start every scheduled assessment that is due. Returns how many were started."""
    now = now or datetime.now(UTC)
    due = db.scalars(
        select(VerifiedDomain).where(
            VerifiedDomain.schedule != "off",
            VerifiedDomain.next_run_at.is_not(None),
            VerifiedDomain.next_run_at <= now,
        )
    ).all()
    started: list[uuid.UUID] = []
    for domain in due:
        # Always move the next run forward, so a skipped domain is not retried every hour.
        domain.next_run_at = next_run(domain.schedule, now)
        user = db.get(User, domain.user_id)
        if user is None or user.disabled_at is not None or not entitled(user):
            continue
        if domain.verified_at is None:
            continue
        busy = db.scalar(
            select(Assessment.id).where(
                Assessment.domain_id == domain.id, Assessment.status.in_(("queued", "running"))
            )
        )
        if busy is not None:
            continue
        used = runner.recent_count(db, user.id, runner.month_start(now))
        if used >= user.assessment_monthly_limit:
            continue
        job = Assessment(
            user_id=user.id,
            domain_id=domain.id,
            domain=domain.domain,
            status="queued",
            scheduled=True,
        )
        db.add(job)
        db.flush()
        started.append(job.id)
    db.commit()
    for job_id in started:
        dispatch(db, job_id)
    return len(started)


def _issue_titles(job: Assessment) -> set[str]:
    return {
        str(f.get("title"))
        for f in job.findings
        if f.get("severity") != "info" and f.get("category") != "good_practice"
    }


def regression(previous: Assessment, current: Assessment) -> tuple[list[str], bool]:
    """(issues that are new this time, whether the overall result got worse)."""
    new = sorted(_issue_titles(current) - _issue_titles(previous))
    worse = _RANK.get(current.result or "", 0) > _RANK.get(previous.result or "", 0)
    return new, worse


def after_assessment(db: Session, assessment_id: uuid.UUID) -> None:
    """Runs in the task worker (full database access) once an assessment ends."""
    job = db.get(Assessment, assessment_id)
    if job is None:
        return
    user = db.get(User, job.user_id)
    if user is None or user.disabled_at is not None:
        return
    base = get_settings().public_url.rstrip("/")

    if job.status == "failed" and job.scheduled:
        _mail(
            db,
            user,
            f"Qalaa: scheduled assessment of {job.domain} could not run",
            f"The scheduled security assessment of {job.domain} did not run.\n\n"
            f"{job.error or 'An unknown error occurred.'}\n\n"
            f"Details: {base}/dashboard/assessment\n",
        )
        return
    if job.status != "completed":
        return

    previous = db.scalar(
        select(Assessment)
        .where(
            Assessment.domain_id == job.domain_id,
            Assessment.status == "completed",
            Assessment.id != job.id,
            Assessment.finished_at < job.finished_at,
        )
        .order_by(Assessment.finished_at.desc())
        .limit(1)
    )
    if previous is None:
        return
    new, worse = regression(previous, job)
    if not new and not worse:
        return
    lines = [f"The latest security assessment of {job.domain} found changes since the last one."]
    if worse:
        lines.append(f"Overall result: {previous.result} -> {job.result}.")
    if new:
        lines.append("New issues:")
        lines.extend(f"  - {title}" for title in new)
    lines.append("")
    lines.append(f"Full report and fixes: {base}/dashboard/assessment/report/{job.id}")
    lines.append("")
    lines.append("You get this email because you own this domain on Qalaa.")
    lines.append(f"Change or stop scheduled assessments at {base}/dashboard/assessment")
    _mail(db, user, f"Qalaa: {job.domain} has new security issues", "\n".join(lines) + "\n")


def _mail(db: Session, user: User, subject: str, body: str) -> None:
    with contextlib.suppress(EmailUnavailableError):
        send_email(db, user.email, subject, body)
