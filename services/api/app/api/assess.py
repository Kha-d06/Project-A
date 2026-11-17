"""Security assessment of websites the account owns.

Access is granted per account by an administrator (the "subscription"). Within
that, a domain must be verified — proven to belong to the account — before it
can be scanned, and ownership is re-checked at scan time. The checks are
read-only (see app/assess/checks.py). This is a tool for owners to audit their
own sites, never for scanning third parties.
"""

import contextlib
import ipaddress
import re
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.auth import record_event
from app.api.deps import Db, SessionUser
from app.assess import runner, verify
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.models import Assessment, User, VerifiedDomain
from app.models.base import utcnow

router = APIRouter(prefix="/assess", tags=["Security assessment"])

ADD_DOMAIN_LIMIT = RateLimit("assess-add-domain", max_requests=20, window_seconds=3600)
VERIFY_LIMIT = RateLimit("assess-verify", max_requests=60, window_seconds=3600)
SCAN_LIMIT = RateLimit("assess-scan", max_requests=40, window_seconds=3600)

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_RESERVED_SUFFIXES = (".local", ".internal", ".localhost", ".test", ".example", ".invalid")


def _normalise_domain(value: str) -> str:
    text = value.strip().lower()
    text = re.sub(r"^[a-z]+://", "", text)  # drop any scheme
    text = text.split("/")[0].split("?")[0]  # drop any path or query
    text = text.split("@")[-1]  # drop any userinfo
    if ":" in text:
        text = text.split(":")[0]  # drop any port
    text = text.strip(".")
    if text.startswith("www."):
        text = text[4:]
    with contextlib.suppress(UnicodeError, ValueError):
        text = text.encode("idna").decode("ascii")  # internationalised domains
    if not _DOMAIN_RE.match(text):
        raise ApiError(
            422, "invalid_domain", "Enter a domain like example.com, without http:// or a path."
        )
    try:
        ipaddress.ip_address(text)
        raise ApiError(422, "invalid_domain", "Enter a domain name, not an IP address.")
    except ValueError:
        pass
    if text == "localhost" or text.endswith(_RESERVED_SUFFIXES):
        raise ApiError(422, "invalid_domain", "That is not a public domain you can verify.")
    return text


def _entitled(user: User) -> bool:
    return user.role == "admin" or user.assessment_enabled_at is not None


def _require_entitled(user: User) -> None:
    if not _entitled(user):
        raise ApiError(
            403,
            "assessment_not_enabled",
            "Security assessment is not enabled on your account. Ask an administrator to turn it on.",
        )


class DomainIn(BaseModel):
    domain: Annotated[str, Field(min_length=3, max_length=253)]


class DomainOut(BaseModel):
    id: uuid.UUID
    domain: str
    verified: bool
    verified_method: str | None
    verified_at: Any
    created_at: Any


class VerificationInstructions(BaseModel):
    domain: DomainOut
    token: str
    dns_name: str
    dns_type: str
    dns_value: str
    file_url: str
    file_content: str


class AssessmentSummary(BaseModel):
    id: uuid.UUID
    domain: str
    status: str
    result: str | None
    summary: str | None
    finding_count: int
    pages_checked: int
    created_at: Any
    finished_at: Any


class AssessmentDetail(AssessmentSummary):
    findings: list[dict[str, Any]]
    checks: list[dict[str, Any]]
    error: str | None


class AssessmentStatus(BaseModel):
    enabled: bool
    domain_limit: int
    monthly_limit: int
    used_this_month: int
    domains: list[DomainOut]
    recent: list[AssessmentSummary]


def _domain_out(d: VerifiedDomain) -> DomainOut:
    return DomainOut(
        id=d.id,
        domain=d.domain,
        verified=d.verified_at is not None,
        verified_method=d.verified_method,
        verified_at=d.verified_at,
        created_at=d.created_at,
    )


def _summary(a: Assessment) -> AssessmentSummary:
    return AssessmentSummary(
        id=a.id,
        domain=a.domain,
        status=a.status,
        result=a.result,
        summary=a.summary,
        finding_count=len(a.findings),
        pages_checked=a.pages_checked,
        created_at=a.created_at,
        finished_at=a.finished_at,
    )


def _instructions(d: VerifiedDomain) -> VerificationInstructions:
    return VerificationInstructions(
        domain=_domain_out(d),
        token=d.token,
        dns_name=d.domain,
        dns_type="TXT",
        dns_value=d.token,
        file_url=f"https://{d.domain}{verify.VERIFICATION_PATH}",
        file_content=d.token,
    )


@router.get("", response_model=AssessmentStatus)
def status(db: Db, user: SessionUser) -> AssessmentStatus:
    _require_entitled(user)
    domains = db.scalars(
        select(VerifiedDomain)
        .where(VerifiedDomain.user_id == user.id)
        .order_by(VerifiedDomain.created_at)
    ).all()
    recent = db.scalars(
        select(Assessment)
        .where(Assessment.user_id == user.id)
        .order_by(Assessment.created_at.desc())
        .limit(20)
    ).all()
    return AssessmentStatus(
        enabled=True,
        domain_limit=user.assessment_domain_limit,
        monthly_limit=user.assessment_monthly_limit,
        used_this_month=runner.recent_count(db, user.id, runner.month_start()),
        domains=[_domain_out(d) for d in domains],
        recent=[_summary(a) for a in recent],
    )


@router.post("/domains", response_model=VerificationInstructions, status_code=201)
def add_domain(
    body: DomainIn, request: Request, db: Db, user: SessionUser
) -> VerificationInstructions:
    _require_entitled(user)
    rate_limit.enforce(ADD_DOMAIN_LIMIT, f"user:{user.id}")
    domain = _normalise_domain(body.domain)
    existing = db.scalar(
        select(VerifiedDomain).where(
            VerifiedDomain.user_id == user.id, VerifiedDomain.domain == domain
        )
    )
    if existing is not None:
        return _instructions(existing)
    count = (
        db.scalar(
            select(func.count())
            .select_from(VerifiedDomain)
            .where(VerifiedDomain.user_id == user.id)
        )
        or 0
    )
    if count >= user.assessment_domain_limit:
        raise ApiError(
            409,
            "domain_limit",
            f"You can add up to {user.assessment_domain_limit} domains. Remove one first.",
        )
    record = VerifiedDomain(user_id=user.id, domain=domain, token=verify.new_token())
    db.add(record)
    record_event(db, request, user, "assessment_domain_added", domain)
    db.commit()
    return _instructions(record)


def _owned_domain(db: Db, user: User, domain_id: uuid.UUID) -> VerifiedDomain:
    record = db.get(VerifiedDomain, domain_id)
    if record is None or record.user_id != user.id:
        raise ApiError(404, "not_found", "That domain is not on your account.")
    return record


@router.post("/domains/{domain_id}/verify", response_model=DomainOut)
def verify_domain(domain_id: uuid.UUID, db: Db, user: SessionUser) -> DomainOut:
    _require_entitled(user)
    rate_limit.enforce(VERIFY_LIMIT, f"user:{user.id}")
    record = _owned_domain(db, user, domain_id)
    method = verify.verify(record.domain, record.token)
    record.last_checked_at = utcnow()
    if method is None:
        record.verified_at = None
        record.verified_method = None
        db.commit()
        raise ApiError(
            400,
            "verification_failed",
            "We could not find the verification record yet. DNS changes can take a while to "
            "spread; check the record and try again in a few minutes.",
        )
    record.verified_at = utcnow()
    record.verified_method = method
    db.commit()
    return _domain_out(record)


@router.delete("/domains/{domain_id}", status_code=204)
def remove_domain(domain_id: uuid.UUID, request: Request, db: Db, user: SessionUser) -> None:
    _require_entitled(user)
    record = _owned_domain(db, user, domain_id)
    record_event(db, request, user, "assessment_domain_removed", record.domain)
    db.delete(record)
    db.commit()


@router.post("/domains/{domain_id}/scan", response_model=AssessmentDetail, status_code=201)
def start_scan(
    domain_id: uuid.UUID, request: Request, db: Db, user: SessionUser
) -> AssessmentDetail:
    _require_entitled(user)
    rate_limit.enforce(SCAN_LIMIT, f"user:{user.id}")
    record = _owned_domain(db, user, domain_id)
    if record.verified_at is None:
        raise ApiError(409, "not_verified", "Verify that you own this domain before scanning it.")
    active = db.scalar(
        select(Assessment).where(
            Assessment.domain_id == record.id, Assessment.status.in_(("queued", "running"))
        )
    )
    if active is not None:
        raise ApiError(409, "already_running", "An assessment of this domain is already running.")
    used = runner.recent_count(db, user.id, runner.month_start())
    if used >= user.assessment_monthly_limit:
        raise ApiError(
            429,
            "monthly_limit",
            f"You have used all {user.assessment_monthly_limit} assessments for this month.",
        )
    job = Assessment(user_id=user.id, domain_id=record.id, domain=record.domain, status="queued")
    db.add(job)
    record_event(db, request, user, "assessment_started", record.domain)
    db.commit()

    if get_settings().run_scans_inline:
        runner.run_assessment(db, job.id)
    else:
        from app.workers.tasks import run_assessment_task

        run_assessment_task.delay(str(job.id))
    db.refresh(job)
    return _detail(job)


def _detail(a: Assessment) -> AssessmentDetail:
    return AssessmentDetail(
        **_summary(a).model_dump(),
        findings=list(a.findings),
        checks=list(a.checks),
        error=a.error,
    )


@router.get("/assessments/{assessment_id}", response_model=AssessmentDetail)
def get_assessment(assessment_id: uuid.UUID, db: Db, user: SessionUser) -> AssessmentDetail:
    _require_entitled(user)
    job = db.get(Assessment, assessment_id)
    if job is None or job.user_id != user.id:
        raise ApiError(404, "not_found", "That assessment does not exist.")
    return _detail(job)
