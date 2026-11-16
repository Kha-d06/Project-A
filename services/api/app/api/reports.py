import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Request
from sqlalchemy import func, select

from app.api.auth import record_event
from app.api.deps import Db, ModeratorUser, OptionalUser, RequiredUser
from app.community.service import mask_phone, normalize_subject, review, similar_count, subject_key
from app.core import rate_limit
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, client_address
from app.core.security import new_token, token_digest
from app.models import CommunityReport
from app.schemas.community import (
    Category,
    ModerationItem,
    PublicReport,
    ReportCreate,
    ReportCreated,
    ReportOut,
    ReportStatus,
    ReviewRequest,
)

router = APIRouter(tags=["Community reports"])

REPORT_LIMIT = RateLimit("report", max_requests=10, window_seconds=3600)
_NOT_FOUND = "This report does not exist, or you do not have access to it."


@router.post("/reports", response_model=ReportCreated, status_code=201)
def create_report(
    body: ReportCreate, request: Request, db: Db, user: OptionalUser
) -> ReportCreated:
    rate_limit.enforce(REPORT_LIMIT, f"user:{user.id}" if user else f"ip:{client_address(request)}")
    normalized = normalize_subject(body.category, body.subject)
    key = subject_key(body.category, normalized)
    attach = user is not None and not body.anonymous
    token = None if attach else new_token()
    report = CommunityReport(
        reporter_id=user.id if attach and user else None,
        tracking_digest=token_digest(token) if token else None,
        category=body.category,
        subject=normalized,
        subject_key=key,
        description=body.description,
        evidence=body.evidence or None,
    )
    db.add(report)
    db.commit()
    return ReportCreated(
        report=ReportOut.model_validate(report),
        tracking_token=token,
        similar_reports=similar_count(db, key, excluding=report.id),
    )


@router.get("/reports", response_model=list[PublicReport])
def public_reports(
    db: Db,
    category: Category | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[PublicReport]:
    """Only moderator-verified reports, and only what was reported, never by whom or
    the reporter's own words."""
    query = (
        select(
            CommunityReport.category,
            CommunityReport.subject,
            func.count(),
            func.max(CommunityReport.reviewed_at),
        )
        .where(CommunityReport.status == "verified")
        .group_by(CommunityReport.category, CommunityReport.subject)
        .order_by(func.max(CommunityReport.reviewed_at).desc())
        .limit(limit)
    )
    if category:
        query = query.where(CommunityReport.category == category)
    return [
        PublicReport(
            category=row_category,
            subject=mask_phone(subject) if row_category == "phone_number" else subject,
            reports=count,
            verified_at=verified_at,
        )
        for row_category, subject, count, verified_at in db.execute(query).all()
    ]


@router.get("/reports/mine", response_model=list[ReportOut])
def my_reports(db: Db, user: RequiredUser) -> list[CommunityReport]:
    return list(
        db.scalars(
            select(CommunityReport)
            .where(CommunityReport.reporter_id == user.id)
            .order_by(CommunityReport.created_at.desc())
        )
    )


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(
    report_id: uuid.UUID, db: Db, user: OptionalUser, token: str | None = None
) -> CommunityReport:
    report = db.get(CommunityReport, report_id)
    if report is None:
        raise ApiError(404, "report_not_found", _NOT_FOUND)
    is_owner = user is not None and report.reporter_id == user.id
    has_token = bool(token and report.tracking_digest == token_digest(token))
    is_moderator = user is not None and user.role in ("moderator", "admin")
    if not (is_owner or has_token or is_moderator):
        raise ApiError(404, "report_not_found", _NOT_FOUND)
    return report


# --- Moderation -------------------------------------------------------------------


@router.get("/admin/reports", response_model=list[ModerationItem])
def moderation_queue(
    db: Db,
    moderator: ModeratorUser,
    status: ReportStatus = "pending",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ModerationItem]:
    reports = db.scalars(
        select(CommunityReport)
        .where(CommunityReport.status == status)
        .order_by(CommunityReport.created_at)
        .limit(limit)
    ).all()
    return [
        ModerationItem.model_validate(
            {
                **ReportOut.model_validate(report).model_dump(),
                "similar_reports": similar_count(db, report.subject_key, excluding=report.id),
                "anonymous": report.reporter_id is None,
            }
        )
        for report in reports
    ]


@router.post("/admin/reports/{report_id}/review", response_model=ReportOut)
def review_report(
    report_id: uuid.UUID, body: ReviewRequest, request: Request, db: Db, moderator: ModeratorUser
) -> CommunityReport:
    report = db.get(CommunityReport, report_id)
    if report is None:
        raise ApiError(404, "report_not_found", _NOT_FOUND)
    record_event(
        db, request, moderator, f"report_{body.status}", f"{report.category}: {report.subject}"
    )
    return review(db, report, moderator, body.status, body.note, body.duplicate_of)
