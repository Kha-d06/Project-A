"""Share links for scan results, and bulk link scanning."""

import uuid
from datetime import timedelta

from fastapi import APIRouter, Request
from sqlalchemy import select

from app.api.deps import Db, RequiredUser
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, client_address
from app.core.security import new_token, token_digest
from app.models import GroupMember, ScanJob, ScanShare
from app.models.base import utcnow
from app.scans import service
from app.schemas.scans import CheckOut, ScanSummary
from app.schemas.sharing import (
    BulkScanOut,
    BulkUrlRequest,
    ShareCreated,
    SharedFinding,
    SharedScan,
    ShareOut,
    ShareRequest,
)

router = APIRouter(tags=["Sharing and bulk scans"])

SHARE_VIEW_LIMIT = RateLimit("share-view", max_requests=300, window_seconds=3600)
SHARE_CREATE_LIMIT = RateLimit("share-create", max_requests=60, window_seconds=3600)
BULK_LIMIT = RateLimit("scan-bulk", max_requests=10, window_seconds=3600)
_GONE = "This shared result does not exist, has expired or was withdrawn."
_FINISHED = ("completed", "inconclusive", "failed")


def _owned_scan(db: Db, scan_id: uuid.UUID, user_id: uuid.UUID) -> ScanJob:
    job = db.get(ScanJob, scan_id)
    if job is None or job.user_id != user_id:
        raise ApiError(404, "scan_not_found", "This scan does not exist or has been deleted.")
    return job


def shared_view(scan: ScanJob, share: ScanShare) -> SharedScan:
    """The sharer decides whether the address, file name or message excerpt is
    included. Without it, evidence and technical details are left out too, since
    they can contain the same information."""
    full = share.include_target
    return SharedScan(
        scan_type=scan.scan_type,
        status=scan.status,
        risk=scan.risk,
        confidence=scan.confidence,
        summary=scan.summary,
        target=scan.target if full else None,
        findings=[
            SharedFinding(
                severity=f.severity,
                category=f.category,
                title=f.title,
                explanation=f.explanation,
                source=f.source,
                evidence=f.evidence if full else None,
            )
            for f in scan.findings
        ],
        checks=[CheckOut.model_validate(check) for check in scan.checks],
        recommendations=scan.recommendations,
        limitations=scan.limitations,
        details=scan.details if full else None,
        completed_at=scan.completed_at,
        note=share.note,
        shared_at=share.created_at,
        expires_at=share.expires_at,
    )


@router.post("/scans/{scan_id}/shares", response_model=ShareCreated, status_code=201)
def create_share(
    scan_id: uuid.UUID, body: ShareRequest, db: Db, user: RequiredUser
) -> ShareCreated:
    rate_limit.enforce(SHARE_CREATE_LIMIT, f"user:{user.id}")
    scan = _owned_scan(db, scan_id, user.id)
    if scan.status not in _FINISHED:
        raise ApiError(409, "scan_not_finished", "Results can be shared once the scan finishes.")
    token: str | None = None
    if body.group_id:
        member = db.get(GroupMember, (body.group_id, user.id))
        if member is None:
            raise ApiError(404, "group_not_found", "You are not a member of that group.")
    else:
        token = new_token()
    share = ScanShare(
        scan_id=scan.id,
        created_by_id=user.id,
        token_digest=token_digest(token) if token else None,
        group_id=body.group_id,
        include_target=body.include_target,
        note=body.note,
        expires_at=utcnow() + timedelta(days=body.expires_in_days),
    )
    db.add(share)
    db.commit()
    url = f"{get_settings().public_url.rstrip('/')}/shared/{token}" if token else None
    return ShareCreated.model_validate({**ShareOut.model_validate(share).model_dump(), "url": url})


@router.get("/scans/{scan_id}/shares", response_model=list[ShareOut])
def list_shares(scan_id: uuid.UUID, db: Db, user: RequiredUser) -> list[ScanShare]:
    _owned_scan(db, scan_id, user.id)
    return list(
        db.scalars(
            select(ScanShare)
            .where(ScanShare.scan_id == scan_id)
            .order_by(ScanShare.created_at.desc())
        )
    )


@router.delete("/shares/{share_id}", status_code=204)
def revoke_share(share_id: uuid.UUID, db: Db, user: RequiredUser) -> None:
    share = db.get(ScanShare, share_id)
    if share is None or share.created_by_id != user.id:
        raise ApiError(404, "share_not_found", "That share does not exist.")
    share.revoked_at = share.revoked_at or utcnow()
    db.commit()


@router.get("/shared/{token}", response_model=SharedScan)
def view_shared(token: str, request: Request, db: Db) -> SharedScan:
    """Public: anyone with the link. No account, no cookies needed."""
    rate_limit.enforce(SHARE_VIEW_LIMIT, client_address(request))
    share = db.scalar(select(ScanShare).where(ScanShare.token_digest == token_digest(token)))
    now = utcnow()
    if (
        share is None
        or share.revoked_at is not None
        or (share.expires_at is not None and share.expires_at < now)
    ):
        raise ApiError(404, "share_not_found", _GONE)
    scan = db.get(ScanJob, share.scan_id)
    if scan is None:
        raise ApiError(404, "share_not_found", _GONE)
    share.views += 1
    db.commit()
    return shared_view(scan, share)


@router.post("/scans/bulk", response_model=BulkScanOut, status_code=202)
def bulk_url_scan(
    body: BulkUrlRequest, request: Request, db: Db, user: RequiredUser
) -> BulkScanOut:
    """Up to 50 links in one call, for scripts and integrations (API keys work)."""
    rate_limit.enforce(BULK_LIMIT, f"user:{user.id}")
    jobs = [
        service.create_scan(
            db, scan_type="url", target=url, payload={"url": url}, user=user, locale="en"
        )
        for url in body.urls
    ]
    return BulkScanOut(scans=[ScanSummary.model_validate(job) for job in jobs])
