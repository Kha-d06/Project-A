import re
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, File, Form, Query, Request, UploadFile

from app.ai.explain import ExplanationUnavailableError, explain
from app.api.deps import Db, OptionalUser, RequiredUser
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, client_address
from app.models import ScanJob, User
from app.models.base import utcnow
from app.scans import service
from app.scans.storage import delete_sample, store_sample
from app.schemas.scans import (
    ExplanationOut,
    MessageScanRequest,
    RiskLevel,
    ScanOut,
    ScanPage,
    ScanStatus,
    ScanSummary,
    ScanType,
    UrlScanRequest,
)

router = APIRouter(prefix="/scans", tags=["Scanning"])

# Resource-protection limits, identical for every visitor and every account.
SCAN_LIMIT = RateLimit("scan", max_requests=60, window_seconds=3600)
FILE_SCAN_LIMIT = RateLimit("scan-file", max_requests=20, window_seconds=3600)
WEBSITE_SCAN_LIMIT = RateLimit("scan-website", max_requests=30, window_seconds=3600)
EXPLANATION_LIMIT = RateLimit("explanation", max_requests=20, window_seconds=3600)

_MESSAGE_TARGET_LENGTH = 80
_UNSAFE_FILENAME_CHARS = re.compile(r"[\x00-\x1f\x7f/\\]")


def request_locale(request: Request) -> str:
    """Arabic if the page asked for it, English otherwise (the only two supported)."""
    return "ar" if request.headers.get("accept-language", "").lower().startswith("ar") else "en"


def _limit_subject(request: Request, user: User | None) -> str:
    return f"user:{user.id}" if user else f"ip:{client_address(request)}"


def _to_scan_out(job: ScanJob) -> ScanOut:
    return ScanOut.model_validate(
        {
            **{field: getattr(job, field) for field in ScanOut.model_fields if hasattr(job, field)},
            "saved_to_history": job.user_id is not None,
        }
    )


def _get_visible_scan(db: Db, scan_id: uuid.UUID, user: User | None) -> ScanJob:
    job = db.get(ScanJob, scan_id)
    # Scans attached to an account are private to it. Scans made without an account
    # can be opened by whoever holds the random scan ID.
    if job is None or (job.user_id is not None and (user is None or job.user_id != user.id)):
        raise ApiError(404, "scan_not_found", "This scan does not exist or has been deleted.")
    return job


@router.post("/url", response_model=ScanOut, status_code=202)
def scan_url(body: UrlScanRequest, request: Request, db: Db, user: OptionalUser) -> ScanOut:
    rate_limit.enforce(SCAN_LIMIT, _limit_subject(request, user))
    job = service.create_scan(
        db,
        scan_type="url",
        target=body.url,
        payload={"url": body.url},
        user=user,
        locale=request_locale(request),
    )
    return _to_scan_out(job)


@router.post("/message", response_model=ScanOut, status_code=202)
def scan_message(body: MessageScanRequest, request: Request, db: Db, user: OptionalUser) -> ScanOut:
    rate_limit.enforce(SCAN_LIMIT, _limit_subject(request, user))
    excerpt = " ".join(body.content.split())
    if len(excerpt) > _MESSAGE_TARGET_LENGTH:
        excerpt = excerpt[:_MESSAGE_TARGET_LENGTH].rstrip() + "…"
    job = service.create_scan(
        db,
        scan_type="message",
        target=excerpt,
        payload={"content": body.content, "ai_consent": body.ai_consent},
        user=user,
        locale=request_locale(request),
    )
    return _to_scan_out(job)


def _upload_scan(
    request: Request,
    db: Db,
    user: User | None,
    upload: UploadFile,
    scan_type: str,
    max_bytes: int,
    extra: dict[str, bool] | None = None,
) -> ScanOut:
    # The client's name is kept for display and extension checks only. It is never
    # used as a path: samples are stored under a random name.
    file_name = _UNSAFE_FILENAME_CHARS.sub("_", upload.filename or "unnamed")[-255:]
    storage_name, _size = store_sample(upload.file, max_bytes)
    try:
        job = service.create_scan(
            db,
            scan_type=scan_type,
            target=file_name,
            payload={"storage_name": storage_name, "file_name": file_name, **(extra or {})},
            user=user,
            locale=request_locale(request),
        )
    except Exception:
        delete_sample(storage_name)
        raise
    return _to_scan_out(job)


@router.post("/file", response_model=ScanOut, status_code=202)
def scan_file(
    request: Request,
    db: Db,
    user: OptionalUser,
    file: Annotated[UploadFile, File()],
    virustotal_consent: Annotated[bool, Form()] = False,
) -> ScanOut:
    rate_limit.enforce(FILE_SCAN_LIMIT, _limit_subject(request, user))
    # With consent, only the SHA-256 fingerprint is sent to VirusTotal, never the file.
    return _upload_scan(
        request,
        db,
        user,
        file,
        "file",
        get_settings().max_upload_bytes,
        {"virustotal_consent": virustotal_consent},
    )


@router.post("/qr", response_model=ScanOut, status_code=202)
def scan_qr(
    request: Request, db: Db, user: OptionalUser, file: Annotated[UploadFile, File()]
) -> ScanOut:
    """Decode a QR code from an image. The decoded link is checked, never opened."""
    rate_limit.enforce(FILE_SCAN_LIMIT, _limit_subject(request, user))
    return _upload_scan(request, db, user, file, "qr", get_settings().max_image_bytes)


@router.post("/apk", response_model=ScanOut, status_code=202)
def scan_apk(
    request: Request, db: Db, user: OptionalUser, file: Annotated[UploadFile, File()]
) -> ScanOut:
    rate_limit.enforce(FILE_SCAN_LIMIT, _limit_subject(request, user))
    return _upload_scan(request, db, user, file, "apk", get_settings().max_apk_bytes)


@router.post("/website", response_model=ScanOut, status_code=202)
def scan_website(body: UrlScanRequest, request: Request, db: Db, user: OptionalUser) -> ScanOut:
    """Link checks plus DNS and a static reading of the page itself."""
    rate_limit.enforce(SCAN_LIMIT, _limit_subject(request, user))
    rate_limit.enforce(WEBSITE_SCAN_LIMIT, _limit_subject(request, user))
    job = service.create_scan(
        db,
        scan_type="website",
        target=body.url,
        payload={"url": body.url},
        user=user,
        locale=request_locale(request),
    )
    return _to_scan_out(job)


@router.get("/history", response_model=ScanPage)
def scan_history(
    db: Db,
    user: RequiredUser,
    scan_type: Annotated[ScanType | None, Query(alias="type")] = None,
    risk: RiskLevel | None = None,
    status: ScanStatus | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> ScanPage:
    query = service.history_query(
        user.id, scan_type=scan_type, risk=risk, status=status, since=since, until=until
    )
    jobs = db.scalars(
        query.order_by(ScanJob.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return ScanPage(
        items=[ScanSummary.model_validate(job) for job in jobs],
        total=service.count(db, query),
        page=page,
        page_size=page_size,
    )


@router.delete("/history", status_code=204)
def clear_history(db: Db, user: RequiredUser) -> None:
    for job in db.scalars(service.history_query(user.id)).all():
        service.delete_scan(db, job)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: uuid.UUID, db: Db, user: OptionalUser) -> ScanOut:
    return _to_scan_out(_get_visible_scan(db, scan_id, user))


@router.post("/{scan_id}/explanation", response_model=ExplanationOut)
def explain_scan(
    scan_id: uuid.UUID, request: Request, db: Db, user: OptionalUser
) -> ExplanationOut:
    job = _get_visible_scan(db, scan_id, user)
    if job.status not in ("completed", "inconclusive"):
        raise ApiError(
            409, "scan_not_finished", "An explanation is available once the scan finishes."
        )
    if not job.ai_explanation:
        rate_limit.enforce(EXPLANATION_LIMIT, _limit_subject(request, user))
        try:
            result = explain(job)
        except ExplanationUnavailableError as exc:
            raise ApiError(503, "ai_unavailable", str(exc)) from exc
        job.ai_explanation = result.text
        job.ai_model = result.model
        job.ai_generated_at = utcnow()
        db.commit()
    return ExplanationOut(
        explanation=job.ai_explanation or "",
        model=job.ai_model or "",
        generated_at=job.ai_generated_at or utcnow(),
    )


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: uuid.UUID, db: Db, user: RequiredUser) -> None:
    job = _get_visible_scan(db, scan_id, user)
    if job.user_id != user.id:
        raise ApiError(404, "scan_not_found", "This scan does not exist or has been deleted.")
    service.delete_scan(db, job)
