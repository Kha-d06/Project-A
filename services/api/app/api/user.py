from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Request, Response
from sqlalchemy import func, select

from app.api.auth import clear_session_cookie, record_event
from app.api.deps import CurrentSession, Db, RequiredUser
from app.core import rate_limit
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.core.security import hash_password, verify_password
from app.models import AuditEvent, ExtensionEvent, ExtensionInstallation, ScanJob, UserSession
from app.models.base import utcnow
from app.scans import service
from app.schemas.auth import (
    AccountDeletion,
    ActivityOut,
    PasswordChange,
    ProfileOut,
    SettingsOut,
    SettingsUpdate,
    UserOut,
)
from app.schemas.scans import DayCount, OverviewOut, ScanOut, ScanSummary

router = APIRouter(prefix="/user", tags=["User"])

PASSWORD_CHECK_LIMIT = RateLimit("password-check", max_requests=10, window_seconds=900)

_ACTIVITY_DAYS = 30
_RECENT_ITEMS = 5
_FLAGGED = ("known_malicious", "suspicious")


def _profile(user: Any) -> ProfileOut:
    return ProfileOut(
        user=UserOut.model_validate(user), settings=SettingsOut.model_validate(user.settings)
    )


@router.get("/profile", response_model=ProfileOut)
def get_profile(user: RequiredUser) -> ProfileOut:
    return _profile(user)


@router.patch("/settings", response_model=ProfileOut)
def update_settings(body: SettingsUpdate, user: RequiredUser, db: Db) -> ProfileOut:
    changes = body.model_dump(exclude_unset=True)
    if "display_name" in changes:
        user.display_name = (changes["display_name"] or "").strip() or None
    for setting in ("save_scan_history", "sync_extension_events"):
        if changes.get(setting) is not None:
            setattr(user.settings, setting, changes[setting])
    db.commit()
    return _profile(user)


@router.post("/password", status_code=204)
def change_password(
    body: PasswordChange, request: Request, user: RequiredUser, session: CurrentSession, db: Db
) -> None:
    rate_limit.enforce(PASSWORD_CHECK_LIMIT, f"user:{user.id}")
    if not verify_password(body.current_password, user.password_hash):
        raise ApiError(403, "wrong_password", "Your current password is incorrect.")
    user.password_hash = hash_password(body.new_password)
    # Sign out every other device: if the old password leaked, those sessions may not be ours.
    for other in db.scalars(select(UserSession).where(UserSession.user_id == user.id)).all():
        if session is None or other.id != session.id:
            db.delete(other)
    record_event(db, request, user, "password_changed")
    db.commit()


@router.get("/activity", response_model=list[ActivityOut])
def recent_activity(user: RequiredUser, db: Db) -> list[AuditEvent]:
    return list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.user_id == user.id)
            .order_by(AuditEvent.created_at.desc())
            .limit(10)
        )
    )


@router.get("/overview", response_model=OverviewOut)
def overview(user: RequiredUser, db: Db) -> OverviewOut:
    owned = ScanJob.user_id == user.id

    def grouped(column: Any) -> dict[str, int]:
        rows = db.execute(select(column, func.count()).where(owned).group_by(column)).all()
        return {key: total for key, total in rows if key is not None}

    def latest(*conditions: Any) -> list[ScanSummary]:
        jobs = db.scalars(
            select(ScanJob)
            .where(owned, *conditions)
            .order_by(ScanJob.created_at.desc())
            .limit(_RECENT_ITEMS)
        )
        return [ScanSummary.model_validate(job) for job in jobs]

    today = utcnow().date()
    first_day = today - timedelta(days=_ACTIVITY_DAYS - 1)
    days = {
        (first_day + timedelta(days=offset)).isoformat(): DayCount(
            date=(first_day + timedelta(days=offset)).isoformat(), total=0, flagged=0
        )
        for offset in range(_ACTIVITY_DAYS)
    }
    recent = db.execute(
        select(ScanJob.created_at, ScanJob.risk).where(
            owned, ScanJob.created_at >= utcnow() - timedelta(days=_ACTIVITY_DAYS)
        )
    ).all()
    for created_at, risk in recent:
        day = days.get(created_at.date().isoformat())
        if day:
            day.total += 1
            day.flagged += risk in _FLAGGED

    by_type = grouped(ScanJob.scan_type)
    return OverviewOut(
        total_scans=sum(by_type.values()),
        by_risk=grouped(ScanJob.risk),
        by_type=by_type,
        recent_scans=latest(),
        recent_threats=latest(ScanJob.risk.in_(_FLAGGED)),
        daily_activity=list(days.values()),
    )


@router.get("/export")
def export_data(user: RequiredUser, db: Db) -> dict[str, Any]:
    """Everything stored about the account, in one machine-readable document."""
    scans = db.scalars(service.history_query(user.id).order_by(ScanJob.created_at)).all()
    events = db.scalars(
        select(AuditEvent).where(AuditEvent.user_id == user.id).order_by(AuditEvent.created_at)
    ).all()
    return {
        "exported_at": utcnow().isoformat(),
        "account": UserOut.model_validate(user).model_dump(mode="json"),
        "settings": SettingsOut.model_validate(user.settings).model_dump(),
        "scans": [
            ScanOut.model_validate(
                {
                    **{f: getattr(job, f) for f in ScanOut.model_fields if hasattr(job, f)},
                    "saved_to_history": True,
                }
            ).model_dump(mode="json")
            for job in scans
        ],
        "extension_installations": [
            {
                "browser": installation.browser,
                "version": installation.version,
                "linked_at_or_created": installation.created_at.isoformat(),
                "last_seen": installation.last_seen_at.isoformat(),
                "revoked": installation.revoked_at.isoformat() if installation.revoked_at else None,
            }
            for installation in db.scalars(
                select(ExtensionInstallation).where(ExtensionInstallation.user_id == user.id)
            )
        ],
        "extension_events": [
            {"kind": e.kind, "host": e.host, "verdict": e.verdict, "at": e.created_at.isoformat()}
            for e in db.scalars(
                select(ExtensionEvent)
                .where(ExtensionEvent.user_id == user.id)
                .order_by(ExtensionEvent.created_at)
            )
        ],
        "account_activity": [
            {
                "action": event.action,
                "ip_address": event.ip_address,
                "at": event.created_at.isoformat(),
            }
            for event in events
        ],
    }


@router.delete("/account", status_code=204)
def delete_account(body: AccountDeletion, response: Response, user: RequiredUser, db: Db) -> None:
    rate_limit.enforce(PASSWORD_CHECK_LIMIT, f"user:{user.id}")
    if not verify_password(body.password, user.password_hash):
        raise ApiError(403, "wrong_password", "Your password is incorrect.")
    for job in db.scalars(service.history_query(user.id)).all():
        service.delete_scan(db, job)
    db.delete(user)
    db.commit()
    clear_session_cookie(response)
