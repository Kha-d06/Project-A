"""Family and organisation groups.

A group lets people share scan results with each other and, if each member
chooses to, lets the owners and admins see how many warnings a member has had
recently (counts only: never which sites, messages or files). Managing a group
needs a website session, like other account changes; API keys cannot.
"""

import uuid
from datetime import timedelta

from fastapi import APIRouter, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.auth import record_event
from app.api.deps import Db, RequiredUser, SessionUser
from app.api.sharing import shared_view
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.core.security import new_token, token_digest
from app.models import (
    ExtensionEvent,
    Group,
    GroupInvite,
    GroupMember,
    ScanJob,
    ScanShare,
    User,
)
from app.models.base import utcnow
from app.notify.email import EmailUnavailableError, email_enabled, send_email
from app.schemas.sharing import (
    AcceptInvite,
    GroupCreate,
    GroupMemberOut,
    GroupOut,
    GroupSharedScan,
    InviteCreated,
    InviteRequest,
    MemberUpdate,
)

router = APIRouter(prefix="/groups", tags=["Family and organisations"])

INVITE_LIMIT = RateLimit("group-invite", max_requests=30, window_seconds=3600)
INVITE_LIFETIME = timedelta(days=7)
MAX_GROUPS_PER_USER = 10
MAX_MEMBERS = {"family": 12, "organisation": 500}
_MANAGERS = ("owner", "admin")
_NOT_FOUND = "That group does not exist, or you are not a member."


def _membership(db: Session, group_id: uuid.UUID, user: User) -> tuple[Group, GroupMember]:
    group = db.get(Group, group_id)
    member = db.get(GroupMember, (group_id, user.id))
    if group is None or member is None:
        raise ApiError(404, "group_not_found", _NOT_FOUND)
    return group, member


def _require_manager(member: GroupMember) -> None:
    if member.role not in _MANAGERS:
        raise ApiError(403, "not_group_admin", "Only the group's owner and admins can do this.")


def _warning_count(db: Session, user_id: uuid.UUID) -> int:
    since = utcnow() - timedelta(days=30)
    scans = db.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(
            ScanJob.user_id == user_id,
            ScanJob.risk.in_(("known_malicious", "suspicious")),
            ScanJob.created_at >= since,
        )
    )
    browsing = db.scalar(
        select(func.count())
        .select_from(ExtensionEvent)
        .where(
            ExtensionEvent.user_id == user_id,
            ExtensionEvent.verdict.in_(("dangerous", "suspicious")),
            ExtensionEvent.created_at >= since,
        )
    )
    return (scans or 0) + (browsing or 0)


def _group_out(db: Session, group: Group, me: GroupMember) -> GroupOut:
    rows = db.execute(
        select(GroupMember, User)
        .join(User, User.id == GroupMember.user_id)
        .where(GroupMember.group_id == group.id)
        .order_by(GroupMember.joined_at)
    ).all()
    manager = me.role in _MANAGERS
    members = [
        GroupMemberOut(
            user_id=user.id,
            email=user.email,
            display_name=user.display_name,
            role=member.role,
            share_activity=member.share_activity,
            joined_at=member.joined_at,
            warnings_last_30_days=_warning_count(db, user.id)
            if manager and member.share_activity
            else None,
        )
        for member, user in rows
    ]
    invites = (
        [
            {"email": invite.email, "role": invite.role, "expires_at": invite.expires_at}
            for invite in db.scalars(
                select(GroupInvite).where(
                    GroupInvite.group_id == group.id,
                    GroupInvite.accepted_at.is_(None),
                    GroupInvite.expires_at > utcnow(),
                )
            )
        ]
        if manager
        else []
    )
    return GroupOut(
        id=group.id,
        name=group.name,
        kind=group.kind,
        created_at=group.created_at,
        my_role=me.role,
        my_share_activity=me.share_activity,
        members=members,
        pending_invites=invites,
    )


@router.get("", response_model=list[GroupOut])
def my_groups(db: Db, user: RequiredUser) -> list[GroupOut]:
    rows = db.execute(
        select(Group, GroupMember)
        .join(GroupMember, GroupMember.group_id == Group.id)
        .where(GroupMember.user_id == user.id)
        .order_by(Group.created_at)
    ).all()
    return [_group_out(db, group, member) for group, member in rows]


@router.post("", response_model=GroupOut, status_code=201)
def create_group(body: GroupCreate, request: Request, db: Db, user: SessionUser) -> GroupOut:
    owned = db.scalar(
        select(func.count())
        .select_from(GroupMember)
        .where(GroupMember.user_id == user.id, GroupMember.role == "owner")
    )
    if (owned or 0) >= MAX_GROUPS_PER_USER:
        raise ApiError(409, "too_many_groups", f"You can own up to {MAX_GROUPS_PER_USER} groups.")
    group = Group(name=body.name.strip(), kind=body.kind)
    db.add(group)
    db.flush()
    member = GroupMember(group_id=group.id, user_id=user.id, role="owner", share_activity=False)
    db.add(member)
    record_event(db, request, user, "group_created", group.name)
    db.commit()
    return _group_out(db, group, member)


@router.post("/{group_id}/invites", response_model=InviteCreated, status_code=201)
def invite(
    group_id: uuid.UUID, body: InviteRequest, request: Request, db: Db, user: SessionUser
) -> InviteCreated:
    rate_limit.enforce(INVITE_LIMIT, f"user:{user.id}")
    group, me = _membership(db, group_id, user)
    _require_manager(me)
    count = db.scalar(
        select(func.count()).select_from(GroupMember).where(GroupMember.group_id == group.id)
    )
    if (count or 0) >= MAX_MEMBERS[group.kind]:
        raise ApiError(409, "group_full", "This group has reached its member limit.")
    token = new_token()
    invite = GroupInvite(
        token_digest=token_digest(token),
        group_id=group.id,
        email=body.email.lower(),
        role=body.role,
        invited_by_id=user.id,
        expires_at=utcnow() + INVITE_LIFETIME,
    )
    db.add(invite)
    url = f"{get_settings().public_url.rstrip('/')}/dashboard/groups?invite={token}"
    emailed = False
    if email_enabled():
        inviter = user.display_name or user.email
        try:
            send_email(
                db,
                invite.email,
                f"{inviter} invited you to “{group.name}” on SENTINEL",
                f"{inviter} invited you to join their SENTINEL {group.kind}, “{group.name}”. "
                "Members can share scan results with each other. Nothing about your browsing "
                "or scans is shared unless you choose to.\n\n"
                f"To accept, sign in with this email address and open this link within 7 days:\n"
                f"\n{url}\n\nIf you do not know this person, ignore this message.\n",
            )
            emailed = True
        except EmailUnavailableError:
            emailed = False
    record_event(db, request, user, "group_invite", f"{group.name}: {invite.email}")
    db.commit()
    return InviteCreated(email=invite.email, expires_at=invite.expires_at, emailed=emailed, url=url)


@router.post("/invites/accept", response_model=GroupOut)
def accept_invite(body: AcceptInvite, request: Request, db: Db, user: SessionUser) -> GroupOut:
    invite = db.get(GroupInvite, token_digest(body.token))
    if invite is None or invite.accepted_at is not None or invite.expires_at < utcnow():
        raise ApiError(400, "invalid_invite", "This invitation is not valid or has expired.")
    if invite.email.lower() != user.email.lower():
        raise ApiError(
            403,
            "invite_email_mismatch",
            "This invitation was sent to a different email address. Sign in with that address.",
        )
    if email_enabled() and user.email_verified_at is None:
        raise ApiError(403, "email_not_verified", "Confirm your email address first.")
    group = db.get(Group, invite.group_id)
    if group is None:
        raise ApiError(400, "invalid_invite", "This group no longer exists.")
    member = db.get(GroupMember, (group.id, user.id))
    if member is None:
        member = GroupMember(group_id=group.id, user_id=user.id, role=invite.role)
        db.add(member)
    invite.accepted_at = utcnow()
    record_event(db, request, user, "group_joined", group.name)
    db.commit()
    return _group_out(db, group, member)


@router.patch("/{group_id}/members/{member_id}", response_model=GroupOut)
def update_member(
    group_id: uuid.UUID,
    member_id: uuid.UUID,
    body: MemberUpdate,
    request: Request,
    db: Db,
    user: SessionUser,
) -> GroupOut:
    group, me = _membership(db, group_id, user)
    target = db.get(GroupMember, (group_id, member_id))
    if target is None:
        raise ApiError(404, "member_not_found", "That person is not in this group.")
    if body.share_activity is not None:
        # Only the member themselves decides whether their activity is visible.
        if member_id != user.id:
            raise ApiError(403, "not_your_setting", "Only that member can change this.")
        target.share_activity = body.share_activity
    if body.role is not None:
        _require_manager(me)
        if target.role == "owner":
            raise ApiError(409, "owner_role", "The owner's role cannot be changed.")
        target.role = body.role
        record_event(db, request, user, "group_role_changed", f"{group.name}: {body.role}")
    db.commit()
    return _group_out(db, group, me)


@router.delete("/{group_id}/members/{member_id}", status_code=204)
def remove_member(
    group_id: uuid.UUID, member_id: uuid.UUID, request: Request, db: Db, user: SessionUser
) -> None:
    group, me = _membership(db, group_id, user)
    target = db.get(GroupMember, (group_id, member_id))
    if target is None:
        raise ApiError(404, "member_not_found", "That person is not in this group.")
    leaving = member_id == user.id
    if not leaving:
        _require_manager(me)
    if target.role == "owner":
        raise ApiError(
            409, "owner_cannot_leave", "The owner cannot leave; delete the group instead."
        )
    db.delete(target)
    record_event(db, request, user, "group_left" if leaving else "group_member_removed", group.name)
    db.commit()


@router.delete("/{group_id}", status_code=204)
def delete_group(group_id: uuid.UUID, request: Request, db: Db, user: SessionUser) -> None:
    group, me = _membership(db, group_id, user)
    if me.role != "owner":
        raise ApiError(403, "not_group_owner", "Only the owner can delete the group.")
    record_event(db, request, user, "group_deleted", group.name)
    db.delete(group)
    db.commit()


@router.get("/{group_id}/shares", response_model=list[GroupSharedScan])
def group_shares(group_id: uuid.UUID, db: Db, user: RequiredUser) -> list[GroupSharedScan]:
    _membership(db, group_id, user)
    now = utcnow()
    rows = db.execute(
        select(ScanShare, ScanJob, User)
        .join(ScanJob, ScanJob.id == ScanShare.scan_id)
        .join(User, User.id == ScanShare.created_by_id)
        .where(
            ScanShare.group_id == group_id,
            ScanShare.revoked_at.is_(None),
            (ScanShare.expires_at.is_(None)) | (ScanShare.expires_at > now),
        )
        .order_by(ScanShare.created_at.desc())
        .limit(100)
    ).all()
    return [
        GroupSharedScan(
            share_id=share.id,
            shared_by=sharer.display_name or sharer.email,
            note=share.note,
            shared_at=share.created_at,
            scan=shared_view(scan, share),
        )
        for share, scan, sharer in rows
    ]
