import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field


class WorkerHealth(BaseModel):
    reachable: bool
    workers: list[str]
    queued_tasks: int | None
    detail: str


class FeedHealth(BaseModel):
    name: str
    indicators: int
    last_success_at: datetime | None
    last_attempt_at: datetime | None
    last_error: str | None
    fresh: bool


class AdminOverview(BaseModel):
    users_total: int
    users_new_7d: int
    scans_24h: dict[str, int]
    failed_24h: int
    stuck: int
    reports_pending: int
    workers: WorkerHealth
    feeds: list[FeedHealth]
    rate_limit_rejections_24h: dict[str, int]


class AdminUser(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str | None
    role: str
    created_at: datetime
    disabled: bool
    scans: int
    assessment_enabled: bool = False
    assessment_domain_limit: int = 3
    assessment_monthly_limit: int = 20


class AdminUserPage(BaseModel):
    items: list[AdminUser]
    total: int


class UserUpdate(BaseModel):
    role: Literal["user", "moderator", "admin"] | None = None
    disabled: bool | None = None
    # Security-assessment entitlement ("subscription"), set per account by an admin.
    assessment_enabled: bool | None = None
    assessment_domain_limit: Annotated[int, Field(ge=1, le=100)] | None = None
    assessment_monthly_limit: Annotated[int, Field(ge=1, le=500)] | None = None


class AdminScan(BaseModel):
    """Job metadata only. What a user scanned (the target) is deliberately absent."""

    id: uuid.UUID
    scan_type: str
    status: str
    error: str | None
    created_at: datetime
    completed_at: datetime | None
    duration_seconds: float | None


class AuditEntry(BaseModel):
    action: str
    detail: str | None
    user_email: str | None
    ip_address: str | None
    created_at: datetime


class AuditPage(BaseModel):
    items: list[AuditEntry]
    total: int
    page: int = Field(ge=1)
