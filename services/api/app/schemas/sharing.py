import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.analyzers.urls import MAX_URL_LENGTH, InvalidUrlError, parse_url
from app.schemas.scans import CheckOut, ScanSummary


class ShareRequest(BaseModel):
    include_target: bool = False
    note: str | None = Field(default=None, max_length=300)
    expires_in_days: int = Field(default=30, ge=1, le=365)
    group_id: uuid.UUID | None = None


class ShareOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    group_id: uuid.UUID | None
    include_target: bool
    note: str | None
    views: int
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class ShareCreated(ShareOut):
    # Public links only. Shown once; the server keeps only a digest.
    url: str | None = None


class SharedFinding(BaseModel):
    severity: str
    category: str
    title: str
    explanation: str
    source: str
    evidence: dict[str, Any] | None = None


class SharedScan(BaseModel):
    """A read-only copy of a result, as shown to someone with a share link."""

    scan_type: str
    status: str
    risk: str | None
    confidence: str | None
    summary: str | None
    target: str | None
    findings: list[SharedFinding]
    checks: list[CheckOut]
    recommendations: list[str]
    limitations: list[str]
    details: dict[str, Any] | None
    completed_at: datetime | None
    note: str | None
    shared_at: datetime
    expires_at: datetime | None


class BulkUrlRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=50)

    @field_validator("urls")
    @classmethod
    def _valid_urls(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for index, value in enumerate(values):
            if len(value) > MAX_URL_LENGTH:
                raise ValueError(f"Item {index + 1} is too long.")
            try:
                normalized = parse_url(value).normalized
            except InvalidUrlError as exc:
                raise ValueError(f"Item {index + 1}: {exc}") from exc
            if normalized not in cleaned:
                cleaned.append(normalized)
        return cleaned


class BulkScanOut(BaseModel):
    scans: list[ScanSummary]


# --- Groups ---------------------------------------------------------------------------


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["family", "organisation"]


class GroupMemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    display_name: str | None
    role: str
    share_activity: bool
    joined_at: datetime
    # Present only for members who chose to share activity, and only for owners/admins.
    warnings_last_30_days: int | None = None


class GroupOut(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    created_at: datetime
    my_role: str
    my_share_activity: bool
    my_apply_blocklist: bool = False
    blocklist: list[str] = []
    policies: dict[str, Any] = {}
    members: list[GroupMemberOut]
    pending_invites: list[dict[str, Any]]


class GroupPolicies(BaseModel):
    """Family: safe_search, lock_protection. Organisation: require_2fa,
    require_extension, max_days_since_scan (0-90). Keys for the other kind are ignored."""

    safe_search: bool | None = None
    lock_protection: bool | None = None
    require_2fa: bool | None = None
    require_extension: bool | None = None
    max_days_since_scan: int | None = Field(default=None, ge=0, le=90)


class MemberCompliance(BaseModel):
    user_id: uuid.UUID
    email: str
    display_name: str | None
    role: str
    follows_rules: bool
    # The rest is present only for members who chose to share activity.
    shared: bool
    two_factor: bool | None = None
    extension_linked: bool | None = None
    devices: int | None = None
    last_device_scan: datetime | None = None
    device_threats: int | None = None
    problems: list[str] = []


class GroupCompliance(BaseModel):
    group_id: uuid.UUID
    policies: dict[str, Any]
    members: list[MemberCompliance]
    sharing: int
    compliant: int


class InviteRequest(BaseModel):
    email: EmailStr
    role: Literal["admin", "member"] = "member"


class InviteCreated(BaseModel):
    email: str
    expires_at: datetime
    emailed: bool
    # Returned so the inviter can pass it on another way if email is not set up.
    url: str


class AcceptInvite(BaseModel):
    token: str = Field(min_length=10, max_length=100)


class MemberUpdate(BaseModel):
    role: Literal["admin", "member"] | None = None
    share_activity: bool | None = None
    apply_blocklist: bool | None = None


class GroupBlocklist(BaseModel):
    domains: list[str] = Field(max_length=500)

    @field_validator("domains")
    @classmethod
    def _domains(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            try:
                host = parse_url(f"http://{value.strip().lower().lstrip('*.')}/").host
            except InvalidUrlError as exc:
                raise ValueError(f"“{value[:60]}” is not a domain name.") from exc
            if "." not in host:
                raise ValueError(f"“{value[:60]}” is not a domain name.")
            if host not in cleaned:
                cleaned.append(host)
        return cleaned


class GroupSharedScan(BaseModel):
    share_id: uuid.UUID
    shared_by: str
    note: str | None
    shared_at: datetime
    scan: SharedScan


# --- Webhooks -------------------------------------------------------------------------


WebhookEvent = Literal["scan.completed", "scan.dangerous"]


def _default_events() -> list[WebhookEvent]:
    return ["scan.dangerous"]


class WebhookCreate(BaseModel):
    url: str = Field(max_length=MAX_URL_LENGTH)
    events: list[WebhookEvent] = Field(default_factory=_default_events, min_length=1)

    @field_validator("url")
    @classmethod
    def _https_only(cls, value: str) -> str:
        try:
            url = parse_url(value)
        except InvalidUrlError as exc:
            raise ValueError(str(exc)) from exc
        if url.scheme != "https":
            raise ValueError("Webhook addresses must use https://.")
        if url.is_ip_address:
            raise ValueError("Use a domain name, not an IP address.")
        return url.normalized


class WebhookOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    events: list[str]
    active: bool
    created_at: datetime
    last_delivery_at: datetime | None
    last_status: str | None
    consecutive_failures: int


class WebhookCreated(WebhookOut):
    secret: str


# --- Breach check ---------------------------------------------------------------------


class Breach(BaseModel):
    name: str
    title: str
    domain: str | None
    breach_date: str | None
    data_classes: list[str]
    verified: bool


class BreachResult(BaseModel):
    email: str
    breaches: list[Breach]
    checked_at: datetime
    source: str = "Have I Been Pwned"
