import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.analyzers.urls import MAX_URL_LENGTH, InvalidUrlError, parse_url


def _web_url(value: str) -> str:
    try:
        return parse_url(value).normalized
    except InvalidUrlError as exc:
        raise ValueError(str(exc)) from exc


class EnrollRequest(BaseModel):
    browser: str = Field(min_length=1, max_length=40)
    version: str = Field(min_length=1, max_length=20)
    link_code: str | None = Field(default=None, max_length=20)


class Credentials(BaseModel):
    installation_id: uuid.UUID
    refresh_token: str
    access_token: str
    expires_in: int
    linked: bool


class RefreshRequest(BaseModel):
    refresh_token: str = Field(max_length=100)


class AccessToken(BaseModel):
    access_token: str
    expires_in: int


class LinkRequest(BaseModel):
    link_code: str = Field(max_length=20)


class CheckUrlRequest(BaseModel):
    url: str = Field(max_length=MAX_URL_LENGTH)
    # "host": the extension has privacy mode on and sent only scheme and domain.
    mode: Literal["full", "host"] = "full"

    _validate_url = field_validator("url")(_web_url)


class CheckDownloadRequest(BaseModel):
    url: str = Field(max_length=MAX_URL_LENGTH)
    filename: str = Field(max_length=255)

    _validate_url = field_validator("url")(_web_url)


class Reason(BaseModel):
    severity: str
    title: str
    explanation: str
    source: str
    evidence: dict[str, Any]


class QuickVerdict(BaseModel):
    verdict: Literal[
        "dangerous", "suspicious", "caution", "no_known_threat", "unavailable", "skipped"
    ]
    host: str
    reasons: list[Reason]
    sources: list[str]
    limitations: list[str]
    checked_at: datetime
    cache_seconds: int


EVENT_KINDS = ("warning_shown", "went_back", "proceeded", "download_warning", "link_checked")


class EventReport(BaseModel):
    kind: Literal["warning_shown", "went_back", "proceeded", "download_warning", "link_checked"]
    url: str = Field(max_length=MAX_URL_LENGTH)
    verdict: Literal["dangerous", "suspicious", "caution", "no_known_threat", "unavailable"]

    _validate_url = field_validator("url")(_web_url)


class EventStored(BaseModel):
    stored: bool


class ExtensionSettings(BaseModel):
    installation_id: uuid.UUID
    linked: bool
    account_email: str | None
    sync_events: bool
    # Domains from family or organisation groups whose block list this account
    # chose to apply, and the names of those groups (shown on the warning page).
    family_blocklist: list[str] = []
    family_groups: list[str] = []


class LinkCodeOut(BaseModel):
    code: str
    expires_at: datetime


class InstallationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    browser: str
    version: str
    created_at: datetime
    last_seen_at: datetime


class ExtensionEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    kind: str
    host: str
    verdict: str
    created_at: datetime


class Blocklist(BaseModel):
    """Domains the extension blocks before the page loads (declarativeNetRequest)."""

    version: str
    generated_at: datetime
    hosts: list[str]
    # Exact URLs (desktop history check only; the extension gets an empty list).
    urls: list[str] = []
    sources: list[str]


class AssistantCookie(BaseModel):
    name: str = Field(max_length=120)
    domain: str = Field(max_length=255)
    third_party: bool = False
    session: bool = True
    days: int | None = Field(default=None, ge=0, le=100_000)


class AssistantContext(BaseModel):
    host: str = Field(max_length=255)
    verdict: str = Field(max_length=40)
    warning_signs: list[str] = Field(default_factory=list, max_length=10)
    cookies: list[AssistantCookie] = Field(default_factory=list, max_length=60)
    trackers: list[str] = Field(default_factory=list, max_length=40)
    has_password_field: bool = False

    @field_validator("warning_signs", "trackers")
    @classmethod
    def _short_items(cls, value: list[str]) -> list[str]:
        return [item[:200] for item in value]


class AssistantQuestion(BaseModel):
    question: str = Field(min_length=2, max_length=500)
    language: Literal["en", "ar"] = "en"
    context: AssistantContext


class AssistantReply(BaseModel):
    answer: str
    ai_generated: bool = True
    model: str
