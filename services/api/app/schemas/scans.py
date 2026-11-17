import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.analyzers.message_scan import MAX_MESSAGE_LENGTH
from app.analyzers.urls import MAX_URL_LENGTH, InvalidUrlError, parse_url

ScanType = Literal["url", "message", "file", "qr", "website", "apk", "screenshot"]
ScanStatus = Literal["queued", "processing", "completed", "failed", "inconclusive"]
RiskLevel = Literal["known_malicious", "suspicious", "no_known_threat", "inconclusive"]

_MIN_MESSAGE_LENGTH = 10


class UrlScanRequest(BaseModel):
    url: str = Field(max_length=MAX_URL_LENGTH)

    @field_validator("url")
    @classmethod
    def _must_be_web_url(cls, value: str) -> str:
        try:
            return parse_url(value).normalized
        except InvalidUrlError as exc:
            raise ValueError(str(exc)) from exc


class MessageScanRequest(BaseModel):
    content: str = Field(max_length=MAX_MESSAGE_LENGTH)
    # Opt-in: send the text (with links, emails and numbers masked) to the AI model
    # for a second opinion. The verdict never depends on it.
    ai_consent: bool = False
    # Optional: the sender name or number exactly as the phone showed it.
    sender: str | None = Field(default=None, max_length=60)

    @field_validator("content")
    @classmethod
    def _must_have_text(cls, value: str) -> str:
        text = value.replace("\x00", "").strip()
        if len(text) < _MIN_MESSAGE_LENGTH:
            raise ValueError("Paste the full message so there is enough text to analyse.")
        return text


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    severity: Literal["critical", "high", "medium", "low", "info"]
    category: str
    title: str
    explanation: str
    evidence: dict[str, Any]
    source: str


class CheckOut(BaseModel):
    key: str
    label: str
    provider: str
    status: Literal["completed", "unavailable", "failed", "skipped"]
    detail: str
    core: bool
    finished_at: datetime


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_type: ScanType
    status: ScanStatus
    target: str
    risk: RiskLevel | None
    created_at: datetime
    completed_at: datetime | None


class ScanOut(ScanSummary):
    confidence: Literal["high", "medium", "low"] | None
    summary: str | None
    findings: list[FindingOut]
    checks: list[CheckOut]
    details: dict[str, Any]
    recommendations: list[str]
    limitations: list[str]
    error: str | None
    started_at: datetime | None
    saved_to_history: bool
    ai_explanation: str | None
    ai_model: str | None
    ai_generated_at: datetime | None


class ExplanationOut(BaseModel):
    explanation: str
    model: str
    generated_at: datetime
    label: str = (
        "Written by AI from the findings above. It may contain mistakes; the findings are "
        "the evidence."
    )


class ScanPage(BaseModel):
    items: list[ScanSummary]
    total: int
    page: int
    page_size: int


class DayCount(BaseModel):
    date: str
    total: int
    flagged: int


class OverviewOut(BaseModel):
    total_scans: int
    by_risk: dict[str, int]
    by_type: dict[str, int]
    recent_scans: list[ScanSummary]
    recent_threats: list[ScanSummary]
    daily_activity: list[DayCount]


class ProviderStatus(BaseModel):
    key: str
    name: str
    purpose: str
    status: Literal["active", "not_configured", "degraded", "awaiting_first_sync"]
    detail: str
    shares_data: str
