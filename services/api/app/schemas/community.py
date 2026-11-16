import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Category = Literal[
    "website", "scam_message", "job_offer", "fraudulent_app", "phone_number", "social_account"
]
ReportStatus = Literal["pending", "verified", "rejected", "duplicate"]


class ReportCreate(BaseModel):
    category: Category
    subject: str = Field(min_length=3, max_length=500)
    description: str = Field(min_length=10, max_length=2000)
    evidence: str | None = Field(default=None, max_length=5000)
    # Signed-in users can still choose not to attach the report to their account.
    anonymous: bool = False

    @field_validator("description", "evidence")
    @classmethod
    def _strip(cls, value: str | None) -> str | None:
        return value.replace("\x00", "").strip() if value is not None else None


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    category: Category
    subject: str
    description: str
    evidence: str | None
    status: ReportStatus
    moderator_note: str | None
    created_at: datetime
    reviewed_at: datetime | None
    verification_expires_at: datetime | None = None


class ReportCreated(BaseModel):
    report: ReportOut
    # Returned once, only when the report is not attached to an account.
    tracking_token: str | None
    similar_reports: int


class PublicReport(BaseModel):
    category: Category
    subject: str
    reports: int
    verified_at: datetime


class ModerationItem(ReportOut):
    similar_reports: int
    anonymous: bool
    # {"level": "trusted" | "new" | "unreliable" | "anonymous", "verified": n, "rejected": n}
    reporter_reputation: dict[str, int | str]


class ReviewRequest(BaseModel):
    status: Literal["verified", "rejected", "duplicate"]
    note: str | None = Field(default=None, max_length=1000)
    duplicate_of: uuid.UUID | None = None
