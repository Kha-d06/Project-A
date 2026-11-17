from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class IndicatorOut(BaseModel):
    source: str
    kind: str
    value: str
    threat: str | None
    tags: str | None
    first_seen: datetime | None
    last_seen: datetime
    reference: str | None


class SourceFreshness(BaseModel):
    name: str
    indicators: int
    last_updated: datetime | None
    fresh: bool


class LookupResult(BaseModel):
    query: str
    kind: Literal["domain", "ip", "hash", "phone"]
    verdict: Literal["listed", "community_verified", "not_listed", "unavailable"]
    indicators: list[IndicatorOut]
    sources: list[SourceFreshness]
    notes: list[str]
    # Phone lookups only.
    country: str | None = None
    reports_awaiting_review: int | None = None


class HashList(BaseModel):
    version: str
    generated_at: datetime
    sources: list[str]
    sha256: list[str]
