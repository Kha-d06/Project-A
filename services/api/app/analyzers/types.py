from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Protocol

from sqlalchemy.orm import Session

from app.models.base import utcnow

Severity = Literal["critical", "high", "medium", "low", "info"]
CheckStatus = Literal["completed", "unavailable", "failed", "skipped"]


@dataclass
class FindingData:
    severity: Severity
    category: str
    title: str
    explanation: str
    source: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Check:
    """A record of one check we attempted, whether or not it produced findings."""

    key: str
    label: str
    provider: str
    status: CheckStatus
    detail: str
    # Core checks are the ones a "no known threat" verdict depends on. If none of
    # them completed, the scan is reported as inconclusive instead.
    core: bool = False
    finished_at: datetime = field(default_factory=utcnow)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "provider": self.provider,
            "status": self.status,
            "detail": self.detail,
            "core": self.core,
            "finished_at": self.finished_at.isoformat(),
        }


@dataclass
class Outcome:
    findings: list[FindingData] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)


class Analyzer(Protocol):
    def __call__(self, payload: dict[str, Any], db: Session) -> Outcome: ...
