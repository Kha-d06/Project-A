from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analyzers.urls import indicator_digest
from app.core.config import get_settings
from app.models import ThreatIndicator, ThreatSource
from app.models.base import utcnow


@dataclass(frozen=True)
class IndicatorMatch:
    source_name: str
    kind: str
    value: str
    threat: str | None
    tags: str | None
    reference_url: str | None
    first_seen_at: datetime | None
    last_seen_at: datetime

    def evidence(self) -> dict[str, str | None]:
        return {
            "matched": self.value,
            "listed_by": self.source_name,
            "threat": self.threat,
            "tags": self.tags,
            "first_seen": self.first_seen_at.isoformat() if self.first_seen_at else None,
            "last_seen": self.last_seen_at.isoformat(),
            "reference": self.reference_url,
        }


def find_indicators(db: Session, kind: str, value: str) -> list[IndicatorMatch]:
    rows = db.execute(
        select(ThreatIndicator, ThreatSource.name)
        .join(ThreatSource)
        .where(
            ThreatIndicator.kind == kind, ThreatIndicator.value_digest == indicator_digest(value)
        )
    ).all()
    return [
        IndicatorMatch(
            source_name=source_name,
            kind=indicator.kind,
            value=indicator.value,
            threat=indicator.threat,
            tags=indicator.tags,
            reference_url=indicator.reference_url,
            first_seen_at=indicator.first_seen_at,
            last_seen_at=indicator.last_seen_at,
        )
        for indicator, source_name in rows
    ]


def fresh_sources(db: Session, keys: tuple[str, ...]) -> list[ThreatSource]:
    """Feeds that synced recently enough for a miss to mean something."""
    cutoff = utcnow() - timedelta(hours=get_settings().feed_stale_after_hours)
    return list(
        db.scalars(
            select(ThreatSource).where(
                ThreatSource.key.in_(keys), ThreatSource.last_success_at >= cutoff
            )
        )
    )
