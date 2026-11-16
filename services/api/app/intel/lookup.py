from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analyzers.urls import indicator_digest
from app.core.config import get_settings
from app.models import ThreatIndicator, ThreatSource
from app.models.base import utcnow


@dataclass(frozen=True)
class IndicatorMatch:
    source_key: str
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
    return _matches(
        db,
        (ThreatIndicator.kind == kind, ThreatIndicator.value_digest == indicator_digest(value)),
    )


def find_by_host(db: Session, host: str, limit: int = 50) -> list[IndicatorMatch]:
    """Every listed URL or host indicator on a host, newest first."""
    return _matches(db, (ThreatIndicator.host == host.lower(),), limit)


def _matches(db: Session, conditions: tuple[Any, ...], limit: int = 50) -> list[IndicatorMatch]:
    rows = db.execute(
        select(ThreatIndicator, ThreatSource.key, ThreatSource.name)
        .join(ThreatSource)
        .where(*conditions)
        .order_by(ThreatIndicator.last_seen_at.desc())
        .limit(limit)
    ).all()
    return [
        IndicatorMatch(
            source_key=source_key,
            source_name=source_name,
            kind=indicator.kind,
            value=indicator.value,
            threat=indicator.threat,
            tags=indicator.tags,
            reference_url=indicator.reference_url,
            first_seen_at=indicator.first_seen_at,
            last_seen_at=indicator.last_seen_at,
        )
        for indicator, source_key, source_name in rows
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
