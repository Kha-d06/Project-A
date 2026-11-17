import logging
import uuid
from collections.abc import Callable
from typing import Any

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.orm import Session

from app.analyzers.apk_scan import analyze_apk
from app.analyzers.arabic import (
    mostly_translated,
    translate_check,
    translate_check_detail,
    translate_finding,
    translate_text,
)
from app.analyzers.file_scan import analyze_file
from app.analyzers.message_scan import analyze_message
from app.analyzers.qr_scan import analyze_qr
from app.analyzers.types import Outcome
from app.analyzers.url_scan import analyze_url
from app.analyzers.verdict import assess
from app.analyzers.website_scan import analyze_website
from app.models import Finding, ScanJob
from app.models.base import utcnow
from app.scans.storage import delete_sample

logger = logging.getLogger(__name__)

ANALYZERS: dict[str, Callable[[dict[str, Any], Session], Outcome]] = {
    "url": analyze_url,
    "message": analyze_message,
    "file": analyze_file,
    "qr": analyze_qr,
    "website": analyze_website,
    "apk": analyze_apk,
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Payload fields that must not outlive the scan: full message text and sample locations.
_TRANSIENT_PAYLOAD_KEYS = ("content", "storage_name")


def _finish(db: Session, job: ScanJob) -> None:
    """Drop the sample and transient input whatever the outcome was."""
    storage_name = job.payload.get("storage_name")
    if storage_name:
        delete_sample(storage_name)
    job.payload = {k: v for k, v in job.payload.items() if k not in _TRANSIENT_PAYLOAD_KEYS}
    job.completed_at = utcnow()
    db.commit()


_ARABIC_LETTERS = range(0x0600, 0x0700)


def _arabic(outcome: Outcome) -> None:
    """Rewrite findings and check names in Arabic where the catalogue covers them,
    and record whether any English remains so the report can say so."""
    untranslated = 0
    for finding in outcome.findings:
        already_arabic = any(ord(char) in _ARABIC_LETTERS for char in finding.title)
        if not already_arabic and not translate_finding(finding):
            untranslated += 1
    for check in outcome.checks:
        translate_check(check)
        translate_check_detail(check)
        if not mostly_translated(check.detail):
            untranslated += 1
    outcome.limitations = [translate_text(item) for item in outcome.limitations]
    untranslated += sum(1 for item in outcome.limitations if not mostly_translated(item))
    outcome.details["findings_language"] = "ar" if untranslated == 0 else "mixed"


def run_scan(db: Session, scan_id: uuid.UUID) -> None:
    job = db.get(ScanJob, scan_id)
    if job is None or job.status != "queued":
        # Deleted by the user while queued, or already picked up by another worker.
        return
    job.status = "processing"
    job.started_at = utcnow()
    db.commit()

    try:
        outcome = ANALYZERS[job.scan_type](job.payload, db)
    except SoftTimeLimitExceeded:
        db.rollback()
        job.status = "failed"
        job.error = "The scan took too long and was stopped. Please try again."
        _finish(db, job)
        return
    except Exception:  # noqa: BLE001 - a crashing analyzer must still leave a truthful record
        db.rollback()
        logger.exception("Scan %s failed", scan_id)
        job.status = "failed"
        job.error = "The scan could not be completed because of an internal error."
        _finish(db, job)
        return

    locale = str(job.payload.get("locale", "en"))
    if locale == "ar":
        _arabic(outcome)
    assessment = assess(job.scan_type, outcome, locale)
    job.status = assessment.status
    job.risk = assessment.risk
    job.confidence = assessment.confidence
    job.summary = assessment.summary
    job.recommendations = assessment.recommendations
    job.checks = [check.as_dict() for check in outcome.checks]
    job.details = outcome.details
    job.limitations = outcome.limitations
    job.findings = [
        Finding(
            position=position,
            severity=finding.severity,
            category=finding.category,
            title=finding.title,
            explanation=finding.explanation,
            evidence={k: v for k, v in finding.evidence.items() if v is not None},
            source=finding.source,
        )
        for position, finding in enumerate(
            sorted(outcome.findings, key=lambda f: _SEVERITY_ORDER[f.severity])
        )
    ]
    _finish(db, job)
