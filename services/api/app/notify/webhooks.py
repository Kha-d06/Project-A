"""Signed webhook deliveries for finished scans.

Each delivery is a JSON POST with:
  X-Qalaa-Event:      scan.completed or scan.dangerous
  X-Qalaa-Timestamp:  Unix seconds
  X-Qalaa-Signature:  sha256=HMAC-SHA256(secret, f"{timestamp}.{body}")
Receivers should check the signature and reject timestamps older than five minutes.
Deliveries go through the SSRF-safe POST, so a webhook cannot be aimed at the
server's own network. After ten consecutive failures a webhook is switched off.
"""

import hashlib
import hmac
import json
import logging
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analyzers.safe_fetch import ResolutionError, UnsafeDestinationError, post_json
from app.core.config import get_settings
from app.core.crypto import decrypt
from app.models import ScanJob, Webhook
from app.models.base import utcnow

logger = logging.getLogger(__name__)
MAX_CONSECUTIVE_FAILURES = 10


def sign(secret: str, timestamp: int, body: bytes) -> str:
    digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"sha256={digest.hexdigest()}"


def scan_event(scan: ScanJob) -> dict[str, Any]:
    """What a webhook receives. The target is the user's own submission."""
    base = get_settings().public_url.rstrip("/")
    return {
        "id": str(scan.id),
        "scan_type": scan.scan_type,
        "status": scan.status,
        "risk": scan.risk,
        "confidence": scan.confidence,
        "summary": scan.summary,
        "target": scan.target,
        "findings": [
            {"severity": f.severity, "category": f.category, "title": f.title, "source": f.source}
            for f in scan.findings[:25]
        ],
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "report_url": f"{base}/dashboard/scans/{scan.id}",
    }


def deliver(webhook: Webhook, event: str, payload: dict[str, Any]) -> str:
    secret = decrypt(webhook.secret_encrypted)
    if secret is None:
        return "secret unreadable (the server secret changed); recreate this webhook"
    body = json.dumps({"event": event, "data": payload}, separators=(",", ":")).encode()
    timestamp = int(time.time())
    headers = {
        "X-Qalaa-Event": event,
        "X-Qalaa-Timestamp": str(timestamp),
        "X-Qalaa-Signature": sign(secret, timestamp, body),
    }
    try:
        status = post_json(webhook.url, body, headers)
    except (UnsafeDestinationError, ResolutionError) as exc:
        return f"refused: {exc}"[:120]
    except OSError as exc:
        return f"failed: {type(exc).__name__}"
    return f"HTTP {status}"


def deliver_for_scan(db: Session, scan: ScanJob) -> int:
    if scan.user_id is None:
        return 0
    events = ["scan.completed"]
    if scan.risk in ("known_malicious", "suspicious"):
        events.append("scan.dangerous")
    hooks = db.scalars(
        select(Webhook).where(Webhook.user_id == scan.user_id, Webhook.active.is_(True))
    ).all()
    payload = scan_event(scan)
    sent = 0
    for hook in hooks:
        for event in events:
            if event not in hook.events:
                continue
            result = deliver(hook, event, payload)
            ok = result.startswith("HTTP 2")
            hook.last_delivery_at = utcnow()
            hook.last_status = result
            hook.consecutive_failures = 0 if ok else hook.consecutive_failures + 1
            if hook.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                hook.active = False
            sent += 1
    db.commit()
    return sent
