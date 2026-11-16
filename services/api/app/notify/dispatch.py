"""Everything that happens after a scan finishes, run by the task worker (which
has full database access), never by the scan worker (which handles untrusted
samples and holds only restricted credentials)."""

import logging
import uuid

from sqlalchemy.orm import Session

from app.models import ScanJob
from app.notify.channels import ChannelUnavailableError, send_reply
from app.notify.webhooks import deliver_for_scan

logger = logging.getLogger(__name__)
_FINISHED = ("completed", "inconclusive", "failed")


def after_scan(db: Session, scan_id: uuid.UUID) -> None:
    scan = db.get(ScanJob, scan_id)
    if scan is None or scan.status not in _FINISHED:
        return
    reply_to = scan.payload.get("reply_to")
    if reply_to:
        try:
            send_reply(db, scan, reply_to)
        except ChannelUnavailableError as exc:
            logger.warning("Reply for scan %s not sent: %s", scan_id, exc)
        # The chat ID or address is only needed for the reply.
        scan.payload = {k: v for k, v in scan.payload.items() if k != "reply_to"}
        db.commit()
    if scan.status != "failed":
        deliver_for_scan(db, scan)
