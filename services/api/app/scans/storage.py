"""Quarantine storage for uploaded samples.

Samples live outside any web-served directory under random names, are written
without execute permission, and are deleted as soon as their scan finishes.
The hourly retention sweep also removes any sample file no running scan refers
to (a crash between storing and queueing, say), so none outlives
SAMPLE_MAX_AGE plus one sweep interval. Deleting a file removes it from the
file system; it doesn't overwrite the disk blocks, and isn't a guarantee
against forensic recovery from the underlying storage (see docs/security.md).
"""

import logging
import os
import re
import secrets
import time
from datetime import timedelta
from pathlib import Path
from typing import BinaryIO

from app.core.config import get_settings
from app.core.errors import ApiError

logger = logging.getLogger(__name__)

_COPY_CHUNK_BYTES = 1024 * 1024
# Names store_sample gives (secrets.token_hex(16)); nothing else in the folder is touched.
_SAMPLE_NAME = re.compile(r"^[0-9a-f]{32}$")
# Longest a sample may exist: the stuck-scan limit (app/scans/service.py).
SAMPLE_MAX_AGE = timedelta(minutes=15)


def _sample_path(storage_name: str) -> Path:
    upload_dir = get_settings().upload_dir.resolve()
    path = (upload_dir / storage_name).resolve()
    if path.parent != upload_dir:
        raise ValueError("Storage name escapes the upload directory")
    return path


def store_sample(stream: BinaryIO, max_bytes: int | None = None) -> tuple[str, int]:
    """Copy an upload into quarantine, enforcing the size limit while streaming."""
    settings = get_settings()
    limit = max_bytes or settings.max_upload_bytes
    settings.upload_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    storage_name = secrets.token_hex(16)
    path = _sample_path(storage_name)
    size = 0
    try:
        with path.open("xb") as target:
            path.chmod(0o600)
            while chunk := stream.read(_COPY_CHUNK_BYTES):
                size += len(chunk)
                if size > limit:
                    megabytes = limit // (1024 * 1024)
                    raise ApiError(
                        413,
                        "file_too_large",
                        f"Files larger than {megabytes} MB cannot be scanned.",
                    )
                target.write(chunk)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    if size == 0:
        path.unlink(missing_ok=True)
        raise ApiError(422, "empty_file", "The file is empty, so there is nothing to scan.")
    return storage_name, size


def delete_sample(storage_name: str) -> None:
    try:
        _sample_path(storage_name).unlink(missing_ok=True)
    except (OSError, ValueError):
        logger.exception("Could not delete sample %s", storage_name)


def sweep_orphan_samples(referenced: set[str], older_than: timedelta = SAMPLE_MAX_AGE) -> int:
    """Deletes sample files that no running scan refers to and that are older than
    `older_than`. Only regular files with a sample's name are considered: never a
    directory, a link, or a file someone else put in the folder."""
    upload_dir = get_settings().upload_dir
    if not upload_dir.is_dir():
        return 0
    cutoff = time.time() - older_than.total_seconds()
    removed = 0
    with os.scandir(upload_dir) as entries:
        for entry in entries:
            if not _SAMPLE_NAME.fullmatch(entry.name) or entry.name in referenced:
                continue
            try:
                if (
                    not entry.is_file(follow_symlinks=False)
                    or entry.stat(follow_symlinks=False).st_mtime > cutoff
                ):
                    continue
                os.unlink(entry.path)
                removed += 1
            except OSError:
                logger.exception("Could not delete orphaned sample %s", entry.name)
    return removed
