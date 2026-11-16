"""Quarantine storage for uploaded samples.

Samples live outside any web-served directory under random names, are written
without execute permission, and are deleted as soon as their scan finishes.
"""

import logging
import secrets
from pathlib import Path
from typing import BinaryIO

from app.core.config import get_settings
from app.core.errors import ApiError

logger = logging.getLogger(__name__)

_COPY_CHUNK_BYTES = 1024 * 1024


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
