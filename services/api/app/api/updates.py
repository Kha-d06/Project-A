"""Hosts the signed qalaa-scan rule and model bundle for desktop updates.

Plain files only: the desktop verifies the ed25519 signature and every
hash itself, so this route needs no authentication and learns nothing about
who asks (no account or device token). Only names listed in the bundle's
own manifest are served, so nothing else in the folder can be fetched.
"""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, Response

from app.core.config import get_settings

router = APIRouter(prefix="/updates", tags=["updates"])

_FIXED = {"manifest.json", "manifest.sig"}


def _listed(root: Path) -> set[str]:
    try:
        manifest = json.loads((root / "manifest.json").read_text())
        return {name for name in manifest.get("files", {}) if isinstance(name, str)}
    except (OSError, ValueError):
        return set()


@router.get("/scan-bundle/{name:path}", include_in_schema=False)
def scan_bundle_file(name: str) -> Response:
    root = get_settings().scan_bundle_dir
    if root is None:
        raise HTTPException(status_code=404, detail="No rule bundle is published on this server.")
    if name not in _FIXED and name not in _listed(root):
        raise HTTPException(status_code=404, detail="Not part of the bundle.")
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise HTTPException(status_code=404, detail="Not part of the bundle.")
    media = "application/json" if name.endswith(".json") else "application/octet-stream"
    return FileResponse(path, media_type=media, headers={"Cache-Control": "public, max-age=300"})
