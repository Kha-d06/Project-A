"""Devices: SENTINEL Desktop and the Android app linked to an account.

A device links with the same one-time code as the browser extension and gets a
long random token (stored as a digest). It sends a heartbeat with its
protection status every 30 seconds, and keeps one long request open
(`/devices/wait`) so a command from the website reaches it within a second.
While a scan runs it reports counts (files scanned, threats found) so the
website can show live progress.

From the website, the account holder can ask a chosen, online device to:
- run a quick, full or folder scan;
- quarantine what a scan found;
- update its fingerprints.

Safeguards:
- Remote commands only work if the device itself allows them (a setting on the device).
- Commands are a fixed set: nothing arbitrary can be run.
- Folder scans name a folder by an ID the device offered; the website never sends a path.
- Results carry file names, folder labels and verdicts, never file contents.
- Commands expire after 15 minutes if the device is offline.
"""

import uuid
from datetime import timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.api import vpn
from app.api.auth import record_event
from app.api.deps import Db, SessionUser
from app.api.extension import _redeem_link_code, build_blocklist
from app.api.vpn import PeerConfig
from app.core import rate_limit, wake
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit, client_address
from app.core.security import new_token, token_digest
from app.intel.feeds import OPENPHISH, THREATFOX, URLHAUS
from app.models import Device, DeviceCommand, User
from app.models.base import utcnow
from app.schemas.extension import Blocklist

router = APIRouter(tags=["Devices"])

TOKEN_PREFIX = "sdv_"  # noqa: S105 - a public prefix, not a secret
ONLINE_WINDOW = timedelta(seconds=90)
COMMAND_LIFETIME = timedelta(minutes=15)
# Android allows background work at most every 15 minutes, so phones check in
# less often: they count as reachable for longer and their commands wait longer.
ANDROID_ONLINE_WINDOW = timedelta(minutes=20)
ANDROID_COMMAND_LIFETIME = timedelta(minutes=35)


def _online_window(device: Device) -> timedelta:
    return ANDROID_ONLINE_WINDOW if device.platform == "android" else ONLINE_WINDOW


def _command_lifetime(device: Device) -> timedelta:
    return ANDROID_COMMAND_LIFETIME if device.platform == "android" else COMMAND_LIFETIME


MAX_DEVICES = 20
SERVER_STATUS_KEYS = ("last_scan", "last_scan_threats")
MAX_COMMANDS_KEPT = 50
REGISTER_LIMIT = RateLimit("device-register", max_requests=10, window_seconds=3600)
COMMAND_LIMIT = RateLimit("device-command", max_requests=30, window_seconds=3600)
POLL_LIMIT = RateLimit("device-poll", max_requests=600, window_seconds=3600)
WAIT_LIMIT = RateLimit("device-wait", max_requests=400, window_seconds=3600)
PROGRESS_LIMIT = RateLimit("device-progress", max_requests=2400, window_seconds=3600)
WAIT_SECONDS_MAX = 25
BLOCKLIST_LIMIT = RateLimit("device-blocklist", max_requests=12, window_seconds=3600)
_NOT_FOUND = "That device does not exist or is not linked to your account."


# --- Schemas --------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    link_code: str = Field(min_length=4, max_length=20)
    name: str = Field(min_length=1, max_length=80)
    platform: Literal["windows", "macos", "linux", "android"]
    app_version: str = Field(min_length=1, max_length=20)


class Registered(BaseModel):
    device_id: uuid.UUID
    token: str
    account_email: str


class Folder(BaseModel):
    id: str = Field(min_length=1, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")
    label: str = Field(min_length=1, max_length=80)


class Heartbeat(BaseModel):
    allow_remote: bool = False
    folders: list[Folder] = Field(default_factory=list, max_length=20)
    # Protection status, e.g. {"watching": true, "signatures": 1234, "last_scan": "..."}
    status: dict[str, Any] = Field(default_factory=dict)
    app_version: str | None = Field(default=None, max_length=20)


class CommandOut(BaseModel):
    id: uuid.UUID
    kind: str
    args: dict[str, Any]
    status: str
    result: dict[str, Any] | None
    error: str | None
    progress: dict[str, Any] | None = None
    created_at: Any
    started_at: Any
    finished_at: Any


class CommandProgress(BaseModel):
    """Live progress while a scan runs: counts only, never file names or paths."""

    scanned: int = Field(ge=0)
    found: int = Field(default=0, ge=0)
    # Optional total when the device knows it (for a progress bar).
    total: int | None = Field(default=None, ge=0)
    folder: str | None = Field(default=None, max_length=80)


class Detection(BaseModel):
    name: str = Field(max_length=255)
    folder: str | None = Field(default=None, max_length=80)
    verdict: Literal["malicious", "suspicious"]
    title: str = Field(max_length=200)
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    quarantined: bool = False


class CommandResult(BaseModel):
    ok: bool
    error: str | None = Field(default=None, max_length=300)
    scanned: int = Field(default=0, ge=0)
    malicious: int = Field(default=0, ge=0)
    suspicious: int = Field(default=0, ge=0)
    quarantined: int = Field(default=0, ge=0)
    detections: list[Detection] = Field(default_factory=list, max_length=200)
    duration_seconds: float | None = Field(default=None, ge=0)


class DeviceOut(BaseModel):
    id: uuid.UUID
    name: str
    platform: str
    app_version: str
    online: bool
    allow_remote: bool
    status: dict[str, Any]
    folders: list[dict[str, Any]]
    last_seen_at: Any
    created_at: Any
    recent_commands: list[CommandOut]


class CommandRequest(BaseModel):
    kind: Literal["quick_scan", "full_scan", "folder_scan", "quarantine", "update_signatures"]
    folder_id: str | None = Field(default=None, max_length=40)
    sha256: list[str] = Field(default_factory=list, max_length=200)


class DeviceRename(BaseModel):
    name: str = Field(min_length=1, max_length=80)


# --- Device authentication ------------------------------------------------------------


def current_device(db: Db, authorization: Annotated[str | None, Header()] = None) -> Device:
    token = (authorization or "").removeprefix("Bearer ").strip()
    if not token.startswith(TOKEN_PREFIX):
        raise ApiError(
            401, "device_unauthorized", "This device is not linked. Link it again from the app."
        )
    device = db.scalar(select(Device).where(Device.token_digest == token_digest(token)))
    if device is None or device.revoked_at is not None:
        raise ApiError(
            401,
            "device_unauthorized",
            "This device was removed from the account. Link it again from the app.",
        )
    return device


CurrentDevice = Annotated[Device, Depends(current_device)]


def _expire_old(db: Session, device: Device) -> None:
    for command in db.scalars(
        select(DeviceCommand).where(
            DeviceCommand.device_id == device.id,
            DeviceCommand.status.in_(("queued", "sent")),
            DeviceCommand.expires_at < utcnow(),
        )
    ):
        command.status = "expired"


# --- Device-side endpoints ------------------------------------------------------------


@router.post("/devices/register", response_model=Registered, status_code=201)
def register(body: RegisterRequest, request: Request, db: Db) -> Registered:
    rate_limit.enforce(REGISTER_LIMIT, client_address(request))
    user = _redeem_link_code(db, request, body.link_code)
    active = db.scalars(
        select(Device).where(Device.user_id == user.id, Device.revoked_at.is_(None))
    ).all()
    if len(active) >= MAX_DEVICES:
        raise ApiError(
            409,
            "too_many_devices",
            f"An account can have up to {MAX_DEVICES} devices. Remove one in the dashboard first.",
        )
    token = TOKEN_PREFIX + new_token()
    device = Device(
        user_id=user.id,
        name=body.name.strip(),
        platform=body.platform,
        app_version=body.app_version,
        token_digest=token_digest(token),
    )
    db.add(device)
    record_event(db, request, user, "device_linked", f"{device.platform}: {device.name}")
    db.commit()
    return Registered(device_id=device.id, token=token, account_email=user.email)


@router.post("/devices/heartbeat")
def heartbeat(body: Heartbeat, device: CurrentDevice, db: Db) -> dict[str, int]:
    rate_limit.enforce(POLL_LIMIT, f"device:{device.id}")
    device.last_seen_at = utcnow()
    device.allow_remote = body.allow_remote
    device.folders = [folder.model_dump() for folder in body.folders]
    # The server keeps its own record of remote scans; a heartbeat cannot overwrite it.
    kept = {key: device.status[key] for key in SERVER_STATUS_KEYS if key in (device.status or {})}
    reported = {
        key: value
        for key, value in list(body.status.items())[:20]
        if (isinstance(value, (str, int, float, bool)) or value is None)
        and key not in SERVER_STATUS_KEYS
    }
    device.status = {**reported, **kept}
    if body.app_version:
        device.app_version = body.app_version
    _expire_old(db, device)
    db.commit()
    pending = db.scalars(
        select(DeviceCommand.id).where(
            DeviceCommand.device_id == device.id, DeviceCommand.status == "queued"
        )
    ).all()
    return {"pending_commands": len(pending)}


@router.get("/devices/commands", response_model=list[CommandOut])
def next_commands(device: CurrentDevice, db: Db) -> list[DeviceCommand]:
    """Queued commands for this device, marked as delivered. Empty when the device
    no longer allows remote commands (they are failed instead)."""
    rate_limit.enforce(POLL_LIMIT, f"device:{device.id}")
    device.last_seen_at = utcnow()
    _expire_old(db, device)
    commands = list(
        db.scalars(
            select(DeviceCommand)
            .where(DeviceCommand.device_id == device.id, DeviceCommand.status == "queued")
            .order_by(DeviceCommand.created_at)
            .limit(5)
        )
    )
    for command in commands:
        if device.allow_remote:
            command.status = "sent"
        else:
            command.status = "failed"
            command.error = "Remote commands are turned off on this device."
            command.finished_at = utcnow()
    db.commit()
    return [command for command in commands if command.status == "sent"]


def _device_command(db: Session, device: Device, command_id: uuid.UUID) -> DeviceCommand:
    command = db.get(DeviceCommand, command_id)
    if command is None or command.device_id != device.id:
        raise ApiError(404, "command_not_found", "Unknown command.")
    return command


@router.post("/devices/commands/{command_id}/started", status_code=204)
def command_started(command_id: uuid.UUID, device: CurrentDevice, db: Db) -> None:
    command = _device_command(db, device, command_id)
    if command.status in ("sent", "queued"):
        command.status = "running"
        command.started_at = utcnow()
        db.commit()


@router.post("/devices/commands/{command_id}/progress", status_code=204)
def command_progress(
    command_id: uuid.UUID, body: CommandProgress, device: CurrentDevice, db: Db
) -> None:
    rate_limit.enforce(PROGRESS_LIMIT, f"device:{device.id}")
    command = _device_command(db, device, command_id)
    if command.status not in ("sent", "running"):
        return
    if command.status == "sent":
        command.status = "running"
        command.started_at = utcnow()
    command.progress = {**body.model_dump(exclude_none=True), "at": utcnow().isoformat()}
    device.last_seen_at = utcnow()
    db.commit()


@router.get("/devices/wait")
async def wait_for_command(
    device: CurrentDevice, db: Db, seconds: int = WAIT_SECONDS_MAX
) -> dict[str, bool]:
    """Long poll: returns {"pending": true} as soon as a command is queued for this
    device, or {"pending": false} after up to 25 seconds. The device then fetches
    its commands as usual."""
    rate_limit.enforce(WAIT_LIMIT, f"device:{device.id}")
    queued = db.scalar(
        select(DeviceCommand.id).where(
            DeviceCommand.device_id == device.id, DeviceCommand.status == "queued"
        )
    )
    device_id = device.id
    db.close()  # do not hold a database connection while waiting
    if queued is not None:
        return {"pending": True}
    return {"pending": await wake.wait(device_id, max(1, min(seconds, WAIT_SECONDS_MAX)))}


class DeviceVpnIn(BaseModel):
    public_key: str

    _key = field_validator("public_key")(classmethod(lambda cls, v: vpn._check_key(v)))


@router.post("/devices/vpn", response_model=PeerConfig, status_code=201)
def device_vpn(body: DeviceVpnIn, request: Request, device: CurrentDevice, db: Db) -> PeerConfig:
    """The desktop app's "Connect" button: adds this computer as a VPN device on the
    owner's account. The app generated the key pair and sends only the public key."""
    rate_limit.enforce(vpn.ADD_LIMIT, f"device:{device.id}")
    owner = db.get(User, device.user_id)
    if owner is None:
        raise ApiError(401, "device_unauthorized", "This device is not linked.")
    config = vpn.create_peer(
        db, owner, f"{device.name} (desktop app)", vpn._check_key(body.public_key)
    )
    record_event(db, request, owner, "vpn_device_added", config.peer.name)
    db.commit()
    return config


@router.get("/devices/blocklist", response_model=Blocklist)
def device_blocklist(device: CurrentDevice, db: Db) -> Blocklist:
    """Malicious domains and exact phishing/malware URLs for the desktop app's
    browser-history check. The app downloads the list and compares locally, so
    no browsing history is sent to the server."""
    rate_limit.enforce(BLOCKLIST_LIMIT, f"device:{device.id}")
    return build_blocklist(db, url_sources=(OPENPHISH, URLHAUS, THREATFOX), max_urls=20_000)


@router.post("/devices/commands/{command_id}/result", status_code=204)
def command_result(
    command_id: uuid.UUID, body: CommandResult, device: CurrentDevice, db: Db
) -> None:
    command = _device_command(db, device, command_id)
    if command.status in ("done", "failed", "expired"):
        return
    command.status = "done" if body.ok else "failed"
    command.error = body.error
    command.result = body.model_dump(exclude={"ok", "error"})
    command.finished_at = utcnow()
    if command.kind.endswith("_scan"):
        device.status = {
            **device.status,
            "last_scan": command.finished_at.isoformat(),
            "last_scan_threats": body.malicious + body.suspicious,
        }
    db.commit()


@router.delete("/devices/self", status_code=204)
def unlink_self(request: Request, device: CurrentDevice, db: Db) -> None:
    # Deleting the device removes its commands and results with it (cascade)
    # and invalidates its token.
    db.execute(delete(DeviceCommand).where(DeviceCommand.device_id == device.id))
    db.delete(device)
    db.commit()


# --- Account-side endpoints (website) -------------------------------------------------


def _owned(db: Session, device_id: uuid.UUID, user_id: uuid.UUID) -> Device:
    device = db.get(Device, device_id)
    if device is None or device.user_id != user_id or device.revoked_at is not None:
        raise ApiError(404, "device_not_found", _NOT_FOUND)
    return device


def _device_out(db: Session, device: Device) -> DeviceOut:
    recent = db.scalars(
        select(DeviceCommand)
        .where(DeviceCommand.device_id == device.id)
        .order_by(DeviceCommand.created_at.desc())
        .limit(10)
    ).all()
    return DeviceOut(
        id=device.id,
        name=device.name,
        platform=device.platform,
        app_version=device.app_version,
        online=utcnow() - device.last_seen_at < _online_window(device),
        allow_remote=device.allow_remote,
        status=device.status,
        folders=device.folders,
        last_seen_at=device.last_seen_at,
        created_at=device.created_at,
        recent_commands=[
            CommandOut.model_validate(command, from_attributes=True) for command in recent
        ],
    )


@router.get("/user/devices", response_model=list[DeviceOut])
def my_devices(db: Db, user: SessionUser) -> list[DeviceOut]:
    devices = db.scalars(
        select(Device)
        .where(Device.user_id == user.id, Device.revoked_at.is_(None))
        .order_by(Device.created_at)
    ).all()
    for device in devices:
        _expire_old(db, device)
    db.commit()
    return [_device_out(db, device) for device in devices]


@router.post("/user/devices/{device_id}/commands", response_model=CommandOut, status_code=201)
def send_command(
    device_id: uuid.UUID, body: CommandRequest, request: Request, db: Db, user: SessionUser
) -> DeviceCommand:
    rate_limit.enforce(COMMAND_LIMIT, f"user:{user.id}")
    device = _owned(db, device_id, user.id)
    if not device.allow_remote:
        raise ApiError(
            409,
            "remote_disabled",
            "This device does not allow scans from the website. Turn it on in the app's settings.",
        )
    if utcnow() - device.last_seen_at >= _online_window(device):
        raise ApiError(
            409,
            "device_offline",
            "This device is offline. Start the SENTINEL app on it and try again.",
        )
    args: dict[str, Any] = {}
    if body.kind == "folder_scan":
        folder = next((f for f in device.folders if f.get("id") == body.folder_id), None)
        if folder is None:
            raise ApiError(422, "unknown_folder", "Choose one of the folders this device offers.")
        args = {"folder_id": folder["id"], "folder_label": folder["label"]}
    if body.kind == "quarantine":
        hashes = sorted(
            {
                h.lower()
                for h in body.sha256
                if len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h)
            }
        )
        if not hashes:
            raise ApiError(
                422, "nothing_to_quarantine", "Choose files found by a scan on this device."
            )
        args = {"sha256": hashes}
    busy = db.scalar(
        select(DeviceCommand.id).where(
            DeviceCommand.device_id == device.id,
            DeviceCommand.kind == body.kind,
            DeviceCommand.status.in_(("queued", "sent", "running")),
        )
    )
    if busy:
        raise ApiError(409, "already_running", "That is already queued or running on this device.")
    command = DeviceCommand(
        device_id=device.id,
        requested_by_id=user.id,
        kind=body.kind,
        args=args,
        expires_at=utcnow() + _command_lifetime(device),
    )
    db.add(command)
    db.flush()
    _prune_commands(db, device)
    record_event(db, request, user, "device_command", f"{device.name}: {body.kind}")
    db.commit()
    wake.notify(device.id)
    return command


def _prune_commands(db: Session, device: Device) -> None:
    """Keep only the newest commands for a device."""
    old = db.scalars(
        select(DeviceCommand.id)
        .where(DeviceCommand.device_id == device.id)
        .order_by(DeviceCommand.created_at.desc(), DeviceCommand.id.desc())
        .offset(MAX_COMMANDS_KEPT)
    ).all()
    if old:
        db.execute(delete(DeviceCommand).where(DeviceCommand.id.in_(old)))


@router.patch("/user/devices/{device_id}", response_model=DeviceOut)
def rename_device(device_id: uuid.UUID, body: DeviceRename, db: Db, user: SessionUser) -> DeviceOut:
    device = _owned(db, device_id, user.id)
    device.name = body.name.strip()
    db.commit()
    return _device_out(db, device)


@router.delete("/user/devices/{device_id}", status_code=204)
def remove_device(device_id: uuid.UUID, request: Request, db: Db, user: SessionUser) -> None:
    device = _owned(db, device_id, user.id)
    # Deleting the device removes its commands and results with it (cascade)
    # and invalidates its token.
    record_event(db, request, user, "device_removed", device.name)
    db.execute(delete(DeviceCommand).where(DeviceCommand.device_id == device.id))
    db.delete(device)
    db.commit()
