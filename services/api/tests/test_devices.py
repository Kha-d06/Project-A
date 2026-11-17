import uuid
from datetime import UTC, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Device, DeviceCommand
from app.models.base import utcnow
from tests.test_sharing_groups import account

API = "/api/v1"
SHA = "a" * 64


def link_device(
    db: Session, owner: TestClient, name: str = "Work laptop", platform: str = "windows"
) -> tuple[TestClient, dict[str, str]]:
    code = owner.post(f"{API}/extension/link-codes").json()["code"]
    device = TestClient(owner.app)
    registered = device.post(
        f"{API}/devices/register",
        json={"link_code": code, "name": name, "platform": platform, "app_version": "0.2.0"},
    )
    assert registered.status_code == 201, registered.text
    return device, {"Authorization": f"Bearer {registered.json()['token']}"}


def heartbeat(device: TestClient, auth: dict[str, str], allow_remote: bool = True) -> None:
    response = device.post(
        f"{API}/devices/heartbeat",
        json={
            "allow_remote": allow_remote,
            "folders": [
                {"id": "downloads", "label": "Downloads"},
                {"id": "documents", "label": "Documents"},
            ],
            "status": {"watching": True, "signatures": 1200, "nested": {"dropped": True}},
        },
        headers=auth,
    )
    assert response.status_code == 200, response.text


def test_remote_scan_round_trip(db: Session) -> None:
    owner, _ = account(db, "devices@example.com")
    device, auth = link_device(db, owner)
    heartbeat(device, auth)

    listed = owner.get(f"{API}/user/devices").json()
    assert listed[0]["online"] is True and listed[0]["allow_remote"] is True
    assert listed[0]["status"] == {"watching": True, "signatures": 1200}  # nested values dropped
    device_id = listed[0]["id"]

    command = owner.post(
        f"{API}/user/devices/{device_id}/commands",
        json={"kind": "folder_scan", "folder_id": "documents"},
    )
    assert command.status_code == 201, command.text
    assert command.json()["args"] == {"folder_id": "documents", "folder_label": "Documents"}
    assert (
        owner.post(
            f"{API}/user/devices/{device_id}/commands",
            json={"kind": "folder_scan", "folder_id": "documents"},
        ).status_code
        == 409
    )
    assert (
        owner.post(
            f"{API}/user/devices/{device_id}/commands",
            json={"kind": "folder_scan", "folder_id": "../etc"},
        ).status_code
        == 422
    )

    pending = device.get(f"{API}/devices/commands", headers=auth).json()
    assert [c["kind"] for c in pending] == ["folder_scan"]
    assert device.get(f"{API}/devices/commands", headers=auth).json() == []  # delivered once
    command_id = pending[0]["id"]
    device.post(f"{API}/devices/commands/{command_id}/started", headers=auth)
    result = {
        "ok": True,
        "scanned": 120,
        "malicious": 1,
        "suspicious": 0,
        "detections": [
            {
                "name": "invoice.pdf.exe",
                "folder": "Documents",
                "verdict": "malicious",
                "title": "This file is known malware",
                "sha256": SHA,
            }
        ],
        "duration_seconds": 4.2,
    }
    assert (
        device.post(
            f"{API}/devices/commands/{command_id}/result", json=result, headers=auth
        ).status_code
        == 204
    )

    view = owner.get(f"{API}/user/devices").json()[0]
    done = view["recent_commands"][0]
    assert done["status"] == "done" and done["result"]["detections"][0]["name"] == "invoice.pdf.exe"
    assert view["status"]["last_scan_threats"] == 1
    # A later heartbeat keeps the server's record of the scan and cannot forge it.
    device.post(
        f"{API}/devices/heartbeat",
        json={
            "allow_remote": True,
            "folders": [],
            "status": {"last_scan_threats": 0, "signatures": 5},
        },
        headers=auth,
    )
    status = owner.get(f"{API}/user/devices").json()[0]["status"]
    assert status["last_scan_threats"] == 1 and "last_scan" in status and status["signatures"] == 5

    quarantine = owner.post(
        f"{API}/user/devices/{device_id}/commands",
        json={"kind": "quarantine", "sha256": [SHA, "not-a-hash"]},
    )
    assert quarantine.json()["args"] == {"sha256": [SHA]}


def test_remote_commands_need_the_devices_permission_and_presence(db: Session) -> None:
    owner, _ = account(db, "devices2@example.com")
    device, auth = link_device(db, owner)
    heartbeat(device, auth, allow_remote=False)
    device_id = owner.get(f"{API}/user/devices").json()[0]["id"]
    refused = owner.post(f"{API}/user/devices/{device_id}/commands", json={"kind": "quick_scan"})
    assert refused.json()["error"]["code"] == "remote_disabled"

    heartbeat(device, auth, allow_remote=True)
    stored = db.get(Device, __import__("uuid").UUID(device_id))
    stored.last_seen_at = utcnow() - timedelta(minutes=5)
    db.commit()
    offline = owner.post(f"{API}/user/devices/{device_id}/commands", json={"kind": "quick_scan"})
    assert offline.json()["error"]["code"] == "device_offline"


def test_commands_expire_and_other_accounts_cannot_reach_a_device(db: Session) -> None:
    owner, _ = account(db, "devices3@example.com")
    stranger, _ = account(db, "stranger3@example.com")
    device, auth = link_device(db, owner)
    heartbeat(device, auth)
    device_id = owner.get(f"{API}/user/devices").json()[0]["id"]
    assert (
        stranger.post(
            f"{API}/user/devices/{device_id}/commands", json={"kind": "quick_scan"}
        ).status_code
        == 404
    )

    owner.post(f"{API}/user/devices/{device_id}/commands", json={"kind": "quick_scan"})
    command = db.scalar(select(DeviceCommand))
    command.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    assert device.get(f"{API}/devices/commands", headers=auth).json() == []
    db.refresh(command)
    assert command.status == "expired"


def test_removed_device_loses_access(db: Session) -> None:
    owner, _ = account(db, "devices4@example.com")
    device, auth = link_device(db, owner)
    device_id = owner.get(f"{API}/user/devices").json()[0]["id"]
    assert owner.delete(f"{API}/user/devices/{device_id}").status_code == 204
    assert device.get(f"{API}/devices/commands", headers=auth).status_code == 401
    assert (
        device.get(
            f"{API}/devices/commands", headers={"Authorization": "Bearer sdv_wrong"}
        ).status_code
        == 401
    )


def test_removal_deletes_history_and_old_commands_are_pruned(db: Session) -> None:
    owner, _ = account(db, "devices5@example.com")
    device, auth = link_device(db, owner)
    heartbeat(device, auth)
    device_id = owner.get(f"{API}/user/devices").json()[0]["id"]
    stored = db.get(Device, uuid.UUID(device_id))
    assert stored is not None
    stored_id = stored.id
    for index in range(55):
        db.add(
            DeviceCommand(
                device_id=stored_id,
                kind="update_signatures",
                args={},
                status="done",
                created_at=utcnow() - timedelta(hours=index + 1),
                expires_at=utcnow(),
            )
        )
    db.commit()
    assert (
        owner.post(
            f"{API}/user/devices/{device_id}/commands", json={"kind": "quick_scan"}
        ).status_code
        == 201
    )
    db.expire_all()
    assert (
        len(db.scalars(select(DeviceCommand).where(DeviceCommand.device_id == stored_id)).all())
        == 50
    )

    assert device.delete(f"{API}/devices/self", headers=auth).status_code == 204
    db.expire_all()
    assert db.get(Device, uuid.UUID(device_id)) is None
    assert db.scalars(select(DeviceCommand).where(DeviceCommand.device_id == stored_id)).all() == []


def test_phones_check_in_less_often_and_their_commands_wait_longer(db: Session) -> None:
    owner, _ = account(db, "devices6@example.com")
    phone, auth = link_device(db, owner, name="Pixel 9", platform="android")
    heartbeat(phone, auth)
    phone_id = owner.get(f"{API}/user/devices").json()[0]["id"]
    stored = db.get(Device, uuid.UUID(phone_id))
    assert stored is not None
    stored.last_seen_at = utcnow() - timedelta(minutes=12)
    db.commit()
    view = owner.get(f"{API}/user/devices").json()[0]
    assert view["platform"] == "android" and view["online"] is True
    command = owner.post(f"{API}/user/devices/{phone_id}/commands", json={"kind": "quick_scan"})
    assert command.status_code == 201, command.text
    queued = db.get(DeviceCommand, uuid.UUID(command.json()["id"]))
    assert queued is not None
    expires = (
        queued.expires_at if queued.expires_at.tzinfo else queued.expires_at.replace(tzinfo=UTC)
    )
    assert timedelta(minutes=30) < expires - utcnow() <= timedelta(minutes=35)

    stored.last_seen_at = utcnow() - timedelta(minutes=25)
    db.commit()
    assert owner.get(f"{API}/user/devices").json()[0]["online"] is False


def test_live_progress_and_instant_wake(db: Session) -> None:
    owner, _ = account(db, "progress@example.com")
    device, auth = link_device(db, owner)
    heartbeat(device, auth)
    device_id = owner.get(f"{API}/user/devices").json()[0]["id"]

    # Nothing queued: the long poll waits, then says so.
    idle = device.get(f"{API}/devices/wait?seconds=1", headers=auth)
    assert idle.status_code == 200 and idle.json() == {"pending": False}

    # Queuing a command wakes the device straight away.
    command = owner.post(f"{API}/user/devices/{device_id}/commands", json={"kind": "full_scan"})
    assert device.get(f"{API}/devices/wait?seconds=25", headers=auth).json() == {"pending": True}
    sent = device.get(f"{API}/devices/commands", headers=auth).json()
    command_id = sent[0]["id"]
    assert command_id == command.json()["id"]

    # Progress is counts only, visible to the owner while it runs.
    progress = device.post(
        f"{API}/devices/commands/{command_id}/progress",
        json={"scanned": 120, "found": 1, "total": 400, "folder": "Home"},
        headers=auth,
    )
    assert progress.status_code == 204
    running = owner.get(f"{API}/user/devices").json()[0]["recent_commands"][0]
    assert running["status"] == "running"
    assert running["progress"]["scanned"] == 120 and running["progress"]["total"] == 400
    bad = device.post(
        f"{API}/devices/commands/{command_id}/progress",
        json={"scanned": -1},
        headers=auth,
    )
    assert bad.status_code == 422

    # Another device cannot report progress on it, and finished commands ignore it.
    other_owner, _ = account(db, "progress-other@example.com")
    other_device, other_auth = link_device(db, other_owner)
    assert (
        other_device.post(
            f"{API}/devices/commands/{command_id}/progress",
            json={"scanned": 1},
            headers=other_auth,
        ).status_code
        == 404
    )
    device.post(
        f"{API}/devices/commands/{command_id}/result",
        json={"ok": True, "scanned": 400},
        headers=auth,
    )
    device.post(f"{API}/devices/commands/{command_id}/progress", json={"scanned": 5}, headers=auth)
    done = owner.get(f"{API}/user/devices").json()[0]["recent_commands"][0]
    assert done["status"] == "done" and done["progress"]["scanned"] == 120


def test_device_blocklist_includes_exact_urls_for_the_history_check(db: Session) -> None:
    from app.intel.feeds import OPENPHISH, THREATFOX, FeedIndicator
    from tests.conftest import seed_feed

    seed_feed(db, THREATFOX, [FeedIndicator("host", "evil-c2.example.net", "botnet_cc")])
    seed_feed(
        db, OPENPHISH, [FeedIndicator("url", "https://shared.example.org/login/bank", "phishing")]
    )
    owner, _ = account(db, "history@example.com")
    device, auth = link_device(db, owner)
    assert device.get(f"{API}/devices/blocklist").status_code == 401
    body = device.get(f"{API}/devices/blocklist", headers=auth).json()
    assert body["hosts"] == ["evil-c2.example.net"]
    assert body["urls"] == ["https://shared.example.org/login/bank"]
    # The shared host itself is never blocked outright.
    assert "shared.example.org" not in body["hosts"]
