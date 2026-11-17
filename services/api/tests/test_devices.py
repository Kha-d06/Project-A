import uuid
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Device, DeviceCommand
from app.models.base import utcnow
from tests.test_sharing_groups import account

API = "/api/v1"
SHA = "a" * 64


def link_device(
    db: Session, owner: TestClient, name: str = "Work laptop"
) -> tuple[TestClient, dict[str, str]]:
    code = owner.post(f"{API}/extension/link-codes").json()["code"]
    device = TestClient(owner.app)
    registered = device.post(
        f"{API}/devices/register",
        json={"link_code": code, "name": name, "platform": "windows", "app_version": "0.2.0"},
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
