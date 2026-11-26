"""Uploaded samples never outlive their scan: deleted when it finishes, and swept
hourly if anything (a crash between storing and queueing) leaves one behind."""

import os
import time
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import ScanJob
from app.models.base import utcnow
from app.scans.service import purge_expired_data
from app.scans.storage import SAMPLE_MAX_AGE, store_sample, sweep_orphan_samples


def _age(path: Path, by: timedelta) -> None:
    old = time.time() - by.total_seconds()
    os.utime(path, (old, old))


@pytest.fixture
def folder(upload_dir: Path) -> Path:
    upload_dir.mkdir(parents=True, exist_ok=True)
    for entry in upload_dir.iterdir():
        if entry.is_file() or entry.is_symlink():
            entry.unlink()
    return upload_dir


def test_sweep_removes_only_old_unreferenced_sample_files(folder: Path) -> None:
    import io

    old, _ = store_sample(io.BytesIO(b"left behind by a crash"))
    young, _ = store_sample(io.BytesIO(b"still being queued"))
    running, _ = store_sample(io.BytesIO(b"a scan is using it"))
    _age(folder / old, SAMPLE_MAX_AGE + timedelta(minutes=1))
    _age(folder / running, SAMPLE_MAX_AGE + timedelta(minutes=1))
    # Things the sweep must never touch: other names, a directory, a link.
    (folder / "README").write_text("operator's note")
    (folder / ("a" * 32 + ".bak")).write_text("not a sample name")
    (folder / ("b" * 32)).mkdir()
    target = folder.parent / "outside.txt"
    target.write_text("must survive")
    (folder / ("c" * 32)).symlink_to(target)
    for name in ("README", "a" * 32 + ".bak", "c" * 32):
        os.utime(folder / name, follow_symlinks=False)

    assert sweep_orphan_samples({running}) == 1
    remaining = {p.name for p in folder.iterdir()}
    assert old not in remaining
    assert {young, running, "README", "a" * 32 + ".bak", "b" * 32, "c" * 32} <= remaining
    assert target.read_text() == "must survive"
    target.unlink()
    (folder / ("c" * 32)).unlink()
    (folder / ("b" * 32)).rmdir()


def test_hourly_purge_sweeps_orphans_but_keeps_running_scans(db: Session, folder: Path) -> None:
    import io

    orphan, _ = store_sample(io.BytesIO(b"orphan"))
    active, _ = store_sample(io.BytesIO(b"active"))
    for name in (orphan, active):
        _age(folder / name, SAMPLE_MAX_AGE + timedelta(minutes=5))
    # A scan created just now that still refers to its (older-looking) file.
    db.add(
        ScanJob(
            id=uuid.uuid4(),
            scan_type="file",
            target="report.pdf",
            status="queued",
            payload={"storage_name": active, "file_name": "report.pdf"},
            created_at=utcnow(),
        )
    )
    db.commit()
    purge_expired_data(db)
    names = {p.name for p in folder.iterdir()}
    assert orphan not in names
    assert active in names


def test_a_stuck_scan_loses_its_sample(db: Session, folder: Path) -> None:
    import io

    stuck, _ = store_sample(io.BytesIO(b"never finished"))
    job = ScanJob(
        id=uuid.uuid4(),
        scan_type="file",
        target="x.exe",
        status="processing",
        payload={"storage_name": stuck, "file_name": "x.exe"},
        created_at=utcnow() - SAMPLE_MAX_AGE - timedelta(minutes=1),
    )
    db.add(job)
    db.commit()
    purge_expired_data(db)
    db.refresh(job)
    assert job.status == "failed" and "storage_name" not in job.payload
    assert stuck not in {p.name for p in folder.iterdir()}


def test_the_api_never_returns_where_a_sample_is_stored(client: TestClient, folder: Path) -> None:
    response = client.post(
        "/api/v1/scans/file", files={"file": ("notes.txt", b"harmless text content")}
    )
    assert response.status_code == 202
    scan = client.get(f"/api/v1/scans/{response.json()['id']}").json()
    assert "storage_name" not in str(scan)
    assert list(folder.iterdir()) == []


def test_an_inbound_email_attachment_is_removed_if_its_scan_cant_be_created(
    client: TestClient, folder: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from email.message import EmailMessage

    from app.api import channels
    from app.core.config import get_settings
    from app.scans import service

    monkeypatch.setattr(get_settings(), "inbound_email_token", "inbound-token")
    real = service.create_scan

    def failing_for_files(*args: object, **kwargs: object) -> object:
        if kwargs.get("scan_type") == "file":
            raise RuntimeError("database unavailable")
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(channels.service, "create_scan", failing_for_files)
    message = EmailMessage()
    message["From"] = "someone@example.org"
    message["Subject"] = "Please check this"
    message.set_content("Is this attachment safe to open? It came from a supplier.")
    message.add_attachment(
        b"MZ fake program", maintype="application", subtype="octet-stream", filename="a.exe"
    )
    auth = {"Authorization": "Bearer inbound-token", "Content-Type": "message/rfc822"}
    with pytest.raises(RuntimeError):
        client.post("/api/v1/inbound/email", content=message.as_bytes(), headers=auth)
    assert list(folder.iterdir()) == []
