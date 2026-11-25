"""The server hosts the signed qalaa-scan bundle as plain files (Wave 4.A)."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app

API = "/api/v1/updates/scan-bundle"


@pytest.fixture
def bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules/a.yar").write_text("rule a { condition: false }")
    (tmp_path / "secret.txt").write_text("not listed")
    manifest = {
        "format": 1,
        "version": "2026.11.25.1",
        "files": {"rules/a.yar": {"sha256": "0" * 64, "size": 27}},
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    (tmp_path / "manifest.sig").write_text("c2ln\n")
    monkeypatch.setattr(get_settings(), "scan_bundle_dir", tmp_path)
    return tmp_path


def test_serves_the_manifest_and_listed_files_without_a_login(bundle: Path) -> None:
    client = TestClient(app)
    assert client.get(f"{API}/manifest.json").json()["version"] == "2026.11.25.1"
    assert client.get(f"{API}/manifest.sig").text.strip() == "c2ln"
    assert client.get(f"{API}/rules/a.yar").text.startswith("rule a")


@pytest.mark.parametrize(
    "name", ["secret.txt", "../etc/passwd", "rules/../secret.txt", "%2e%2e/secret.txt"]
)
def test_nothing_outside_the_manifest_is_served(bundle: Path, name: str) -> None:
    assert TestClient(app).get(f"{API}/{name}").status_code == 404


def test_without_a_published_bundle_it_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "scan_bundle_dir", None)
    response = TestClient(app).get(f"{API}/manifest.json")
    assert response.status_code == 404
    assert "No rule bundle" in response.json()["error"]["message"]
