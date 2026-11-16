import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.cli import set_role
from app.core.config import get_settings
from app.main import app
from tests.conftest import sign_up


def create_key(client: TestClient, headers: dict[str, str], name: str = "script") -> dict:
    response = client.post("/api/v1/user/api-keys", json={"name": name}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def test_api_key_scans_land_in_the_owners_history(client: TestClient) -> None:
    headers = sign_up(client)
    created = create_key(client, headers)
    assert created["key"].startswith("snt_")
    assert created["prefix"] == created["key"][:12]

    script = TestClient(app)
    auth = {"Authorization": f"Bearer {created['key']}"}
    scan = script.post(
        "/api/v1/scans/message", json={"content": "Hello, lunch on Friday?"}, headers=auth
    )
    assert scan.status_code == 202
    assert scan.json()["saved_to_history"] is True
    assert script.get("/api/v1/scans/history", headers=auth).json()["total"] == 1

    listed = client.get("/api/v1/user/api-keys").json()
    assert listed[0]["last_used_at"] is not None
    assert "key" not in listed[0]


def test_api_keys_cannot_reach_sensitive_actions(db: Session, client: TestClient) -> None:
    headers = sign_up(client)
    set_role(db, "amira@example.com", "admin")
    key = create_key(client, headers)["key"]
    auth = {"Authorization": f"Bearer {key}"}
    script = TestClient(app)
    assert script.get("/api/v1/admin/overview", headers=auth).status_code == 401
    assert script.get("/api/v1/user/export", headers=auth).status_code == 401
    assert script.post("/api/v1/user/api-keys", json={"name": "x"}, headers=auth).status_code == 401
    deletion = script.request(
        "DELETE", "/api/v1/user/account", json={"password": "x"}, headers=auth
    )
    assert deletion.status_code == 401


def test_revoked_and_invalid_keys_are_rejected(client: TestClient) -> None:
    headers = sign_up(client)
    created = create_key(client, headers)
    auth = {"Authorization": f"Bearer {created['key']}"}
    assert (
        client.delete(f"/api/v1/user/api-keys/{created['id']}", headers=headers).status_code == 204
    )
    script = TestClient(app)
    assert (
        script.get("/api/v1/scans/history", headers=auth).json()["error"]["code"]
        == "invalid_api_key"
    )
    forged = {"Authorization": "Bearer snt_not-a-real-key"}
    assert script.get("/api/v1/scans/history", headers=forged).status_code == 401


def test_active_key_limit(client: TestClient) -> None:
    headers = sign_up(client)
    for n in range(10):
        create_key(client, headers, f"key {n}")
    over = client.post("/api/v1/user/api-keys", json={"name": "one more"}, headers=headers)
    assert over.status_code == 409


def test_metrics_need_the_configured_token(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert client.get("/api/v1/system/metrics").status_code == 404
    monkeypatch.setattr(get_settings(), "metrics_token", "metrics-secret")
    assert (
        client.get("/api/v1/system/metrics", headers={"Authorization": "Bearer wrong"}).status_code
        == 404
    )

    client.post("/api/v1/scans/message", json={"content": "Hello, lunch on Friday?"})
    body = client.get(
        "/api/v1/system/metrics", headers={"Authorization": "Bearer metrics-secret"}
    ).text
    assert 'sentinel_scans_24h{type="message",status="completed"} 1' in body
    assert "sentinel_scans_stuck 0" in body
    assert "# TYPE sentinel_users gauge" in body
