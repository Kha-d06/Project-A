import base64
import os
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.main import app
from app.models import VpnServer
from app.models.base import utcnow
from tests.test_sharing_groups import API, account

TOKEN = "t" * 40
SERVER_KEY = base64.b64encode(b"s" * 32).decode()


def key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


@pytest.fixture
def vpn_on(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "vpn_endpoint", "vpn.example.org:51820")
    monkeypatch.setattr(settings, "vpn_sync_token", TOKEN)
    monkeypatch.setattr(settings, "vpn_max_peers_per_user", 2)


def sync(stats: list[dict[str, object]] | None = None, token: str = TOKEN) -> object:
    with TestClient(app) as server:
        return server.post(
            f"{API}/vpn/sync",
            json={"public_key": SERVER_KEY, "peers": stats or []},
            headers={"Authorization": f"Bearer {token}"},
        )


def test_vpn_is_off_until_configured(db: Session) -> None:
    user, _ = account(db, "vpn0@example.com")
    assert user.get(f"{API}/vpn").json()["enabled"] is False
    response = user.post(f"{API}/vpn/devices", json={"name": "Phone", "public_key": key()})
    assert response.json()["error"]["code"] == "vpn_disabled"
    assert sync().status_code == 401  # type: ignore[attr-defined]


@pytest.mark.usefixtures("vpn_on")
def test_vpn_device_lifecycle(db: Session) -> None:
    user, _ = account(db, "vpn1@example.com")
    phone_key = key()
    offline = user.post(f"{API}/vpn/devices", json={"name": "Phone", "public_key": phone_key})
    assert offline.json()["error"]["code"] == "vpn_offline"

    assert sync(token="wrong" * 10).status_code == 401  # type: ignore[attr-defined]
    assert sync().json() == []  # type: ignore[attr-defined]
    assert user.get(f"{API}/vpn").json()["server_online"] is True

    created = user.post(f"{API}/vpn/devices", json={"name": "Phone", "public_key": phone_key})
    assert created.status_code == 201, created.text
    config = created.json()
    assert config["address"] == "10.13.13.2/32"  # .1 is the server
    assert config["server_public_key"] == SERVER_KEY
    assert config["endpoint"] == "vpn.example.org:51820"
    assert config["allowed_ips"] == "0.0.0.0/0, ::/0"
    assert "private" not in created.text.lower()

    duplicate = user.post(f"{API}/vpn/devices", json={"name": "Copy", "public_key": phone_key})
    assert duplicate.json()["error"]["code"] == "vpn_key_in_use"
    laptop_key = key()
    laptop = user.post(f"{API}/vpn/devices", json={"name": "Laptop", "public_key": laptop_key})
    assert laptop.json()["address"] == "10.13.13.3/32"
    third = user.post(f"{API}/vpn/devices", json={"name": "Tablet", "public_key": key()})
    assert third.json()["error"]["code"] == "vpn_device_limit"

    # The server learns about both peers and reports traffic for one.
    now = int(time.time())
    peers = sync(
        [
            {
                "public_key": phone_key,
                "latest_handshake": now,
                "received_bytes": 5000,
                "sent_bytes": 900,
            }
        ]
    ).json()  # type: ignore[attr-defined]
    assert {p["address"] for p in peers} == {"10.13.13.2", "10.13.13.3"}
    devices = {d["name"]: d for d in user.get(f"{API}/vpn").json()["devices"]}
    assert devices["Phone"]["connected"] is True and devices["Phone"]["received_bytes"] == 5000
    assert devices["Laptop"]["connected"] is False

    # Counters that reset when the server restarts do not lower the totals.
    sync(
        [{"public_key": phone_key, "latest_handshake": now, "received_bytes": 10, "sent_bytes": 10}]
    )
    assert {d["name"]: d for d in user.get(f"{API}/vpn").json()["devices"]}["Phone"][
        "received_bytes"
    ] == 5000

    # Other accounts cannot remove it; the owner can, and the server drops it.
    other, _ = account(db, "vpn2@example.com")
    phone_id = devices["Phone"]["id"]
    assert other.delete(f"{API}/vpn/devices/{phone_id}").status_code == 404
    assert user.delete(f"{API}/vpn/devices/{phone_id}").status_code == 204
    remaining = sync().json()  # type: ignore[attr-defined]
    assert [p["public_key"] for p in remaining] == [laptop_key]


@pytest.mark.usefixtures("vpn_on")
def test_vpn_rejects_bad_keys_and_reports_a_silent_server(db: Session) -> None:
    user, _ = account(db, "vpn3@example.com")
    sync()
    for bad in ["short", base64.b64encode(b"x" * 31).decode(), "!" * 44]:
        assert (
            user.post(f"{API}/vpn/devices", json={"name": "X", "public_key": bad}).status_code
            == 422
        )
    server = db.get(VpnServer, 1)
    assert server is not None
    server.last_sync_at = utcnow() - timedelta(minutes=5)
    db.commit()
    assert user.get(f"{API}/vpn").json()["server_online"] is False


def test_vpn_needs_a_strong_sync_token() -> None:
    from app.core.config import Settings

    with pytest.raises(ValueError, match="VPN_SYNC_TOKEN"):
        Settings(vpn_endpoint="vpn.example.org:51820", vpn_sync_token="short")
