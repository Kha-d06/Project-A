"""The internet-side exposure check probes only the caller's own public IP."""

import pytest
from sqlalchemy.orm import Session

from app.api import network
from tests.test_sharing_groups import API, account


def test_exposure_requires_consent(db: Session) -> None:
    user, _ = account(db, "net-consent@example.com")
    response = user.post(f"{API}/network/exposure", json={"consent": False})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "consent_required"


def test_exposure_refuses_private_caller(db: Session) -> None:
    # The test client connects from a loopback/private address, which must be refused.
    user, _ = account(db, "net-private@example.com")
    response = user.post(f"{API}/network/exposure", json={"consent": True})
    assert response.status_code == 400
    assert response.json()["error"]["code"] in {"not_public", "no_public_ip"}


def test_exposure_needs_authentication(db: Session) -> None:
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as anon:
        assert anon.post(f"{API}/network/exposure", json={"consent": True}).status_code == 401


@pytest.mark.anyio
async def test_is_open_handles_closed_port() -> None:
    # Nothing is listening on this port on loopback, so the probe must report closed.
    assert await network._is_open("127.0.0.1", 9, timeout=0.5) is False


def test_check_ports_are_remote_control_services() -> None:
    ports = {port for port, _, _ in network.CHECK_PORTS}
    # The dangerous remote-control/file-sharing ports are all covered.
    assert {23, 445, 3389, 5900, 5555}.issubset(ports)
