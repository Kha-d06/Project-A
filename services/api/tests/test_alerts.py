import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.main import app
from app.models import OutboxEmail
from tests.test_sharing_groups import API, account

TOKEN = "m" * 40
BATCH = {
    "status": "firing",
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "ThreatFeedStale", "severity": "warning"},
            "annotations": {"summary": "No feed sync for 6 hours"},
        },
        {
            "status": "resolved",
            "labels": {"alertname": "ScansStuck"},
            "annotations": {"summary": "Scans are moving again"},
        },
    ],
}


@pytest.fixture
def monitoring(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "metrics_token", TOKEN)
    monkeypatch.setattr(settings, "email_backend", "outbox")


@pytest.mark.usefixtures("monitoring")
def test_alerts_are_emailed_to_admins_only(db: Session) -> None:
    account(db, "boss@example.com", role="admin")
    account(db, "member@example.com")
    client = TestClient(app)
    assert client.post(f"{API}/system/alerts", json=BATCH).status_code == 404  # no token
    assert (
        client.post(
            f"{API}/system/alerts", json=BATCH, headers={"Authorization": "Bearer wrong"}
        ).status_code
        == 404
    )
    response = client.post(
        f"{API}/system/alerts", json=BATCH, headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert response.status_code == 204, response.text
    mails = db.scalars(select(OutboxEmail).where(OutboxEmail.subject.startswith("[Qalaa]"))).all()
    assert [m.recipient for m in mails] == ["boss@example.com"]
    assert mails[0].subject == "[Qalaa] 1 alert(s) firing"
    assert "ThreatFeedStale (warning): No feed sync for 6 hours" in mails[0].body
    assert "Resolved:" in mails[0].body and "ScansStuck" in mails[0].body


def test_alerts_endpoint_is_hidden_without_a_token() -> None:
    assert TestClient(app).post(f"{API}/system/alerts", json=BATCH).status_code == 404
