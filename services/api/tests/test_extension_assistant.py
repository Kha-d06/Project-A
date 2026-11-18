import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.ai import assistant
from app.core.config import get_settings
from app.intel.feeds import THREATFOX, URLHAUS, FeedIndicator
from tests.conftest import seed_feed
from tests.test_extension import EXT, bearer, enroll

CONTEXT = {
    "host": "paypa1-login.example.com",
    "verdict": "suspicious",
    "warning_signs": ["Look-alike of paypal.com"],
    "cookies": [
        {
            "name": "_ga",
            "domain": ".example.com",
            "third_party": False,
            "session": False,
            "days": 400,
        }
    ],
    "trackers": ["Google Analytics"],
    "has_password_field": True,
}


def test_blocklist_contains_only_domain_indicators(client: TestClient, db: Session) -> None:
    seed_feed(
        db,
        THREATFOX,
        [
            FeedIndicator("host", "evil-c2.example.net", "botnet_cc"),
            FeedIndicator("host", "203.0.113.9", "botnet_cc"),
        ],
    )
    seed_feed(db, URLHAUS, [FeedIndicator("url", "http://shared-host.example.org/bad.exe", "x")])
    credentials = enroll(client)
    response = client.get(f"{EXT}/blocklist", headers=bearer(credentials))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["hosts"] == ["evil-c2.example.net"]
    assert "shared-host.example.org" not in body["hosts"]
    assert body["version"].startswith("1-")


def test_blocklist_needs_extension_credentials(client: TestClient) -> None:
    assert client.get(f"{EXT}/blocklist").status_code == 401


def test_assistant_unavailable_without_ai(client: TestClient) -> None:
    credentials = enroll(client)
    response = client.post(
        f"{EXT}/assistant",
        json={"question": "Is this site safe?", "context": CONTEXT},
        headers=bearer(credentials),
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "assistant_unavailable"


def test_assistant_sends_only_the_summary(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[dict] = []

    def respond(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        text = "Qalaa found warning signs. Do not sign in. More at https://evil.example/"
        return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})

    original = httpx.Client
    monkeypatch.setattr(
        assistant.httpx, "Client", lambda **kw: original(transport=httpx.MockTransport(respond))
    )
    monkeypatch.setattr(get_settings(), "openai_api_key", "k")
    monkeypatch.setattr(get_settings(), "openai_model", "m")
    credentials = enroll(client)
    response = client.post(
        f"{EXT}/assistant",
        json={"question": "هل هذا الموقع آمن؟", "language": "ar", "context": CONTEXT},
        headers=bearer(credentials),
    )
    assert response.status_code == 200, response.text
    reply = response.json()
    assert "evil.example" not in reply["answer"] and reply["ai_generated"] is True
    document = json.loads(sent[0]["messages"][1]["content"])
    assert document["answer_language"] == "Arabic"
    assert set(document["site"]) == set(CONTEXT)
    assert "value" not in document["site"]["cookies"][0]
    assert "secret-session-id" not in sent[0]["messages"][1]["content"]


def test_assistant_rejects_oversized_context(client: TestClient) -> None:
    credentials = enroll(client)
    bad = {**CONTEXT, "trackers": ["x"] * 41}
    response = client.post(
        f"{EXT}/assistant",
        json={"question": "hi there", "context": bad},
        headers=bearer(credentials),
    )
    assert response.status_code == 422
