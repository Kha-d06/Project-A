import io
import json
from pathlib import Path

import httpx
import pytest
import zxingcpp
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw
from sqlalchemy.orm import Session

from app.ai import vision
from app.analyzers.urls import parse_url
from app.core.config import get_settings
from app.intel.feeds import URLHAUS, FeedIndicator
from tests.conftest import seed_feed

LISTED = "http://malware.example.net/payload.exe"


def screenshot(with_qr: str | None = None) -> bytes:
    image = Image.new("RGB", (600, 900), "white")
    ImageDraw.Draw(image).text((20, 20), "Your parcel is held. Pay now.", fill="black")
    if with_qr:
        code = zxingcpp.create_barcode(with_qr, zxingcpp.BarcodeFormat.QRCode).to_image(scale=6)
        qr = Image.frombytes("L", (code.shape[1], code.shape[0]), bytes(code))
        image.paste(qr, (150, 300))
    out = io.BytesIO()
    image.save(out, format="PNG", pnginfo=None)
    return out.getvalue()


def post(client: TestClient, content: bytes, consent: bool) -> dict:
    response = client.post(
        "/api/v1/scans/screenshot",
        files={"file": ("chat.png", content)},
        data={"ai_consent": "true" if consent else "false"},
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_without_consent_only_qr_codes_are_checked(client: TestClient, db: Session) -> None:
    seed_feed(db, URLHAUS, [FeedIndicator("url", parse_url(LISTED).normalized, "malware_download")])
    scan = post(client, screenshot(with_qr=LISTED), consent=False)
    assert scan["risk"] == "known_malicious"
    assert any("not read" in item for item in scan["limitations"])
    assert all(check["key"] != "ai_reading" for check in scan["checks"])


def test_with_consent_text_is_read_and_judged_by_rules(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_feed(db, URLHAUS, [FeedIndicator("url", parse_url(LISTED).normalized, "malware_download")])
    sent: list[dict] = []

    def respond(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        answer = {
            "text": "Your account will be suspended. Send me the verification code you received now.",
            "urls": [LISTED],
            "phones": [],
            "label": "likely_scam",
            "reason": "Asks for a code under pressure.",
        }
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(answer)}}]})

    original = httpx.Client
    monkeypatch.setattr(
        vision.httpx, "Client", lambda **kw: original(transport=httpx.MockTransport(respond))
    )
    monkeypatch.setattr(get_settings(), "openai_api_key", "k")
    monkeypatch.setattr(get_settings(), "openai_model", "vision-model")

    scan = post(client, screenshot(), consent=True)
    categories = {finding["category"] for finding in scan["findings"]}
    assert {"credential_request", "threat_intelligence", "ai_opinion"} <= categories
    assert scan["risk"] == "known_malicious"
    image_part = sent[0]["messages"][1]["content"][0]["image_url"]["url"]
    assert image_part.startswith("data:image/jpeg;base64,")


def test_consent_without_ai_provider_is_reported_honestly(client: TestClient) -> None:
    scan = post(client, screenshot(), consent=True)
    reading = next(check for check in scan["checks"] if check["key"] == "ai_reading")
    assert reading["status"] == "unavailable"
    assert scan["risk"] == "inconclusive"


def test_image_metadata_is_stripped(tmp_path: Path) -> None:
    path = tmp_path / "photo.jpg"
    image = Image.new("RGB", (3000, 2000), "white")
    exif = Image.Exif()
    exif[0x010F] = "PhoneMaker"  # camera make
    exif[0x0131] = "Gallery 2.0"  # software
    image.save(path, format="JPEG", exif=exif.tobytes())
    assert Image.open(path).getexif()
    data_url = vision.clean_image(str(path))
    import base64

    cleaned = Image.open(io.BytesIO(base64.b64decode(data_url.split(",", 1)[1])))
    assert max(cleaned.size) <= 1600
    assert not cleaned.getexif()
