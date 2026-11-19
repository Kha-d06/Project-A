"""Email checks: header signals, link mismatches, the endpoint, nothing stored."""

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analyzers.email_check import analyze_email, auth_results
from app.models import ScanJob

API = "/api/v1"


def _titles(payload: dict, db: Session) -> list[str]:
    base = {"text": "Hello, see you at the meeting tomorrow.", "from_header": ""}
    return [f.title for f in analyze_email({**base, **payload}, db).findings]


def test_auth_results_reads_first_result_per_method() -> None:
    header = "mx.example; spf=pass smtp.mailfrom=a.example; dkim=fail; dmarc=FAIL (p=reject)"
    assert auth_results(header) == {"spf": "pass", "dkim": "fail", "dmarc": "fail"}


def test_header_signals(db: Session) -> None:
    assert "The sender's domain says this email is not from it" in _titles(
        {"from_header": "a@bank.example", "authentication_results": "dmarc=fail"}, db
    )
    assert "This email could not prove where it came from" in _titles(
        {"from_header": "a@bank.example", "authentication_results": "spf=softfail dkim=none"}, db
    )
    assert "The sender claims to be PayPal" in _titles(
        {"from_header": "PayPal Service <notice@pay-help.example>"}, db
    )
    assert "The sender claims to be PayPal" not in _titles(
        {"from_header": "PayPal <service@paypal.com>"}, db
    )
    assert "The sender's name shows a different address" in _titles(
        {"from_header": '"support@bank.com" <x@cheap-mail.example>'}, db
    )
    assert "Replies would go to a different domain" in _titles(
        {"from_header": "a@shop.example", "reply_to": "b@elsewhere.example"}, db
    )
    # A reply address on the same domain is ordinary.
    assert (
        _titles({"from_header": "a@shop.example", "reply_to": "help@mail.shop.example"}, db) == []
    )


def test_link_text_that_names_another_site(db: Session) -> None:
    links = [{"text": "www.mybank.com/login", "href": "https://login-check.example/x"}]
    assert "A link shows one address but opens another" in _titles(
        {"from_header": "a@mybank.com", "links": links}, db
    )
    same = [{"text": "mybank.com", "href": "https://www.mybank.com/offers"}]
    assert "A link shows one address but opens another" not in _titles(
        {"from_header": "a@mybank.com", "links": same}, db
    )


def test_endpoint_answers_without_storing(client: TestClient, db: Session) -> None:
    before = db.scalar(select(func.count()).select_from(ScanJob))
    body = {
        "from_header": "Apple Support <id@apple-verify.example>",
        "subject": "Your account will be suspended",
        "authentication_results": "spf=fail dkim=fail dmarc=fail",
        "text": "Verify your account within 24 hours or it will be closed.",
        "links": [{"text": "appleid.apple.com", "href": "http://apple-verify.example/login"}],
    }
    response = client.post(f"{API}/email/check", json=body)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["risk"] in ("suspicious", "known_malicious")
    assert result["findings"][0]["severity"] in ("critical", "high")
    assert db.scalar(select(func.count()).select_from(ScanJob)) == before

    quiet = client.post(
        f"{API}/email/check",
        json={"from_header": "friend@example.org", "text": "Lunch on Thursday?"},
    ).json()
    assert quiet["findings"] == [] and quiet["risk"] in ("no_known_threat", "inconclusive")
    assert client.post(f"{API}/email/check", json={"text": "x"}).status_code == 422
