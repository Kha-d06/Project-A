import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.cli import set_role
from app.intel.feeds import MALWAREBAZAAR, URLHAUS, FeedIndicator
from app.main import app
from tests.conftest import PASSWORD, seed_feed, sign_up

LISTED = "http://malware.example.net/payload.exe"


def account(db: Session, email: str, role: str = "user") -> tuple[TestClient, dict[str, str]]:
    client = TestClient(app)
    headers = sign_up(client, email)
    if role != "user":
        assert set_role(db, email, role) == 0
    return client, headers


def report(client: TestClient, **fields: object) -> dict:
    body = {
        "category": "website",
        "subject": "https://parcel-fee.example.org/pay",
        "description": "Text message asking for a redelivery fee.",
        **fields,
    }
    response = client.post("/api/v1/reports", json=body)
    assert response.status_code == 201, response.text
    return response.json()


# --- Intelligence lookups -----------------------------------------------------------


def test_domain_lookup_lists_indicators_with_provenance(client: TestClient, db: Session) -> None:
    seed_feed(db, URLHAUS, [FeedIndicator("url", LISTED, "malware_download", "exe")])
    result = client.get("/api/v1/intelligence/domain/Malware.Example.NET").json()
    assert result["query"] == "malware.example.net"
    assert result["verdict"] == "listed"
    assert result["indicators"][0]["value"] == LISTED
    assert result["indicators"][0]["source"] == "urlhaus test feed"
    assert result["sources"][0]["fresh"] is True


def test_unlisted_domain_is_not_a_guarantee(client: TestClient, db: Session) -> None:
    seed_feed(db, URLHAUS, [FeedIndicator("url", LISTED, "malware_download")])
    result = client.get("/api/v1/intelligence/domain/example.org").json()
    assert result["verdict"] == "not_listed"
    assert "not a guarantee" in result["notes"][0]


def test_lookup_without_fresh_feed_is_unavailable(client: TestClient) -> None:
    assert client.get("/api/v1/intelligence/domain/example.org").json()["verdict"] == "unavailable"


def test_ip_and_hash_validation(client: TestClient, db: Session) -> None:
    assert client.get("/api/v1/intelligence/ip/10.0.0.1").json()["error"]["code"] == "private_ip"
    assert client.get("/api/v1/intelligence/ip/not-an-ip").status_code == 422
    md5 = client.get("/api/v1/intelligence/hash/" + "a" * 32).json()
    assert "MD5" in md5["error"]["message"]

    seed_feed(db, MALWAREBAZAAR, [FeedIndicator("sha256", "b" * 64, "malware")])
    assert client.get("/api/v1/intelligence/hash/" + "B" * 64).json()["verdict"] == "listed"


# --- Community reports --------------------------------------------------------------


def test_anonymous_report_is_trackable_only_with_its_token(client: TestClient, db: Session) -> None:
    created = report(client)
    token = created["tracking_token"]
    assert token
    report_id = created["report"]["id"]
    assert created["report"]["status"] == "pending"
    assert created["report"]["subject"] == "https://parcel-fee.example.org/pay"

    stranger = TestClient(app)
    assert stranger.get(f"/api/v1/reports/{report_id}").status_code == 404
    assert (
        stranger.get(f"/api/v1/reports/{report_id}", params={"token": "wrong"}).status_code == 404
    )
    assert stranger.get(f"/api/v1/reports/{report_id}", params={"token": token}).status_code == 200


def test_signed_in_reports_are_listed_and_duplicates_counted(db: Session) -> None:
    client, headers = account(db, "reporter@example.com")
    first = client.post(
        "/api/v1/reports",
        json={
            "category": "phone_number",
            "subject": "+44 20 7946 0958",
            "description": "Fake bank call asking for codes.",
        },
        headers=headers,
    ).json()
    assert first["tracking_token"] is None
    assert first["report"]["subject"] == "+442079460958"

    again = report(TestClient(app), category="phone_number", subject="0044 20 7946 0958")
    assert again["similar_reports"] == 1
    assert [r["id"] for r in client.get("/api/v1/reports/mine").json()] == [first["report"]["id"]]

    anonymous = client.post(
        "/api/v1/reports",
        json={
            "category": "job_offer",
            "subject": "Remote data entry",
            "description": "Asks for a deposit first.",
            "anonymous": True,
        },
        headers=headers,
    ).json()
    assert anonymous["tracking_token"]
    assert len(client.get("/api/v1/reports/mine").json()) == 1


def test_invalid_subjects_are_explained(client: TestClient) -> None:
    response = client.post(
        "/api/v1/reports",
        json={
            "category": "website",
            "subject": "javascript:alert(1)",
            "description": "Ten characters at least.",
        },
    )
    assert response.status_code == 422
    phone = client.post(
        "/api/v1/reports",
        json={
            "category": "phone_number",
            "subject": "123",
            "description": "Ten characters at least.",
        },
    )
    assert phone.json()["error"]["code"] in ("invalid_subject", "validation_error")


def test_moderation_requires_the_moderator_role(db: Session) -> None:
    user, _ = account(db, "user@example.com")
    assert user.get("/api/v1/admin/reports").status_code == 403
    assert TestClient(app).get("/api/v1/admin/reports").status_code == 401


def test_verified_reports_reach_scans_as_warnings_not_confirmed_threats(db: Session) -> None:
    seed_feed(db, URLHAUS, [FeedIndicator("url", LISTED, "malware_download")])
    moderator, headers = account(db, "mod@example.com", "moderator")
    website = report(TestClient(app), description="Fake parcel fee page <script>x</script>")
    phone = report(
        TestClient(app),
        category="phone_number",
        subject="+1 555 010 0199",
        description="Calls pretending to be the bank.",
    )

    queue = moderator.get("/api/v1/admin/reports").json()
    assert {item["id"] for item in queue} == {website["report"]["id"], phone["report"]["id"]}
    assert all(item["anonymous"] for item in queue)

    for item in (website, phone):
        response = moderator.post(
            f"/api/v1/admin/reports/{item['report']['id']}/review",
            json={"status": "verified", "note": "Confirmed"},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "verified"

    scan = (
        TestClient(app)
        .post("/api/v1/scans/url", json={"url": "https://parcel-fee.example.org/pay"})
        .json()
    )
    community = next(f for f in scan["findings"] if f["category"] == "community_report")
    assert community["severity"] == "high"
    assert scan["risk"] == "suspicious"  # never "known_malicious" on reports alone

    message = (
        TestClient(app)
        .post(
            "/api/v1/scans/message",
            json={"content": "Please call us back on +1 555 010 0199 today."},
        )
        .json()
    )
    assert any(f["category"] == "community_report" for f in message["findings"])

    public = TestClient(app).get("/api/v1/reports").json()
    subjects = {entry["subject"] for entry in public}
    assert "https://parcel-fee.example.org/pay" in subjects
    assert "+155••••••99" in subjects  # phone numbers are masked
    assert "description" not in public[0] and "<script>" not in str(public)

    # Overturning the verification removes the warning again.
    moderator.post(
        f"/api/v1/admin/reports/{website['report']['id']}/review",
        json={"status": "rejected", "note": "Legitimate courier"},
        headers=headers,
    )
    rescan = (
        TestClient(app)
        .post("/api/v1/scans/url", json={"url": "https://parcel-fee.example.org/pay"})
        .json()
    )
    assert not any(f["category"] == "community_report" for f in rescan["findings"])
    assert len(TestClient(app).get("/api/v1/reports").json()) == 1


def test_unverified_reports_are_never_public(client: TestClient) -> None:
    report(client)
    assert client.get("/api/v1/reports").json() == []


def test_duplicate_review_needs_an_original(db: Session) -> None:
    moderator, headers = account(db, "mod@example.com", "moderator")
    first = report(TestClient(app))["report"]["id"]
    second = report(TestClient(app))["report"]["id"]
    path = f"/api/v1/admin/reports/{second}/review"
    assert moderator.post(path, json={"status": "duplicate"}, headers=headers).status_code == 422
    ok = moderator.post(path, json={"status": "duplicate", "duplicate_of": first}, headers=headers)
    assert ok.json()["status"] == "duplicate"


# --- Administration -----------------------------------------------------------------


def test_admin_area_is_enforced_on_the_server(db: Session) -> None:
    moderator, _ = account(db, "mod@example.com", "moderator")
    for path in (
        "/api/v1/admin/overview",
        "/api/v1/admin/users",
        "/api/v1/admin/audit",
        "/api/v1/admin/scans",
    ):
        assert moderator.get(path).status_code == 403


def test_admin_overview_and_scan_monitoring_hide_scan_targets(db: Session) -> None:
    admin, _ = account(db, "admin@example.com", "admin")
    TestClient(app).post(
        "/api/v1/scans/message", json={"content": "A private message about my bank account."}
    )
    overview = admin.get("/api/v1/admin/overview").json()
    assert overview["users_total"] == 1
    assert overview["scans_24h"]["completed"] == 1
    assert overview["workers"]["detail"].startswith("Scans run inline")
    assert {feed["name"] for feed in overview["feeds"]} == {
        "URLhaus (abuse.ch)",
        "ThreatFox (abuse.ch)",
        "MalwareBazaar (abuse.ch)",
    }

    scans = admin.get("/api/v1/admin/scans").json()
    assert scans[0]["scan_type"] == "message"
    assert "target" not in scans[0] and "private message" not in str(scans)


def test_rate_limit_rejections_are_counted(db: Session) -> None:
    admin, _ = account(db, "admin@example.com", "admin")
    attacker = TestClient(app)
    for _ in range(9):
        attacker.post(
            "/api/v1/auth/login", json={"email": "admin@example.com", "password": "wrong password!"}
        )
    counts = admin.get("/api/v1/admin/overview").json()["rate_limit_rejections_24h"]
    assert counts["login-account"] == 1


def test_admin_can_manage_users_and_actions_are_audited(db: Session) -> None:
    admin, headers = account(db, "admin@example.com", "admin")
    target, _ = account(db, "target@example.com")

    found = admin.get("/api/v1/admin/users", params={"query": "TARGET"}).json()
    assert found["total"] == 1
    user_id = found["items"][0]["id"]

    promoted = admin.patch(
        f"/api/v1/admin/users/{user_id}", json={"role": "moderator"}, headers=headers
    )
    assert promoted.json()["role"] == "moderator"

    disabled = admin.patch(
        f"/api/v1/admin/users/{user_id}", json={"disabled": True}, headers=headers
    )
    assert disabled.json()["disabled"] is True
    assert target.get("/api/v1/auth/session").json()["user"] is None  # signed out everywhere
    login = TestClient(app).post(
        "/api/v1/auth/login", json={"email": "target@example.com", "password": PASSWORD}
    )
    assert login.json()["error"]["code"] == "account_disabled"

    self_id = admin.get("/api/v1/auth/session").json()["user"]["id"]
    demote_self = admin.patch(
        f"/api/v1/admin/users/{self_id}", json={"role": "user"}, headers=headers
    )
    assert demote_self.status_code == 409

    actions = [entry["action"] for entry in admin.get("/api/v1/admin/audit").json()["items"]]
    assert "admin_role_changed" in actions and "admin_account_disabled" in actions


def test_admin_feed_sync(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    admin, headers = account(db, "admin@example.com", "admin")
    monkeypatch.setattr("app.intel.feeds.download_feed", lambda url: "")
    assert admin.post("/api/v1/admin/feeds/sync", headers=headers).json() == {"status": "completed"}


def test_set_role_cli_validates_input(db: Session) -> None:
    assert set_role(db, "nobody@example.com", "admin") == 1
    account(db, "someone@example.com")
    assert set_role(db, "someone@example.com", "superuser") == 1
