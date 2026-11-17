import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assess import runner, verify
from app.models import Assessment, User, VerifiedDomain
from app.models.base import utcnow
from tests.test_sharing_groups import API, account


class FakeNet:
    """Stands in for DNS and the web during assessment tests. Nothing leaves the process."""

    def __init__(self) -> None:
        self.txt: dict[str, list[str]] = {}
        self.pages: dict[str, dict] = {}
        self.mx: set[str] = set()

    def publish_dns(self, domain: str, token: str) -> None:
        self.txt.setdefault(domain, []).append(token)

    def publish_file(self, domain: str, token: str) -> None:
        self.pages[f"https://{domain}/.well-known/sentinel-verification.txt"] = {
            "status": 200,
            "body": token,
        }

    def set_page(self, url: str, **kw: object) -> None:
        self.pages[url] = kw

    def resolver(self, name: str) -> list[str]:
        return self.txt.get(name, [])

    def has_mx(self, name: str) -> bool:
        return name in self.mx

    def dnssec(self, name: str) -> bool | None:
        return False

    def file_fetcher(self, domain: str, path: str) -> tuple[int | None, str]:
        page = self.pages.get(f"https://{domain}{path}")
        return (page["status"], str(page.get("body", ""))) if page else (404, "")

    def fetch(self, url: str) -> runner.FetchResult:
        page = self.pages.get(url)
        if page is None:
            return runner.FetchResult(status=404)
        return runner.FetchResult(
            status=page.get("status"),
            headers=page.get("headers", {}),
            set_cookies=page.get("set_cookies", []),
            tls_valid_until=page.get("tls"),
            body=str(page.get("body", "")),
            redirect_location=page.get("redirect_location"),
        )


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch) -> FakeNet:
    fake = FakeNet()
    monkeypatch.setattr(runner, "_default_fetch", fake.fetch)
    monkeypatch.setattr(verify, "dns_resolver", fake.resolver)
    monkeypatch.setattr(verify, "has_mx", fake.has_mx)
    monkeypatch.setattr(verify, "dnssec_enabled", fake.dnssec)
    monkeypatch.setattr(verify, "_file_fetcher", fake.file_fetcher)
    return fake


def enable(db: Session, email: str, **limits: int) -> User:
    user = db.scalar(select(User).where(User.email == email))
    assert user is not None
    user.assessment_enabled_at = utcnow()
    for key, value in limits.items():
        setattr(user, key, value)
    db.commit()
    return user


def test_feature_is_off_until_an_admin_enables_it(db: Session, net: FakeNet) -> None:
    owner, _ = account(db, "assess0@example.com")
    assert owner.get(f"{API}/assess").status_code == 403
    assert owner.post(f"{API}/assess/domains", json={"domain": "example.com"}).status_code == 403
    enable(db, "assess0@example.com")
    status = owner.get(f"{API}/assess").json()
    assert status["enabled"] is True and status["domains"] == []


def test_domain_is_normalised_and_verified_both_ways(db: Session, net: FakeNet) -> None:
    owner, _ = account(db, "assess1@example.com")
    enable(db, "assess1@example.com")
    created = owner.post(
        f"{API}/assess/domains", json={"domain": "https://www.Example.com/path?x=1"}
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["domain"]["domain"] == "example.com"
    token = body["token"]
    domain_id = body["domain"]["id"]

    # Before the record is published, verification fails and the domain stays unverified.
    failed = owner.post(f"{API}/assess/domains/{domain_id}/verify")
    assert failed.status_code == 400
    assert owner.get(f"{API}/assess").json()["domains"][0]["verified"] is False

    # DNS method.
    net.publish_dns("example.com", token)
    ok = owner.post(f"{API}/assess/domains/{domain_id}/verify")
    assert (
        ok.status_code == 200
        and ok.json()["verified"] is True
        and ok.json()["verified_method"] == "dns"
    )

    # File method also works (second domain).
    other = owner.post(f"{API}/assess/domains", json={"domain": "example.org"}).json()
    net.publish_file("example.org", other["token"])
    verified = owner.post(f"{API}/assess/domains/{other['domain']['id']}/verify").json()
    assert verified["verified_method"] == "file"


def test_cannot_scan_an_unverified_domain(db: Session, net: FakeNet) -> None:
    owner, _ = account(db, "assess2@example.com")
    enable(db, "assess2@example.com")
    created = owner.post(f"{API}/assess/domains", json={"domain": "unverifiedco.net"}).json()
    scan = owner.post(f"{API}/assess/domains/{created['domain']['id']}/scan")
    assert scan.status_code == 409 and scan.json()["error"]["code"] == "not_verified"


def _verified_domain(db: Session, owner, net: FakeNet, domain: str) -> str:
    created = owner.post(f"{API}/assess/domains", json={"domain": domain}).json()
    net.publish_dns(domain, created["token"])
    owner.post(f"{API}/assess/domains/{created['domain']['id']}/verify")
    return created["domain"]["id"]


def test_scan_finds_real_misconfigurations_and_never_says_secure(db: Session, net: FakeNet) -> None:
    owner, _ = account(db, "assess3@example.com")
    enable(db, "assess3@example.com")
    domain_id = _verified_domain(db, owner, net, "shopco.net")
    # A site with no security headers, an exposed .env, and a session cookie without flags.
    net.set_page(
        "https://shopco.net/",
        status=200,
        headers={},
        set_cookies=["sessionid=abc; Path=/"],
        tls="Jan  5 00:00:00 2028 GMT",
    )
    net.set_page("http://shopco.net/", status=200)  # no HTTPS redirect
    net.set_page("https://shopco.net/.env", status=200, body="SECRET_KEY=hunter2\nDB_PASSWORD=x")
    net.mx.add("shopco.net")

    scan = owner.post(f"{API}/assess/domains/{domain_id}/scan")
    assert scan.status_code == 201, scan.text
    body = scan.json()
    assert body["status"] == "completed"
    titles = [f["title"] for f in body["findings"]]
    assert "An .env file is publicly readable" in titles
    assert "Plain HTTP is not redirected to HTTPS" in titles
    assert any("HSTS" in t for t in titles)
    assert body["result"] == "critical"  # worst finding drives the headline
    assert "secure" not in body["summary"].lower().split("below")[0]
    # The findings are ordered worst-first.
    assert body["findings"][0]["severity"] == "critical"
    # Every check that ran is recorded, even those with no finding.
    assert any(c["key"] == "dns" for c in body["checks"])


def test_a_clean_site_reports_no_issues_without_promising_safety(db: Session, net: FakeNet) -> None:
    owner, _ = account(db, "assess4@example.com")
    enable(db, "assess4@example.com")
    domain_id = _verified_domain(db, owner, net, "tidyco.net")
    net.set_page(
        "https://tidyco.net/",
        status=200,
        tls="Jan  5 00:00:00 2028 GMT",
        headers={
            "strict-transport-security": "max-age=63072000; includeSubDomains",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
        },
    )
    net.set_page("http://tidyco.net/", status=301, redirect_location="https://tidyco.net/")
    net.publish_dns("tidyco.net", "v=spf1 -all")
    net.txt["_dmarc.tidyco.net"] = ["v=DMARC1; p=reject; rua=mailto:d@tidyco.net"]

    body = owner.post(f"{API}/assess/domains/{domain_id}/scan").json()
    assert body["result"] == "no_issues"
    assert "not a guarantee" in body["summary"].lower()


def test_ownership_is_rechecked_at_scan_time(db: Session, net: FakeNet) -> None:
    """The core safety gate: a domain whose token is removed can no longer be scanned."""
    owner, _ = account(db, "assess5@example.com")
    enable(db, "assess5@example.com")
    domain_id = _verified_domain(db, owner, net, "lapsedco.net")
    net.set_page("https://lapsedco.net/", status=200, body="<html>secret internal app</html>")
    # The owner took the TXT record down (domain sold, or mistake).
    net.txt.pop("lapsedco.net", None)

    scan = owner.post(f"{API}/assess/domains/{domain_id}/scan")
    assert scan.status_code == 201
    body = scan.json()
    assert body["status"] == "failed"
    assert "could not confirm" in body["error"].lower()
    assert body["findings"] == []
    assert body["pages_checked"] == 0  # nothing on the site was touched
    # The domain is now marked unverified again.
    record = db.scalar(select(VerifiedDomain).where(VerifiedDomain.domain == "lapsedco.net"))
    assert record is not None and record.verified_at is None


def test_limits_and_isolation(db: Session, net: FakeNet) -> None:
    owner, _ = account(db, "assess6@example.com")
    enable(db, "assess6@example.com", assessment_domain_limit=1, assessment_monthly_limit=1)
    domain_id = _verified_domain(db, owner, net, "oneco.net")
    # Domain limit of 1.
    second = owner.post(f"{API}/assess/domains", json={"domain": "twoco.net"})
    assert second.status_code == 409 and second.json()["error"]["code"] == "domain_limit"

    net.set_page("https://oneco.net/", status=200, tls="Jan  5 00:00:00 2028 GMT")
    net.set_page("http://oneco.net/", status=301, redirect_location="https://oneco.net/")
    assert owner.post(f"{API}/assess/domains/{domain_id}/scan").status_code == 201
    # Monthly limit of 1 reached.
    limited = owner.post(f"{API}/assess/domains/{domain_id}/scan")
    assert limited.status_code == 429 and limited.json()["error"]["code"] == "monthly_limit"

    # Another account cannot see, verify, scan or read this domain.
    intruder, _ = account(db, "assess7@example.com")
    enable(db, "assess7@example.com")
    assert intruder.post(f"{API}/assess/domains/{domain_id}/verify").status_code == 404
    assert intruder.post(f"{API}/assess/domains/{domain_id}/scan").status_code == 404
    assessment = db.scalar(select(Assessment).where(Assessment.domain == "oneco.net"))
    assert assessment is not None
    assert intruder.get(f"{API}/assess/assessments/{assessment.id}").status_code == 404


def test_invalid_domains_are_rejected(db: Session, net: FakeNet) -> None:
    owner, _ = account(db, "assess8@example.com")
    enable(db, "assess8@example.com")
    for bad in ("192.168.0.1", "localhost", "router.local", "not a domain", "http://", "example"):
        response = owner.post(f"{API}/assess/domains", json={"domain": bad})
        assert response.status_code == 422, f"{bad} should be rejected, got {response.status_code}"


def test_admin_grants_and_limits_the_feature(db: Session, net: FakeNet) -> None:
    admin, _ = account(db, "assessadmin@example.com", role="admin")
    member, _ = account(db, "assessmember@example.com")
    member_id = db.scalar(select(User.id).where(User.email == "assessmember@example.com"))
    # Admin turns the feature on and sets limits.
    patched = admin.patch(
        f"{API}/admin/users/{member_id}",
        json={
            "assessment_enabled": True,
            "assessment_domain_limit": 10,
            "assessment_monthly_limit": 50,
        },
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["assessment_enabled"] is True
    assert patched.json()["assessment_domain_limit"] == 10
    # The member can now use it.
    assert member.get(f"{API}/assess").json()["domain_limit"] == 10
    # Admins themselves always have access even without the flag.
    assert admin.get(f"{API}/assess").status_code == 200
