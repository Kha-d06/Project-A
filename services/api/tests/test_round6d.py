"""Security score, identity monitoring, group policies and compliance, STIX export."""

import re
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import score
from app.api import breach
from app.core.config import get_settings
from app.groups_policy import MemberFacts, clean_policies, compliance
from app.intel.feeds import COMMUNITY, FeedIndicator
from app.intel.stix import TLP_CLEAR, bundle, pattern_for
from app.models import OutboxEmail, User
from app.models.base import utcnow
from app.notify.breaches import check_identities
from tests.conftest import seed_feed
from tests.test_devices import heartbeat, link_device
from tests.test_extension import EXT, bearer, enroll
from tests.test_sharing_groups import API, account


@pytest.fixture
def outbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "email_backend", "outbox")


def last_code(db: Session, address: str) -> str:
    mail = db.scalars(
        select(OutboxEmail)
        .where(OutboxEmail.recipient == address)
        .order_by(OutboxEmail.created_at.desc())
    ).first()
    assert mail is not None
    match = re.search(r"code on the Breach check page: (\d{6})", mail.body)
    assert match
    return match.group(1)


# --- Security score -----------------------------------------------------------------------


def test_score_counts_only_steps_that_apply() -> None:
    nothing = score.compute({})
    assert nothing["score"] == 0 and nothing["grade"] == "weak"
    full = score.compute({step.key: True for step in score.STEPS})
    assert full["score"] == 100 and full["grade"] == "strong"
    # Without a VPN or breach service, those steps are left out, not counted against anyone.
    available = {
        "email_verified",
        "two_factor",
        "password_manager",
        "extension",
        "device_protected",
    }
    partial = score.compute({"email_verified": True, "two_factor": True}, available)
    assert partial["score"] == round(30 * 100 / 75)
    assert {s["key"] for s in partial["steps"]} == available  # type: ignore[union-attr]
    assert partial["steps"][0]["done"] is False  # type: ignore[index]  # open steps first


def test_security_score_endpoint(db: Session) -> None:
    client, _ = account(db, "score@example.com")
    first = client.get(f"{API}/user/security-score").json()
    keys = {s["key"]: s["done"] for s in first["steps"]}
    assert keys["two_factor"] is False and keys["device_protected"] is False
    assert "vpn" not in keys  # this server has no VPN

    device, auth = link_device(db, client)
    heartbeat(device, auth)
    device_id = client.get(f"{API}/user/devices").json()[0]["id"]
    command = client.post(f"{API}/user/devices/{device_id}/commands", json={"kind": "full_scan"})
    device.get(f"{API}/devices/commands", headers=auth)
    device.post(
        f"{API}/devices/commands/{command.json()['id']}/result",
        json={"ok": True, "scanned": 10},
        headers=auth,
    )
    after = client.get(f"{API}/user/security-score").json()
    assert {s["key"]: s["done"] for s in after["steps"]}["device_protected"] is True
    assert after["score"] > first["score"]


# --- Identity monitoring --------------------------------------------------------------------


@pytest.mark.usefixtures("outbox")
def test_identity_needs_the_code_sent_to_that_address(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "hibp_api_key", "k")
    listed = [{"Name": "ShopLeak", "Title": "Shop Leak", "DataClasses": ["Passwords"]}]
    monkeypatch.setattr(
        breach.httpx,
        "get",
        lambda url, params, headers, timeout: httpx.Response(200, json=list(listed)),
    )
    client, _ = account(db, "ident@example.com")
    assert (
        client.post(f"{API}/identity", json={"email": "ident@example.com"}).json()["error"]["code"]
        == "already_monitored"
    )
    assert client.post(f"{API}/identity", json={"email": "not an email"}).status_code == 422
    added = client.post(f"{API}/identity", json={"email": "Old.Address@Example.com"})
    assert added.status_code == 201, added.text
    item = added.json()
    assert item["email"] == "old.address@example.com" and item["verified"] is False
    assert item["breaches"] == []  # nothing is checked before confirmation

    for _ in range(5):
        wrong = client.post(f"{API}/identity/{item['id']}/verify", json={"code": "000000"})
        if wrong.status_code != 422:
            break
    blocked = client.post(
        f"{API}/identity/{item['id']}/verify",
        json={"code": last_code(db, "old.address@example.com")},
    )
    assert blocked.status_code == 429  # too many wrong codes: a new one is needed

    client.post(f"{API}/identity/{item['id']}/resend")
    code = last_code(db, "old.address@example.com")
    other, _ = account(db, "ident-other@example.com")
    assert other.post(f"{API}/identity/{item['id']}/verify", json={"code": code}).status_code == 404
    confirmed = client.post(f"{API}/identity/{item['id']}/verify", json={"code": code}).json()
    assert confirmed["verified"] is True
    assert confirmed["breaches"][0]["title"] == "Shop Leak"

    # The weekly check reports only new breaches, to the account holder.
    assert check_identities(db) == 0
    listed.append({"Name": "Forum", "Title": "Forum Leak", "DataClasses": ["Emails"]})
    assert check_identities(db) == 1
    mail = db.scalars(
        select(OutboxEmail).where(
            OutboxEmail.recipient == "ident@example.com",
            OutboxEmail.subject.contains("monitored address"),
        )
    ).all()
    assert len(mail) == 1 and "Forum Leak" in mail[0].body and "Shop Leak" not in mail[0].body

    assert client.delete(f"{API}/identity/{item['id']}").status_code == 204
    assert client.get(f"{API}/identity").json()["identities"] == []


def test_identity_needs_email_delivery(db: Session) -> None:
    client, _ = account(db, "ident-noemail@example.com")
    response = client.post(f"{API}/identity", json={"email": "x@example.org"})
    assert response.status_code == 503


# --- Group policies ---------------------------------------------------------------------------


def test_policy_cleaning_and_compliance_rules() -> None:
    assert clean_policies("family", {"safe_search": True, "require_2fa": True}) == {
        "safe_search": True
    }
    assert clean_policies(
        "organisation", {"require_2fa": True, "max_days_since_scan": 0, "safe_search": True}
    ) == {"require_2fa": True}
    with pytest.raises(ValueError):
        clean_policies("organisation", {"max_days_since_scan": 400})
    now = datetime(2026, 11, 18, tzinfo=UTC)
    rules = {"require_2fa": True, "require_extension": True, "max_days_since_scan": 7}
    good = MemberFacts(True, True, 1, now - timedelta(days=2), 0)
    assert compliance(rules, good, now) == []
    stale = MemberFacts(False, False, 1, now - timedelta(days=9), 2)
    assert compliance(rules, stale, now) == [
        "no_2fa",
        "no_extension",
        "scan_overdue",
        "threats_found",
    ]
    assert compliance(rules, MemberFacts(True, True, 0, None, 0), now) == ["no_device"]


def _join(db: Session, owner, member_email: str, kind: str) -> tuple[dict, object]:
    member, _ = account(db, member_email)
    group = owner.post(f"{API}/groups", json={"name": "Team", "kind": kind}).json()
    invite = owner.post(f"{API}/groups/{group['id']}/invites", json={"email": member_email}).json()
    member.post(f"{API}/groups/invites/accept", json={"token": invite["url"].split("invite=")[1]})
    return group, member


def test_family_rules_reach_only_members_who_follow_them(db: Session) -> None:
    parent, _ = account(db, "rules-parent@example.com")
    group, child = _join(db, parent, "rules-child@example.com", "family")
    updated = parent.put(
        f"{API}/groups/{group['id']}/policies",
        json={"safe_search": True, "lock_protection": True, "require_2fa": True},
    )
    assert updated.status_code == 200
    assert updated.json()["policies"] == {"safe_search": True, "lock_protection": True}
    child_id = next(m["user_id"] for m in updated.json()["members"] if m["role"] == "member")
    assert child.put(f"{API}/groups/{group['id']}/policies", json={}).status_code == 403

    # The child's browser is linked; the rules apply only once the child follows them.
    code = child.post(f"{API}/extension/link-codes").json()["code"]
    child_client = TestClient(child.app)
    credentials = enroll(child_client, link_code=code)
    before = child_client.get(f"{EXT}/settings", headers=bearer(credentials)).json()
    assert before["safe_search"] is False and before["lock_protection"] is False
    child.patch(f"{API}/groups/{group['id']}/members/{child_id}", json={"apply_blocklist": True})
    after = child_client.get(f"{EXT}/settings", headers=bearer(credentials)).json()
    assert after["safe_search"] is True and after["lock_protection"] is True
    assert after["family_groups"] == ["Team"]


def test_organisation_compliance_shows_only_members_who_share(db: Session) -> None:
    boss, _ = account(db, "org-boss@example.com")
    group, worker = _join(db, boss, "org-worker@example.com", "organisation")
    boss.put(
        f"{API}/groups/{group['id']}/policies",
        json={"require_2fa": True, "max_days_since_scan": 7},
    )
    view = boss.get(f"{API}/groups/{group['id']}/compliance").json()
    member = next(m for m in view["members"] if m["email"] == "org-worker@example.com")
    assert member["shared"] is False and member["two_factor"] is None and member["problems"] == []
    assert worker.get(f"{API}/groups/{group['id']}/compliance").status_code == 403

    worker_id = member["user_id"]
    worker.patch(f"{API}/groups/{group['id']}/members/{worker_id}", json={"share_activity": True})
    view = boss.get(f"{API}/groups/{group['id']}/compliance").json()
    member = next(m for m in view["members"] if m["email"] == "org-worker@example.com")
    assert member["shared"] is True
    assert member["problems"] == ["no_2fa", "no_device"]
    assert view["sharing"] == 1 and view["compliant"] == 0


# --- STIX ---------------------------------------------------------------------------------------


def test_stix_patterns_escape_and_classify() -> None:
    assert pattern_for("host", "evil.example") == "[domain-name:value = 'evil.example']"
    assert pattern_for("host", "203.0.113.9") == "[ipv4-addr:value = '203.0.113.9']"
    assert pattern_for("url", "http://x.example/a'b") == "[url:value = 'http://x.example/a\\'b']"
    assert pattern_for("sha256", "A" * 64) == f"[file:hashes.'SHA-256' = '{'a' * 64}']"
    assert pattern_for("phone", "+971500000000") is None
    now = utcnow()
    first = bundle([("host", "evil.example", "reported_scam", None, now)], "Test", now)
    second = bundle([("host", "evil.example", "reported_scam", None, now)], "Test", now)
    indicator = first["objects"][1]
    assert indicator["id"] == second["objects"][1]["id"]  # stable across exports
    assert indicator["object_marking_refs"] == [TLP_CLEAR]
    assert indicator["spec_version"] == "2.1"


def test_stix_export_shares_only_community_data(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.intel.feeds import URLHAUS

    seed_feed(db, COMMUNITY, [FeedIndicator("host", "reported-scam.example", "reported_scam")])
    seed_feed(db, URLHAUS, [FeedIndicator("url", "http://third-party.example/x", "malware")])
    client, _ = account(db, "stix@example.com")
    from app.main import app

    anonymous = TestClient(app)
    assert anonymous.get(f"{API}/intelligence/stix").status_code == 401
    body = client.get(f"{API}/intelligence/stix").json()
    patterns = [o["pattern"] for o in body["objects"] if o["type"] == "indicator"]
    assert patterns == ["[domain-name:value = 'reported-scam.example']"]

    monkeypatch.setattr(get_settings(), "share_feed", "public")
    assert anonymous.get(f"{API}/intelligence/stix").status_code == 200
    monkeypatch.setattr(get_settings(), "share_feed", "off")
    assert client.get(f"{API}/intelligence/stix").status_code == 404
    assert db.scalar(select(User).where(User.email == "stix@example.com")) is not None
