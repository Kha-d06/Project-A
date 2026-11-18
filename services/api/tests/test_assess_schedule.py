"""Opt-in active tests, scheduled re-assessments and regression emails."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assess import checks, runner, schedule
from app.core.config import get_settings
from app.models import Assessment, OutboxEmail, VerifiedDomain
from tests import test_assess
from tests.test_assess import FakeNet, _verified_domain, enable
from tests.test_sharing_groups import API, account

TOKEN = "abcd1234"
net = test_assess.net  # the fake DNS + web fixture


@pytest.fixture
def outbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "email_backend", "outbox")


def _clean_site(net: FakeNet, domain: str) -> None:
    net.set_page(
        f"https://{domain}/",
        status=200,
        headers={
            "strict-transport-security": "max-age=63072000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
        },
        tls="Jan  5 00:00:00 2028 GMT",
    )
    net.set_page(f"http://{domain}/", status=301, redirect_location=f"https://{domain}/")


# --- The checks themselves -------------------------------------------------------------


def test_reflection_needs_the_unescaped_marker() -> None:
    marker = checks.probe_marker(TOKEN)
    assert checks.check_reflection(TOKEN, 200, f"<p>You searched {marker}</p>") is not None
    escaped = marker.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    assert checks.check_reflection(TOKEN, 200, f"<p>You searched {escaped}</p>") is None
    assert checks.check_reflection(TOKEN, None, marker) is None


def test_open_redirect_only_for_the_canary() -> None:
    assert checks.check_open_redirect(302, checks.REDIRECT_CANARY) is not None
    assert checks.check_open_redirect(302, "https://example.com/home") is None
    assert checks.check_open_redirect(200, checks.REDIRECT_CANARY) is None


def test_sql_error_signatures() -> None:
    assert checks.check_sql_errors("Warning: You have an error in your SQL syntax near") is not None
    assert checks.check_sql_errors("<h1>Not found</h1>") is None


def test_probe_paths_carry_only_harmless_markers() -> None:
    paths = checks.probe_paths(TOKEN)
    assert set(paths) == {"reflection", "redirect", "sql"}
    joined = "".join(paths.values()).lower()
    assert "script" not in joined and "union" not in joined and "password" not in joined


# --- Confirmation gate ------------------------------------------------------------------


def test_active_tests_need_owner_confirmation(
    db: Session, net: FakeNet, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner.secrets, "token_hex", lambda _n: TOKEN)
    owner, _ = account(db, "probe1@example.com")
    enable(db, "probe1@example.com")
    domain_id = _verified_domain(db, owner, net, "probeco.net")
    _clean_site(net, "probeco.net")
    paths = checks.probe_paths(TOKEN)
    net.set_page(
        f"https://probeco.net{paths['reflection']}",
        status=200,
        body=f"Results for {checks.probe_marker(TOKEN)}",
    )
    net.set_page(
        f"https://probeco.net{paths['redirect']}",
        status=302,
        redirect_location=checks.REDIRECT_CANARY,
    )

    refused = owner.post(f"{API}/assess/domains/{domain_id}/scan", json={"active_probes": True})
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "confirmation_required"
    assert db.scalar(select(Assessment).where(Assessment.domain == "probeco.net")) is None

    # Without active tests the probe URLs are never requested, so nothing is found there.
    plain = owner.post(f"{API}/assess/domains/{domain_id}/scan").json()
    assert plain["active_probes"] is False
    assert not any(f["category"] == "active" for f in plain["findings"])
    assert not any(c["key"] == "active" for c in plain["checks"])

    active = owner.post(
        f"{API}/assess/domains/{domain_id}/scan",
        json={"active_probes": True, "confirm_owner": True},
    )
    assert active.status_code == 201, active.text
    body = active.json()
    assert body["active_probes"] is True
    titles = {f["title"] for f in body["findings"] if f["category"] == "active"}
    assert "Text from the address is shown on the page without escaping" in titles
    assert "The homepage redirects to any address given in the URL" in titles
    assert any(c["key"] == "active" for c in body["checks"])


# --- Schedules --------------------------------------------------------------------------


def test_schedule_needs_a_verified_domain(db: Session, net: FakeNet) -> None:
    owner, _ = account(db, "sched1@example.com")
    enable(db, "sched1@example.com")
    created = owner.post(f"{API}/assess/domains", json={"domain": "notyet.net"}).json()
    response = owner.patch(
        f"{API}/assess/domains/{created['domain']['id']}", json={"schedule": "weekly"}
    )
    assert response.status_code == 409

    domain_id = _verified_domain(db, owner, net, "weekly.net")
    weekly = owner.patch(f"{API}/assess/domains/{domain_id}", json={"schedule": "weekly"})
    assert weekly.status_code == 200 and weekly.json()["schedule"] == "weekly"
    assert weekly.json()["next_run_at"] is not None
    assert (
        owner.patch(f"{API}/assess/domains/{domain_id}", json={"schedule": "daily"}).status_code
        == 422
    )
    off = owner.patch(f"{API}/assess/domains/{domain_id}", json={"schedule": "off"}).json()
    assert off["schedule"] == "off" and off["next_run_at"] is None

    # Another account cannot change it.
    stranger, _ = account(db, "sched-stranger@example.com")
    enable(db, "sched-stranger@example.com")
    assert (
        stranger.patch(f"{API}/assess/domains/{domain_id}", json={"schedule": "weekly"}).status_code
        == 404
    )


@pytest.mark.usefixtures("outbox")
def test_due_domains_are_reassessed_and_regressions_emailed(db: Session, net: FakeNet) -> None:
    owner, _ = account(db, "sched2@example.com")
    enable(db, "sched2@example.com")
    domain_id = _verified_domain(db, owner, net, "watched.net")
    _clean_site(net, "watched.net")
    first = owner.post(f"{API}/assess/domains/{domain_id}/scan").json()
    assert first["result"] in ("no_issues", "info", "low")
    owner.patch(f"{API}/assess/domains/{domain_id}", json={"schedule": "monthly"})

    # Not due yet: nothing starts.
    assert schedule.run_due(db) == 0

    # The site regresses: an exposed .env appears.
    net.set_page("https://watched.net/.env", status=200, body="SECRET_KEY=x\nDB_PASSWORD=y")
    later = datetime.now(UTC) + timedelta(days=31)
    assert schedule.run_due(db, now=later) == 1

    jobs = db.scalars(
        select(Assessment).where(Assessment.domain == "watched.net").order_by(Assessment.created_at)
    ).all()
    assert len(jobs) == 2 and jobs[1].scheduled and not jobs[1].active_probes
    assert jobs[1].status == "completed" and jobs[1].result == "critical"
    record = db.get(VerifiedDomain, jobs[1].domain_id)
    assert record is not None and record.next_run_at is not None
    assert record.next_run_at.replace(tzinfo=UTC) > later

    mail = db.scalars(
        select(OutboxEmail).where(
            OutboxEmail.subject == "Qalaa: watched.net has new security issues"
        )
    ).all()
    assert len(mail) == 1 and mail[0].recipient == "sched2@example.com"
    assert "An .env file is publicly readable" in mail[0].body
    assert f"/dashboard/assessment/report/{jobs[1].id}" in mail[0].body

    # Running again with nothing new sends no further email.
    assert schedule.run_due(db, now=later + timedelta(days=31)) == 1
    again = db.scalars(select(OutboxEmail).where(OutboxEmail.subject.contains("watched.net"))).all()
    assert len(again) == 1


@pytest.mark.usefixtures("outbox")
def test_schedules_respect_entitlement_and_monthly_limit(db: Session, net: FakeNet) -> None:
    owner, _ = account(db, "sched3@example.com")
    user = enable(db, "sched3@example.com", assessment_monthly_limit=1)
    domain_id = _verified_domain(db, owner, net, "limited.net")
    _clean_site(net, "limited.net")
    owner.post(f"{API}/assess/domains/{domain_id}/scan")  # uses this month's only scan
    owner.patch(f"{API}/assess/domains/{domain_id}", json={"schedule": "weekly"})

    soon = datetime.now(UTC) + timedelta(days=8)
    if soon.month == datetime.now(UTC).month:
        assert schedule.run_due(db, now=soon) == 0  # over the limit: skipped, not queued

    user.assessment_enabled_at = None
    db.commit()
    assert schedule.run_due(db, now=soon + timedelta(days=40)) == 0  # access removed


def test_regression_comparison() -> None:
    before = Assessment(
        result="low", findings=[{"title": "A", "severity": "low", "category": "headers"}]
    )
    same = Assessment(
        result="low", findings=[{"title": "A", "severity": "low", "category": "headers"}]
    )
    worse = Assessment(
        result="high",
        findings=[
            {"title": "A", "severity": "low", "category": "headers"},
            {"title": "B", "severity": "high", "category": "exposure"},
            {"title": "note", "severity": "info", "category": "dns"},
        ],
    )
    assert schedule.regression(before, same) == ([], False)
    assert schedule.regression(before, worse) == (["B"], True)
    assert schedule.regression(worse, before) == ([], False)
