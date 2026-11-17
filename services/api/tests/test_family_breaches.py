import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import breach
from app.core.config import get_settings
from app.models import OutboxEmail, User
from app.models.base import utcnow
from app.notify.breaches import check_breaches
from tests.test_extension import EXT, bearer, enroll
from tests.test_sharing_groups import account

API = "/api/v1"


def test_family_block_list_applies_only_to_members_who_opt_in(db: Session) -> None:
    parent, _ = account(db, "fam-parent@example.com")
    child, _ = account(db, "fam-child@example.com")
    group = parent.post(f"{API}/groups", json={"name": "Home", "kind": "family"}).json()
    token = (
        parent.post(f"{API}/groups/{group['id']}/invites", json={"email": "fam-child@example.com"})
        .json()["url"]
        .split("invite=")[1]
    )
    child.post(f"{API}/groups/invites/accept", json={"token": token})

    bad = parent.put(f"{API}/groups/{group['id']}/blocklist", json={"domains": ["not a domain"]})
    assert bad.status_code == 422
    updated = parent.put(
        f"{API}/groups/{group['id']}/blocklist",
        json={"domains": ["*.Gambling.example", "casino.example", "casino.example"]},
    ).json()
    assert updated["blocklist"] == ["gambling.example", "casino.example"]
    assert (
        child.put(f"{API}/groups/{group['id']}/blocklist", json={"domains": []}).status_code == 403
    )

    # The child's linked browser gets nothing until the child turns it on.
    code = child.post(f"{EXT}/link-codes").json()["code"]
    credentials = enroll(child, code)
    settings = child.get(f"{EXT}/settings", headers=bearer(credentials)).json()
    assert settings["family_blocklist"] == []

    me = next(
        m
        for m in child.get(f"{API}/groups").json()[0]["members"]
        if m["email"] == "fam-child@example.com"
    )
    forced = parent.patch(
        f"{API}/groups/{group['id']}/members/{me['user_id']}", json={"apply_blocklist": True}
    )
    assert forced.status_code == 403
    child.patch(
        f"{API}/groups/{group['id']}/members/{me['user_id']}", json={"apply_blocklist": True}
    )
    settings = child.get(f"{EXT}/settings", headers=bearer(credentials)).json()
    assert settings["family_blocklist"] == ["casino.example", "gambling.example"]
    assert settings["family_groups"] == ["Home"]


def test_breach_monitoring_reports_only_new_breaches(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "email_backend", "outbox")
    monkeypatch.setattr(get_settings(), "hibp_api_key", "k")
    client, _ = account(db, "monitor@example.com")
    db.scalar(select(User).where(User.email == "monitor@example.com")).email_verified_at = utcnow()
    db.commit()
    client.patch(f"{API}/user/settings", json={"breach_monitoring": True})

    listed = [{"Name": "OldSite", "Title": "Old Site"}]
    monkeypatch.setattr(
        breach.httpx,
        "get",
        lambda url, params, headers, timeout: httpx.Response(200, json=list(listed)),
    )
    assert check_breaches(db) == 1
    assert check_breaches(db) == 0  # nothing new
    listed.append({"Name": "NewSite", "Title": "New Site"})
    assert check_breaches(db) == 1
    mails = [m for m in db.scalars(select(OutboxEmail)).all() if "data breach" in m.subject]
    assert len(mails) == 2
    assert "New Site" in mails[-1].body and "Old Site" not in mails[-1].body
