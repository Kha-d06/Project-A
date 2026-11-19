"""Family screen time: rule validation, combining several families' rules, the rule
reaching the browser, minute reports and who may see them."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.groups_policy import clean_policies, strictest_screen_time
from tests.test_extension import EXT, bearer, enroll
from tests.test_round6d import _join
from tests.test_sharing_groups import API, account


def test_clean_policies_validates_screen_time() -> None:
    cleaned = clean_policies(
        "family", {"allowed_from": "07:30", "allowed_until": "20:00", "daily_minutes": 90}
    )
    assert cleaned == {"allowed_from": "07:30", "allowed_until": "20:00", "daily_minutes": 90}
    assert clean_policies("family", {"daily_minutes": 0}) == {}
    for bad in (
        {"allowed_from": "07:30"},
        {"allowed_from": "21:00", "allowed_until": "08:00"},
        {"allowed_from": "25:00", "allowed_until": "26:00"},
        {"daily_minutes": 2000},
    ):
        with pytest.raises(ValueError):
            clean_policies("family", bad)


def test_strictest_rule_wins_across_families() -> None:
    rule = strictest_screen_time(
        [
            {"allowed_from": "07:00", "allowed_until": "21:00", "daily_minutes": 120},
            {"allowed_from": "09:00", "allowed_until": "20:00", "daily_minutes": 60},
            {"safe_search": True},
        ]
    )
    assert rule == {"allowed_from": "09:00", "allowed_until": "20:00", "daily_minutes": 60}
    assert strictest_screen_time([{"safe_search": True}]) is None
    # Windows that never overlap leave no allowed time at all.
    none_left = strictest_screen_time(
        [
            {"allowed_from": "07:00", "allowed_until": "12:00"},
            {"allowed_from": "18:00", "allowed_until": "21:00"},
        ]
    )
    assert none_left is not None
    assert none_left["allowed_from"] == none_left["allowed_until"]


def _linked(child: TestClient) -> tuple[TestClient, dict[str, str]]:
    code = child.post(f"{API}/extension/link-codes").json()["code"]
    browser = TestClient(child.app)
    return browser, bearer(enroll(browser, link_code=code))


def test_screen_time_reaches_browser_and_minutes_reach_parent(db: Session) -> None:
    parent, _ = account(db, "st-parent@example.com")
    group, child = _join(db, parent, "st-child@example.com", "family")
    parent.put(
        f"{API}/groups/{group['id']}/policies",
        json={"allowed_from": "08:00", "allowed_until": "20:00", "daily_minutes": 60},
    )
    browser, headers = _linked(child)
    assert browser.get(f"{EXT}/settings", headers=headers).json()["screen_time"] is None

    members = parent.get(f"{API}/groups").json()[0]["members"]
    child_id = next(m["user_id"] for m in members if m["role"] == "member")
    child.patch(f"{API}/groups/{group['id']}/members/{child_id}", json={"apply_blocklist": True})
    rule = browser.get(f"{EXT}/settings", headers=headers).json()["screen_time"]
    assert rule == {"allowed_from": "08:00", "allowed_until": "20:00", "daily_minutes": 60}

    report = {"day": "2026-11-19", "minutes": 42}
    assert browser.post(f"{EXT}/screen-time", json=report, headers=headers).status_code == 204
    # A lower late report never lowers the day's total.
    lower = {"day": "2026-11-19", "minutes": 10}
    assert browser.post(f"{EXT}/screen-time", json=lower, headers=headers).status_code == 204
    too_many = {"day": "2026-11-19", "minutes": 5000}
    assert browser.post(f"{EXT}/screen-time", json=too_many, headers=headers).status_code == 422

    def child_row() -> dict:
        members = parent.get(f"{API}/groups").json()[0]["members"]
        return next(m for m in members if m["user_id"] == child_id)

    # The parent sees minutes only once the child shares activity.
    assert child_row()["screen_time_minutes"] is None
    child.patch(f"{API}/groups/{group['id']}/members/{child_id}", json={"share_activity": True})
    row = child_row()
    assert row["screen_time_minutes"] == 42 and row["screen_time_day"] == "2026-11-19"
    # Other members never see anyone's minutes.
    mine = child.get(f"{API}/groups").json()[0]["members"]
    assert all(m["screen_time_minutes"] is None for m in mine)


def test_unlinked_browser_cannot_report(client: TestClient) -> None:
    browser = client
    headers = bearer(enroll(browser))
    report = {"day": "2026-11-19", "minutes": 5}
    assert browser.post(f"{EXT}/screen-time", json=report, headers=headers).status_code == 403
