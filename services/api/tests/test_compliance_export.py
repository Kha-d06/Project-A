"""Compliance export: same access and privacy as the compliance view, as CSV or
printable HTML."""

import csv
import io
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.compliance_export import COLUMNS, to_csv, to_html
from tests.test_round6d import _join
from tests.test_sharing_groups import API, account

SHARED = {
    "email": "a@example.com",
    "role": "member",
    "follows_rules": True,
    "shared": True,
    "two_factor": False,
    "extension_linked": True,
    "devices": 2,
    "last_device_scan": datetime(2026, 11, 1, tzinfo=UTC),
    "device_threats": 0,
    "problems": ["no_2fa"],
}
PRIVATE = {"email": "b@example.com", "role": "member", "follows_rules": False, "shared": False}


def test_csv_has_one_row_per_member_and_hides_private_detail() -> None:
    rows = list(csv.reader(io.StringIO(to_csv("Team", {"require_2fa": True}, [SHARED, PRIVATE]))))
    assert rows[0] == ["Group", "Team"]
    assert rows[1] == ["Rules", "Two-step sign-in required"]
    header = rows[3]
    assert header == [name for name, _ in COLUMNS]
    shared, private = (dict(zip(header, row, strict=True)) for row in rows[4:])
    assert shared["Two-step"] == "no" and shared["Last scan"] == "2026-11-01"
    assert shared["Problems"] == "no_2fa"
    # A member who did not share activity shows nothing beyond who they are.
    assert private["Two-step"] == private["Devices"] == private["Problems"] == "—"


def test_html_escapes_names_and_counts_compliance() -> None:
    page = to_html(
        "<script>x</script>", {}, [SHARED, PRIVATE], datetime(2026, 11, 19, 8, 0, tzinfo=UTC)
    )
    assert "<script>x</script>" not in page and "&lt;script&gt;" in page
    assert "0 of 1 members who share activity meet every rule." in page
    assert "No rules set." in page


def test_export_endpoint_access_and_formats(db: Session) -> None:
    boss, _ = account(db, "export-boss@example.com")
    group, worker = _join(db, boss, "export-worker@example.com", "organisation")
    boss.put(f"{API}/groups/{group['id']}/policies", json={"require_2fa": True})

    as_csv = boss.get(f"{API}/groups/{group['id']}/compliance/export")
    assert as_csv.status_code == 200
    assert as_csv.headers["content-type"].startswith("text/csv")
    assert 'filename="Team-compliance.csv"' in as_csv.headers["content-disposition"]
    assert "export-worker@example.com" in as_csv.text

    as_html = boss.get(f"{API}/groups/{group['id']}/compliance/export?format=html")
    assert as_html.headers["content-type"].startswith("text/html")
    assert "Compliance report: Team" in as_html.text

    # Only owners and admins may export, exactly like the live view.
    assert worker.get(f"{API}/groups/{group['id']}/compliance/export").status_code == 403
    outsider, _ = account(db, "export-outsider@example.com")
    assert outsider.get(f"{API}/groups/{group['id']}/compliance/export").status_code == 404
    assert boss.get(f"{API}/groups/{group['id']}/compliance/export?format=pdf").status_code == 422
