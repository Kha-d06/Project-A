"""Render a group's compliance view as a downloadable CSV, or a printable HTML
report (the browser saves that as a PDF).

Pure functions, so they can be tested without the web layer. Members who did not
choose to share their activity show no detail, exactly as in the live view.
"""

from __future__ import annotations

import csv
import html
import io
from collections.abc import Callable
from datetime import datetime
from typing import Any

POLICY_LABELS = {
    "require_2fa": "Two-step sign-in required",
    "require_extension": "Browser extension required",
    "max_days_since_scan": "Max days since a device scan",
    "safe_search": "SafeSearch enforced",
    "lock_protection": "Protection cannot be paused",
}

Member = dict[str, Any]


def _yes_no(value: bool | None) -> str:
    return "—" if value is None else ("yes" if value else "no")


def _count(value: int | None) -> str:
    return "—" if value is None else str(value)


def _day(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else "—"


def _problems(m: Member) -> str:
    if not m["shared"]:
        return "—"
    return "; ".join(m.get("problems") or []) or "none"


# One column definition, used by both formats so they can never disagree.
COLUMNS: list[tuple[str, Callable[[Member], str]]] = [
    ("Email", lambda m: m["email"]),
    ("Role", lambda m: m["role"]),
    ("Follows rules", lambda m: _yes_no(m["follows_rules"])),
    ("Shares activity", lambda m: _yes_no(m["shared"])),
    ("Two-step", lambda m: _yes_no(m.get("two_factor"))),
    ("Extension", lambda m: _yes_no(m.get("extension_linked"))),
    ("Devices", lambda m: _count(m.get("devices"))),
    ("Last scan", lambda m: _day(m.get("last_device_scan"))),
    ("Threats", lambda m: _count(m.get("device_threats"))),
    ("Problems", _problems),
]


def policy_summary(policies: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key, value in policies.items():
        label = POLICY_LABELS.get(key, key)
        out.append(f"{label}: {value}" if key == "max_days_since_scan" else label)
    return out


def _tally(members: list[Member]) -> tuple[int, int]:
    """(members meeting every rule, members sharing activity)."""
    sharing = [m for m in members if m["shared"]]
    return sum(1 for m in sharing if not m.get("problems")), len(sharing)


def to_csv(group_name: str, policies: dict[str, Any], members: list[Member]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Group", group_name])
    writer.writerow(["Rules", "; ".join(policy_summary(policies)) or "none"])
    writer.writerow([])
    writer.writerow([name for name, _ in COLUMNS])
    for m in members:
        writer.writerow([cell(m) for _, cell in COLUMNS])
    return buffer.getvalue()


STYLE = """
body { font-family: system-ui, sans-serif; margin: 2rem; color: #141821; }
h1 { font-size: 1.4rem; font-weight: 500; }
h2 { font-size: 1.05rem; font-weight: 500; margin-top: 1.5rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.85rem; }
th, td { border: 1px solid #c6cbd4; padding: 0.3rem 0.5rem; text-align: start; }
th { background: #ebedf1; font-weight: 500; }
.muted { color: #49505f; }
@media print { body { margin: 0.5rem; } }
"""


def to_html(
    group_name: str, policies: dict[str, Any], members: list[Member], generated: datetime
) -> str:
    esc = html.escape
    name = esc(group_name)
    head = "".join(f"<th>{esc(title)}</th>" for title, _ in COLUMNS)
    rows = "".join(
        "<tr>" + "".join(f"<td>{esc(cell(m))}</td>" for _, cell in COLUMNS) + "</tr>"
        for m in members
    )
    rules = "".join(f"<li>{esc(p)}</li>" for p in policy_summary(policies))
    compliant, sharing = _tally(members)
    stamp = generated.strftime("%Y-%m-%d %H:%M UTC")
    summary = f"{compliant} of {sharing} members who share activity meet every rule."
    note = (
        "Members who have not chosen to share activity show no detail. "
        "These are agreed rules with visibility, not remote control."
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f"<title>Compliance report: {name}</title><style>{STYLE}</style></head><body>"
        f"<h1>Compliance report: {name}</h1>"
        f'<p class="muted">Generated {stamp}. {summary}</p>'
        f"<h2>Rules</h2><ul>{rules or '<li>No rules set.</li>'}</ul>"
        f"<h2>Members</h2><table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>"
        f'<p class="muted">{note}</p></body></html>'
    )
