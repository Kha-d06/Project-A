"""Group rules (policies) and how members measure up against them.

Family groups:
- safe_search: the members' browsers (Qalaa extension) force SafeSearch on
  Google, Bing and DuckDuckGo, and YouTube's restricted mode.
- lock_protection: the extension's "pause protection" switch is disabled.
- allowed_from / allowed_until ("HH:MM", same day, in the device's own local
  time): browsing is allowed only inside this window.
- daily_minutes (1-1440): browsing stops for the day after this much active time.
  Screen time covers browsing in browsers where the extension is linked, not
  other apps.

Organisations:
- require_2fa: members should use two-step sign-in.
- require_extension: members should have the browser extension linked.
- max_days_since_scan: each member's computers should have finished a scan
  within this many days (0 = no rule).

Like the block list, rules apply only to members who chose to follow the group's
rules, and the compliance view covers only members who chose to share activity.
Qalaa cannot stop the account holder from changing their own settings, so
these are agreed rules with visibility, not remote control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

FAMILY_KEYS = ("safe_search", "lock_protection", "allowed_from", "allowed_until", "daily_minutes")
ORGANISATION_KEYS = ("require_2fa", "require_extension", "max_days_since_scan")
MAX_DAYS_SINCE_SCAN = 90
MINUTES_IN_DAY = 24 * 60
_CLOCK = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


def clock_minutes(value: str) -> int:
    """'HH:MM' to minutes after midnight; ValueError if it is not a 24-hour time."""
    match = _CLOCK.match(value)
    if not match:
        raise ValueError("times must be HH:MM (24-hour)")
    return int(match.group(1)) * 60 + int(match.group(2))


def clean_policies(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    """Keep only the rules that apply to this kind of group, with valid values."""
    allowed = FAMILY_KEYS if kind == "family" else ORGANISATION_KEYS
    cleaned: dict[str, Any] = {}
    for key in allowed:
        if key not in values or values[key] is None:
            continue
        if key == "max_days_since_scan":
            days = int(values[key])
            if days < 0 or days > MAX_DAYS_SINCE_SCAN:
                raise ValueError(f"max_days_since_scan must be between 0 and {MAX_DAYS_SINCE_SCAN}")
            if days:
                cleaned[key] = days
        elif key == "daily_minutes":
            minutes = int(values[key])
            if minutes < 0 or minutes > MINUTES_IN_DAY:
                raise ValueError(f"daily_minutes must be between 0 and {MINUTES_IN_DAY}")
            if minutes:
                cleaned[key] = minutes
        elif key in ("allowed_from", "allowed_until"):
            clock_minutes(str(values[key]))  # validates
            cleaned[key] = str(values[key])
        elif bool(values[key]):
            cleaned[key] = True
    # A browsing window needs both ends, and must end later the same day.
    has_from, has_until = "allowed_from" in cleaned, "allowed_until" in cleaned
    if has_from != has_until:
        raise ValueError("set both allowed_from and allowed_until, or neither")
    if has_from and clock_minutes(cleaned["allowed_from"]) >= clock_minutes(
        cleaned["allowed_until"]
    ):
        raise ValueError("allowed_until must be later than allowed_from on the same day")
    return cleaned


def strictest_screen_time(policies: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Combine the screen-time rules of every family group a member follows: the
    smallest daily limit, and the overlap of the browsing windows. Windows that do
    not overlap leave no allowed time (from == until)."""
    limits = [int(p["daily_minutes"]) for p in policies if p.get("daily_minutes")]
    windows = [
        (clock_minutes(p["allowed_from"]), clock_minutes(p["allowed_until"]))
        for p in policies
        if p.get("allowed_from")
    ]
    if not limits and not windows:
        return None
    rule: dict[str, Any] = {
        "daily_minutes": min(limits) if limits else 0,
        "allowed_from": None,
        "allowed_until": None,
    }
    if windows:
        start = max(w[0] for w in windows)
        end = max(start, min(w[1] for w in windows))
        rule["allowed_from"] = f"{start // 60:02d}:{start % 60:02d}"
        rule["allowed_until"] = f"{end // 60:02d}:{end % 60:02d}"
    return rule


@dataclass
class MemberFacts:
    two_factor: bool
    extension_linked: bool
    devices: int
    # Most recent finished scan on any of the member's computers.
    last_device_scan: datetime | None
    device_threats: int


def compliance(policies: dict[str, Any], facts: MemberFacts, now: datetime) -> list[str]:
    """The rules this member does not meet, as stable codes."""
    problems: list[str] = []
    if policies.get("require_2fa") and not facts.two_factor:
        problems.append("no_2fa")
    if policies.get("require_extension") and not facts.extension_linked:
        problems.append("no_extension")
    days = int(policies.get("max_days_since_scan") or 0)
    if days:
        if facts.devices == 0:
            problems.append("no_device")
        elif facts.last_device_scan is None or now - facts.last_device_scan > timedelta(days=days):
            problems.append("scan_overdue")
    if facts.device_threats:
        problems.append("threats_found")
    return problems
