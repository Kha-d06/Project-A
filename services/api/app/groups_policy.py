"""Group rules (policies) and how members measure up against them.

Family groups:
- safe_search: the members' browsers (SENTINEL extension) force SafeSearch on
  Google, Bing and DuckDuckGo, and YouTube's restricted mode.
- lock_protection: the extension's "pause protection" switch is disabled.

Organisations:
- require_2fa: members should use two-step sign-in.
- require_extension: members should have the browser extension linked.
- max_days_since_scan: each member's computers should have finished a scan
  within this many days (0 = no rule).

Like the block list, rules apply only to members who chose to follow the group's
rules, and the compliance view covers only members who chose to share activity.
SENTINEL cannot stop the account holder from changing their own settings, so
these are agreed rules with visibility, not remote control.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

FAMILY_KEYS = ("safe_search", "lock_protection")
ORGANISATION_KEYS = ("require_2fa", "require_extension", "max_days_since_scan")
MAX_DAYS_SINCE_SCAN = 90


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
        elif bool(values[key]):
            cleaned[key] = True
    return cleaned


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
