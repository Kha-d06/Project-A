"""Share Qalaa's own threat data as a STIX 2.1 bundle.

Only indicators from moderator-verified community reports are shared: they are
this server's own data. Indicators from third-party feeds stay out, because
each feed has its own sharing terms.

IDs are stable (UUIDv5 of the indicator), so a consumer that polls the bundle
updates objects instead of duplicating them. Phone numbers are left out: STIX
has no standard object for them.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

# STIX 2.1 TLP 2.0 marking definition for TLP:CLEAR (fixed, published by OASIS).
TLP_CLEAR = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
_NAMESPACE = uuid.UUID("5e1f3c2a-6c5b-4d1e-9a3f-2b7c8d9e0f11")


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def pattern_for(kind: str, value: str) -> str | None:
    if kind == "url":
        return f"[url:value = '{_escape(value)}']"
    if kind == "host":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return f"[domain-name:value = '{_escape(value.lower())}']"
        return f"[ipv{ip.version}-addr:value = '{ip}']"
    if kind == "sha256" and len(value) == 64:
        return f"[file:hashes.'SHA-256' = '{value.lower()}']"
    return None


def _stamp(value: datetime | None, fallback: datetime) -> str:
    moment = value or fallback
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def bundle(
    indicators: list[tuple[str, str, str | None, datetime | None, datetime]],
    producer: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """indicators: (kind, value, threat, first_seen, last_seen)."""
    now = now or datetime.now(UTC)
    identity_id = f"identity--{uuid.uuid5(_NAMESPACE, 'producer:' + producer)}"
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": producer,
            "identity_class": "organization",
        }
    ]
    for kind, value, threat, first_seen, last_seen in indicators:
        pattern = pattern_for(kind, value)
        if pattern is None:
            continue
        created = _stamp(first_seen, last_seen)
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(_NAMESPACE, f'{kind}:{value}')}",
                "created_by_ref": identity_id,
                "created": created,
                "modified": _stamp(last_seen, now),
                "name": f"Reported {kind}: {value}"[:250],
                "description": "Confirmed by a Qalaa moderator from a community report.",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": created,
                "labels": [threat or "reported_scam"],
                "object_marking_refs": [TLP_CLEAR],
            }
        )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
