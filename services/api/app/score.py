"""The security score: a 0-100 summary of how well an account is protected, with
the steps that would raise it.

It measures protective settings the person controls (two-step sign-in, a
password manager, browser and device protection...), not how risky their
browsing is, and it never claims an account is "safe". Steps that do not apply
on this server (no VPN configured, no breach service) are left out rather than
counted against anyone.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Step:
    key: str
    weight: int


STEPS = (
    Step("email_verified", 10),
    Step("two_factor", 20),
    Step("password_manager", 15),
    Step("extension", 15),
    Step("device_protected", 15),
    Step("breach_monitoring", 15),
    Step("vpn", 5),
)


def compute(done: dict[str, bool], available: set[str] | None = None) -> dict[str, object]:
    """`done` maps step keys to whether they are met; steps not in `available`
    (when given) are skipped. Returns score, grade and the step list."""
    steps = [step for step in STEPS if available is None or step.key in available]
    total = sum(step.weight for step in steps) or 1
    earned = sum(step.weight for step in steps if done.get(step.key))
    score = round(earned * 100 / total)
    grade = (
        "strong" if score >= 85 else "good" if score >= 65 else "fair" if score >= 40 else "weak"
    )
    return {
        "score": score,
        "grade": grade,
        "steps": [
            {
                "key": step.key,
                "done": bool(done.get(step.key)),
                "points": round(step.weight * 100 / total),
            }
            for step in sorted(steps, key=lambda s: (bool(done.get(s.key)), -s.weight))
        ],
    }
