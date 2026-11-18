"""Has my email address appeared in a data breach? (Have I Been Pwned)

Only the signed-in user's own address can be checked, and only once it is
verified when email is enabled: searching other people's addresses would make
this a tool for finding targets. Password checks use the Pwned Passwords range
API straight from the browser (k-anonymity), so passwords never reach Qalaa.
"""

from typing import Any
from urllib.parse import quote

import httpx
from fastapi import APIRouter

from app.api.deps import Db, SessionUser
from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.rate_limit import RateLimit
from app.models.base import utcnow
from app.notify.email import email_enabled
from app.schemas.sharing import Breach, BreachResult

router = APIRouter(prefix="/breach", tags=["Breach check"])
BREACH_LIMIT = RateLimit("breach-check", max_requests=10, window_seconds=3600)


def hibp_breaches(email: str) -> list[dict[str, Any]]:
    key = get_settings().hibp_api_key
    if not key:
        raise ApiError(
            503,
            "breach_check_unavailable",
            "Breach checks need a Have I Been Pwned API key, which this server does not have.",
        )
    try:
        response = httpx.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": key, "user-agent": "Qalaa-breach-check"},
            timeout=15,
        )
    except httpx.HTTPError as exc:
        raise ApiError(
            503, "breach_check_unavailable", "Have I Been Pwned did not answer."
        ) from exc
    if response.status_code == 404:
        return []
    if response.status_code == 429:
        raise ApiError(503, "breach_check_unavailable", "Too many checks right now; try later.")
    if response.status_code != 200:
        raise ApiError(503, "breach_check_unavailable", "Have I Been Pwned did not answer.")
    body = response.json()
    return body if isinstance(body, list) else []


@router.get("/email", response_model=BreachResult)
def my_email_breaches(db: Db, user: SessionUser) -> BreachResult:
    rate_limit.enforce(BREACH_LIMIT, f"user:{user.id}")
    if email_enabled() and user.email_verified_at is None:
        raise ApiError(
            403, "email_not_verified", "Confirm your email address first, then check it."
        )
    breaches = [
        Breach(
            name=str(item.get("Name", ""))[:100],
            title=str(item.get("Title") or item.get("Name") or "")[:150],
            domain=str(item.get("Domain") or "")[:150] or None,
            breach_date=str(item.get("BreachDate") or "")[:20] or None,
            data_classes=[str(c)[:60] for c in (item.get("DataClasses") or [])][:20],
            verified=bool(item.get("IsVerified", False)),
        )
        for item in hibp_breaches(user.email)
    ]
    return BreachResult(email=user.email, breaches=breaches, checked_at=utcnow())
