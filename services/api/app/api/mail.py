"""One-off email checks for the desktop mailbox scanner and the Thunderbird
add-on. The email is analysed in memory and answered at once: nothing about it
is stored, and no account is needed."""

from fastapi import APIRouter, Request

from app.analyzers.email_check import analyze_email
from app.analyzers.verdict import assess
from app.api.deps import Db, OptionalUser
from app.api.scans import request_locale
from app.core import rate_limit
from app.core.rate_limit import RateLimit, client_address
from app.schemas.email import EmailCheckOut, EmailCheckRequest, EmailFinding

router = APIRouter(prefix="/email", tags=["Scanning"])

# A mailbox scan checks each new message, so this is higher than for pasted scans.
EMAIL_LIMIT = RateLimit("email-check", max_requests=600, window_seconds=3600)
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@router.post("/check", response_model=EmailCheckOut)
def check_email(
    body: EmailCheckRequest, request: Request, db: Db, user: OptionalUser
) -> EmailCheckOut:
    subject = f"user:{user.id}" if user else f"ip:{client_address(request)}"
    rate_limit.enforce(EMAIL_LIMIT, subject)
    locale = request_locale(request)
    payload = {**body.model_dump(), "locale": locale}
    if not (body.text.strip() or body.subject.strip() or body.links):
        payload["text"] = "(empty message)"
    outcome = analyze_email(payload, db)
    verdict = assess("message", outcome, locale)
    findings = sorted(outcome.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 5))
    return EmailCheckOut(
        risk=verdict.risk,
        confidence=verdict.confidence,
        summary=verdict.summary,
        recommendations=verdict.recommendations,
        findings=[
            EmailFinding(severity=f.severity, title=f.title, explanation=f.explanation)
            for f in findings
        ],
        limitations=outcome.limitations,
    )
