from datetime import timedelta

from fastapi import APIRouter
from sqlalchemy import select, text

from app.api.deps import Db
from app.core.config import get_settings
from app.intel.feeds import FEEDS, TEST_FIXTURES
from app.models import ThreatSource
from app.models.base import utcnow
from app.notify.email import email_enabled
from app.schemas.scans import ProviderStatus

router = APIRouter(prefix="/system", tags=["System"])

_FEED_PURPOSE = {
    "urlhaus": "Links known to distribute malware",
    "threatfox": "Malware hosts, links and file fingerprints from many sources",
    "malwarebazaar": "Fingerprints of recently reported malware files",
}
_NOTHING_SHARED = "Nothing leaves this server during a scan."


def _feed_status(source: ThreatSource | None, key: str, name: str) -> ProviderStatus:
    settings = get_settings()
    purpose = _FEED_PURPOSE[key]
    shares = "Nothing. The feed is downloaded and matched locally."
    if source is None or source.last_success_at is None:
        detail = (
            f"The last download failed: {source.last_error}"
            if source and source.last_error
            else "The feed has not been downloaded yet."
        )
        status = "degraded" if source and source.last_error else "awaiting_first_sync"
        return ProviderStatus(
            key=key, name=name, purpose=purpose, status=status, detail=detail, shares_data=shares
        )
    stale = source.last_success_at < utcnow() - timedelta(hours=settings.feed_stale_after_hours)
    detail = (
        f"{source.indicator_count:,} indicators, last updated "
        f"{source.last_success_at:%Y-%m-%d %H:%M} UTC."
    )
    if stale:
        detail += " This copy is out of date and is not used for verdicts."
    return ProviderStatus(
        key=key,
        name=name,
        purpose=purpose,
        status="degraded" if stale else "active",
        detail=detail,
        shares_data=shares,
    )


@router.get("/providers", response_model=list[ProviderStatus])
def provider_status(db: Db) -> list[ProviderStatus]:
    """What this deployment can actually check right now. Drives the UI's integration list."""
    settings = get_settings()
    sources = {source.key: source for source in db.scalars(select(ThreatSource))}
    statuses = [_feed_status(sources.get(feed.key), feed.key, feed.name) for feed in FEEDS]
    fixtures = sources.get(TEST_FIXTURES)
    if fixtures:
        statuses.append(
            ProviderStatus(
                key=TEST_FIXTURES,
                name=fixtures.name,
                purpose="Lets developers exercise detections without internet access",
                status="active",
                detail=f"{fixtures.indicator_count} indicators on reserved example domains. "
                "Matches are shown as evidence but never count as a reputation check.",
                shares_data=_NOTHING_SHARED,
            )
        )

    statuses.append(
        ProviderStatus(
            key="urlhaus_api",
            name="URLhaus live lookup",
            purpose="Up-to-the-minute reputation for a submitted link",
            status="active" if settings.urlhaus_auth_key else "not_configured",
            detail="Configured."
            if settings.urlhaus_auth_key
            else "Needs a free abuse.ch Auth-Key (SENTINEL_URLHAUS_AUTH_KEY).",
            shares_data="The submitted link is sent to abuse.ch.",
        )
    )
    statuses.append(
        ProviderStatus(
            key="rdap",
            name="RDAP domain registries",
            purpose="Domain registration date",
            status="active",
            detail="Queried per scan; individual registries may not answer.",
            shares_data="The domain name (not the full link) is sent to rdap.org and the registry.",
        )
    )
    statuses.append(
        ProviderStatus(
            key="clamav",
            name="ClamAV",
            purpose="Antivirus signatures for uploaded files",
            status="active" if settings.clamav_host else "not_configured",
            detail=f"Using clamd at {settings.clamav_host}:{settings.clamav_port}."
            if settings.clamav_host
            else "No ClamAV service is configured (SENTINEL_CLAMAV_HOST).",
            shares_data=_NOTHING_SHARED,
        )
    )
    statuses.append(
        ProviderStatus(
            key="yara",
            name="YARA signature rules",
            purpose="Known malicious techniques in uploaded files and apps",
            status="active",
            detail="SENTINEL's built-in rules"
            + (
                f", plus custom rules from {settings.yara_rules_dir}"
                if settings.yara_rules_dir
                else ""
            )
            + ".",
            shares_data=_NOTHING_SHARED,
        )
    )
    statuses.append(
        ProviderStatus(
            key="mobsf",
            name="MobSF",
            purpose="Deeper static analysis of Android apps",
            status="active" if settings.mobsf_url and settings.mobsf_api_key else "not_configured",
            detail="Configured."
            if settings.mobsf_url and settings.mobsf_api_key
            else "No MobSF server is configured (SENTINEL_MOBSF_URL, SENTINEL_MOBSF_API_KEY).",
            shares_data="Uploaded apps are sent to the operator's own MobSF server only.",
        )
    )
    statuses.append(
        ProviderStatus(
            key="email",
            name="Email delivery",
            purpose="Address verification and password reset",
            status="active" if email_enabled() else "not_configured",
            detail="Configured." if email_enabled() else "Not configured (SENTINEL_EMAIL_BACKEND).",
            shares_data="Your address goes to the operator's mail provider when a message is sent.",
        )
    )
    ai_ready = bool(settings.openai_api_key and settings.openai_model)
    statuses.append(
        ProviderStatus(
            key="ai",
            name="AI explanations (OpenAI)",
            purpose="Optional plain-language summaries of scan results, on request",
            status="active" if ai_ready else "not_configured",
            detail=f"Using {settings.openai_model}."
            if ai_ready
            else "Not configured (SENTINEL_OPENAI_API_KEY, SENTINEL_OPENAI_MODEL).",
            shares_data="When you ask for an explanation, the verdict and finding summaries are "
            "sent to OpenAI. Message text, files and full addresses are not.",
        )
    )
    return statuses


@router.get("/health")
def health(db: Db) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "ok"}
