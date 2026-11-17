from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.analyzers.safe_fetch import Hop, RedirectTrace, trace_redirects
from app.analyzers.types import Check, FindingData, Outcome
from app.analyzers.url_heuristics import analyze_url_text
from app.analyzers.urls import InvalidUrlError, ParsedUrl, parse_url
from app.intel import providers
from app.intel.feeds import COMMUNITY, OPENPHISH, THREATFOX, URLHAUS
from app.intel.lookup import IndicatorMatch, find_indicators, fresh_sources
from app.models.base import utcnow

_NEW_DOMAIN_DAYS = 30
_NEW_CERTIFICATE_DAYS = 14
_WEB_RISK_LABELS = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing or another deceptive site",
    "UNWANTED_SOFTWARE": "unwanted software",
}
_STOP_MESSAGES = {
    "unresolved": "The domain does not exist or has no address.",
    "tls_error": "The site's security certificate could not be verified.",
    "connection_error": "The site did not respond.",
    "timeout": "The site took too long to respond.",
    "redirect_loop": "The link redirects in a loop.",
    "too_many_redirects": "The link redirects more times than we follow.",
    "unsafe_destination": "The link leads to a private or internal network address.",
    "unsupported_scheme": "The link redirects to something that is not a web page.",
}


def community_finding(match: IndicatorMatch, subject: str) -> FindingData:
    """Moderator-verified community reports are strong warnings, not confirmed threats:
    they rest on people's reports rather than on catalogued malware evidence."""
    return FindingData(
        "high",
        "community_report",
        f"{subject} was reported by SENTINEL users as a scam",
        "People reported it to SENTINEL and a moderator reviewed and confirmed the reports. "
        "Treat it as a likely scam.",
        match.source_name,
        {"matched": match.value, "first_reported": match.evidence()["first_seen"]},
    )


def indicator_findings(db: Session, url: ParsedUrl) -> list[FindingData]:
    """Compare a URL against the locally stored threat feeds and verified reports."""
    findings = []
    url_matches = find_indicators(db, "url", url.normalized)
    for match in url_matches:
        if match.source_key == COMMUNITY:
            findings.append(community_finding(match, "This link"))
            continue
        findings.append(
            FindingData(
                "critical",
                "threat_intelligence",
                f"This exact link is listed by {match.source_name}",
                "The address was reported and catalogued as distributing malware"
                + (f" ({match.threat.replace('_', ' ')})" if match.threat else "")
                + ". Do not open it or run anything downloaded from it.",
                match.source_name,
                match.evidence(),
            )
        )
    for match in find_indicators(db, "host", url.host):
        if match.source_key == COMMUNITY:
            if not any(f.category == "community_report" for f in findings):
                findings.append(community_finding(match, "This website"))
        elif not url_matches:
            findings.append(
                FindingData(
                    "low",
                    "threat_intelligence",
                    f"Other links on this host are listed by {match.source_name}",
                    "A different address on the same host was reported for distributing malware. "
                    "On shared hosting and file-sharing services this says little about the "
                    "link you submitted, so treat it as context rather than proof.",
                    match.source_name,
                    {"host": url.host, "listed_by": match.source_name},
                )
            )
    return findings


def _local_feed_check(db: Session, url: ParsedUrl, outcome: Outcome) -> None:
    # Stored indicators are evidence even if the feed is stale, so always look.
    # Whether a miss means anything depends on the feed being fresh.
    outcome.findings += indicator_findings(db, url)
    sources = fresh_sources(db, (URLHAUS, THREATFOX, OPENPHISH))
    if not sources:
        outcome.checks.append(
            Check(
                "local_threat_feed",
                "Known malicious links",
                "URLhaus feed (local copy)",
                "unavailable",
                "No recently synchronised threat feed is available on this server.",
                core=True,
            )
        )
        return
    oldest = min(source.last_success_at for source in sources if source.last_success_at)
    outcome.checks.append(
        Check(
            "local_threat_feed",
            "Known malicious links",
            ", ".join(source.name for source in sources) + " (local copies)",
            "completed",
            f"Compared against {sum(s.indicator_count for s in sources):,} indicators, all "
            f"updated since {oldest:%Y-%m-%d %H:%M} UTC.",
            core=True,
        )
    )


def _urlhaus_live_check(url: ParsedUrl, outcome: Outcome) -> None:
    label, provider = "Live reputation lookup", "URLhaus API"
    try:
        result = providers.urlhaus_lookup(url.normalized)
    except providers.ProviderUnavailableError as exc:
        outcome.checks.append(
            Check("urlhaus_api", label, provider, "unavailable", f"{exc}.", core=True)
        )
        return
    if result.listed:
        outcome.findings.append(
            FindingData(
                "critical",
                "threat_intelligence",
                "This link is listed by URLhaus",
                "URLhaus tracks addresses used to distribute malware. Do not open this link or "
                "run anything downloaded from it.",
                "URLhaus API",
                {
                    "threat": result.threat,
                    "status": result.status,
                    "date_added": result.date_added,
                    "tags": ", ".join(result.tags) or None,
                    "reference": result.reference,
                },
            )
        )
    detail = "Listed as a malware distribution address." if result.listed else "Not listed."
    outcome.checks.append(Check("urlhaus_api", label, provider, "completed", detail, core=True))


def _web_risk_check(url: ParsedUrl, outcome: Outcome) -> None:
    label, provider = "Google Web Risk", "Google Web Risk API"
    try:
        threats = providers.web_risk_lookup(url.normalized)
    except providers.ProviderUnavailableError as exc:
        outcome.checks.append(Check("web_risk", label, provider, "unavailable", f"{exc}."))
        return
    if threats:
        kinds = ", ".join(_WEB_RISK_LABELS.get(t, t.lower()) for t in threats)
        outcome.findings.append(
            FindingData(
                "critical",
                "threat_intelligence",
                "Google lists this link as dangerous",
                f"Google Web Risk lists this address for {kinds}. Browsers using Google Safe "
                "Browsing show a red warning page for it.",
                provider,
                {"threat_types": ", ".join(threats)},
            )
        )
    detail = "Listed as dangerous." if threats else "Not listed."
    outcome.checks.append(Check("web_risk", label, provider, "completed", detail))


def _certificate_history_check(url: ParsedUrl, outcome: Outcome) -> None:
    label, provider = "Certificate history", "Certificate Transparency logs (crt.sh)"
    if url.is_ip_address:
        outcome.checks.append(
            Check("certificates", label, provider, "skipped", "IP addresses have no history.")
        )
        return
    try:
        first = providers.first_certificate_seen(url.registrable_domain)
    except providers.ProviderUnavailableError as exc:
        outcome.checks.append(Check("certificates", label, provider, "unavailable", f"{exc}."))
        return
    if first is None:
        outcome.checks.append(
            Check(
                "certificates",
                label,
                provider,
                "completed",
                "No publicly logged certificates were found for this domain.",
            )
        )
        return
    outcome.details["first_certificate_at"] = first.isoformat()
    age = utcnow() - first
    if age < timedelta(days=_NEW_CERTIFICATE_DAYS):
        outcome.findings.append(
            FindingData(
                "medium",
                "domain_age",
                f"The site's first security certificate was issued {max(age.days, 0)} days ago",
                "Public certificate logs show this domain only started using HTTPS very "
                "recently. Phishing sites are usually set up days before they are used.",
                provider,
                {"domain": url.registrable_domain, "first_certificate": first.date().isoformat()},
            )
        )
    outcome.checks.append(
        Check(
            "certificates",
            label,
            provider,
            "completed",
            f"The first logged certificate for {url.registrable_domain} was issued on "
            f"{first:%Y-%m-%d}.",
        )
    )


def _hop_summary(trace: RedirectTrace) -> list[dict[str, Any]]:
    return [
        {"url": hop.url, "status": hop.status, "address": hop.address, "tls": hop.tls}
        for hop in trace.hops
    ]


def _redirect_check(
    db: Session, url: ParsedUrl, outcome: Outcome, *, read_page: bool
) -> tuple[ParsedUrl, RedirectTrace]:
    """Trace redirects and return the final destination (or the original if none)."""
    label, provider = "Destination and redirects", "SENTINEL safe fetcher"
    trace = trace_redirects(url.normalized, read_final_body=read_page)
    outcome.details["redirect_chain"] = _hop_summary(trace)

    if trace.stopped == "unsafe_destination":
        outcome.findings.append(
            FindingData(
                "medium",
                "network",
                "Link leads to a private or internal network address",
                "Public websites do not live on private addresses. A link like this may be "
                "aimed at devices on your own network, such as a router's admin page.",
                provider,
                {"detail": trace.stopped_detail},
            )
        )
    elif trace.stopped == "tls_error":
        outcome.findings.append(
            FindingData(
                "medium",
                "tls",
                "The site's security certificate is not valid",
                "The certificate is expired, issued for a different site, or not issued by a "
                "trusted authority. Browsers will warn before opening this page.",
                provider,
                {"detail": trace.stopped_detail},
            )
        )

    final = url
    if trace.final_url and trace.final_url != url.normalized:
        try:
            final = parse_url(trace.final_url)
        except InvalidUrlError:
            final = url
    if final.registrable_domain != url.registrable_domain:
        outcome.findings.append(
            FindingData(
                "info",
                "redirect",
                f"Link redirects to a different site ({final.registrable_domain})",
                "The address you submitted forwards to another domain. The checks below were "
                "also applied to that destination.",
                provider,
                {"from": url.host, "to": final.host, "hops": len(trace.hops)},
            )
        )
        outcome.findings += analyze_url_text(final)
        outcome.findings += indicator_findings(db, final)

    if trace.stopped:
        message = _STOP_MESSAGES.get(trace.stopped, "The destination could not be reached.")
        outcome.checks.append(Check("redirects", label, provider, "failed", message))
        outcome.limitations.append(
            f"We could not reach the destination, so redirects were not fully checked. {message}"
        )
    else:
        hops = len(trace.hops) - 1
        detail = f"Followed {hops} redirect{'s' if hops != 1 else ''}." if hops else "No redirects."
        outcome.checks.append(Check("redirects", label, provider, "completed", detail))

    tls = next((hop.tls for hop in reversed(trace.hops) if hop.tls), None)
    final_scheme = urlsplit(trace.final_url or url.normalized).scheme
    if tls:
        outcome.details["tls"] = tls
        outcome.checks.append(
            Check(
                "tls",
                "Security certificate",
                provider,
                "completed",
                f"Valid certificate issued by {tls.get('issuer') or 'an unnamed authority'}. "
                "A valid certificate encrypts the connection; it does not show the site is "
                "trustworthy.",
            )
        )
    elif trace.reached_destination and final_scheme == "http":
        outcome.findings.append(
            FindingData(
                "low",
                "tls",
                "The page is served without encryption",
                "The destination uses http://, so anything you send to it can be read or "
                "changed in transit. Do not enter passwords or payment details there.",
                provider,
                {"url": trace.final_url},
            )
        )
        outcome.checks.append(
            Check(
                "tls", "Security certificate", provider, "completed", "The site does not use TLS."
            )
        )
    return final, trace


def _domain_age_check(url: ParsedUrl, outcome: Outcome) -> None:
    label, provider = "Domain registration date", "RDAP (domain registry)"
    if url.is_ip_address:
        outcome.checks.append(
            Check("domain_age", label, provider, "skipped", "IP addresses have no registration.")
        )
        return
    try:
        registered_at = providers.domain_registration_date(url.registrable_domain)
    except providers.ProviderUnavailableError as exc:
        outcome.checks.append(Check("domain_age", label, provider, "unavailable", f"{exc}."))
        return

    outcome.details["domain_registered_at"] = registered_at.isoformat()
    age = utcnow() - registered_at
    if age < timedelta(days=_NEW_DOMAIN_DAYS):
        outcome.findings.append(
            FindingData(
                "medium",
                "domain_age",
                f"Domain was registered {max(age.days, 0)} days ago",
                "Most phishing sites use domains registered days or weeks before the attack. "
                "New domains are not automatically harmful, but an unfamiliar site on a "
                "brand-new domain deserves extra care.",
                provider,
                {"domain": url.registrable_domain, "registered": registered_at.date().isoformat()},
            )
        )
    outcome.checks.append(
        Check(
            "domain_age",
            label,
            provider,
            "completed",
            f"{url.registrable_domain} was registered on {registered_at:%Y-%m-%d}.",
        )
    )


def analyze_url_target(
    url: ParsedUrl, db: Session, *, read_page: bool = False
) -> tuple[Outcome, ParsedUrl, Hop | None]:
    """Run every link check. Returns the outcome, the final destination, and, if
    read_page is set and the destination served HTML, the final response."""
    outcome = Outcome(details={"submitted_url": url.normalized, "host": url.host})

    outcome.findings += analyze_url_text(url)
    outcome.checks.append(
        Check(
            "url_patterns",
            "Address patterns",
            "SENTINEL URL pattern analysis",
            "completed",
            "Checked for look-alike domains, brand impersonation and deceptive address tricks.",
        )
    )
    _local_feed_check(db, url, outcome)
    _urlhaus_live_check(url, outcome)
    _web_risk_check(url, outcome)
    final, trace = _redirect_check(db, url, outcome, read_page=read_page)
    _domain_age_check(final, outcome)
    _certificate_history_check(final, outcome)

    outcome.details["final_url"] = final.normalized
    outcome.details["registrable_domain"] = final.registrable_domain
    page = trace.hops[-1] if trace.reached_destination and trace.hops else None
    return outcome, final, page


def analyze_url(payload: dict[str, Any], db: Session) -> Outcome:
    outcome, _, _ = analyze_url_target(parse_url(payload["url"]), db)
    outcome.limitations.append(
        "Page content was not downloaded or inspected. This scan looks at the address, its "
        "reputation, where it redirects and how it is registered. Use the website analyzer "
        "to inspect the page itself."
    )
    return outcome
