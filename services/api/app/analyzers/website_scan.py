"""Deeper analysis of a website: everything the link scanner does, plus DNS
records and a static reading of the page the address finally serves."""

from typing import Any

import dns.exception
import dns.resolver
from sqlalchemy.orm import Session

from app.analyzers.page_content import PageFacts, charset_of, inspect_html
from app.analyzers.page_render import RenderingUnavailableError, render_page, rendering_enabled
from app.analyzers.safe_fetch import Hop
from app.analyzers.types import Check, FindingData, Outcome
from app.analyzers.url_heuristics import BRAND_DOMAINS, brand_name
from app.analyzers.url_scan import analyze_url_target
from app.analyzers.urls import ParsedUrl, parse_url
from app.analyzers.visual import closest_match, dhash, load_references

SOURCE = "Qalaa page analysis"
DNS_SOURCE = "DNS"
_DNS_TIMEOUT_SECONDS = 3
_DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
_MAX_RECORDS = 8

# Services that let anyone publish a page on a subdomain. A login page for a big
# brand hosted on one of these is not the brand's.
FREE_HOSTING_SUFFIXES = (
    "000webhostapp.com", "weebly.com", "wixsite.com", "web.app", "firebaseapp.com",
    "github.io", "netlify.app", "vercel.app", "glitch.me", "pages.dev", "blogspot.com",
    "sites.google.com", "duckdns.org", "ddns.net", "no-ip.org", "ngrok-free.app", "ngrok.io",
)  # fmt: skip

_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}


def _on_free_hosting(url: ParsedUrl) -> str | None:
    return next(
        (
            suffix
            for suffix in FREE_HOSTING_SUFFIXES
            if url.host == suffix or url.host.endswith(f".{suffix}")
        ),
        None,
    )


def _brands_mentioned(facts: PageFacts) -> set[str]:
    text = " ".join([facts.title, *facts.headings]).lower()
    squashed = "".join(char for char in text if char.isalnum())
    return {
        brand
        for brand in BRAND_DOMAINS
        if len(brand) >= 4 and (brand in text or (len(brand) >= 6 and brand in squashed))
    }


def _brand_resources(facts: PageFacts) -> set[str]:
    brands = set()
    for host in facts.resource_hosts:
        for brand, domains in BRAND_DOMAINS.items():
            if any(host == domain or host.endswith(f".{domain}") for domain in domains):
                brands.add(brand)
    return brands


def _page_findings(final: ParsedUrl, facts: PageFacts) -> list[FindingData]:
    findings: list[FindingData] = []
    owns_brand = {
        brand for brand, domains in BRAND_DOMAINS.items() if final.registrable_domain in domains
    }
    collects_secrets = [form for form in facts.forms if form.has_password or form.has_card_fields]
    imitated = (_brands_mentioned(facts) | _brand_resources(facts)) - owns_brand

    if collects_secrets and imitated:
        brand = sorted(imitated)[0]
        findings.append(
            FindingData(
                "high",
                "brand_impersonation",
                f"Sign-in or payment page presents itself as {brand_name(brand)}",
                f"The page asks for a password or card details and uses {brand_name(brand)}'s "
                f"name or images, but it is hosted on “{final.registrable_domain}”, which is "
                f"not a {brand_name(brand)} domain. This is the typical shape of a phishing page.",
                SOURCE,
                {"page_title": facts.title, "domain": final.registrable_domain, "brand": brand},
            )
        )

    free_host = _on_free_hosting(final)
    if free_host and collects_secrets:
        findings.append(
            FindingData(
                "medium",
                "free_hosting",
                "Asks for sensitive details on a free hosting service",
                f"Anyone can publish a page on “{free_host}”. Legitimate banks and large "
                "services do not host their sign-in pages there.",
                SOURCE,
                {"host": final.host, "service": free_host},
            )
        )

    for form in collects_secrets:
        action = parse_url(form.action) if form.action.startswith("http") else None
        if action and action.scheme == "http":
            findings.append(
                FindingData(
                    "medium",
                    "insecure_form",
                    "Password or card form sends data without encryption",
                    "The form submits to an http:// address, so whatever is typed into it can be "
                    "read by others on the network.",
                    SOURCE,
                    {"form_action": form.action},
                )
            )
        elif action and action.registrable_domain != final.registrable_domain:
            findings.append(
                FindingData(
                    "medium",
                    "external_form",
                    "Sign-in form sends your details to a different site",
                    f"The form on this page submits to “{action.registrable_domain}”. "
                    "Legitimate sign-in forms almost always submit to the same organisation.",
                    SOURCE,
                    {"form_action": form.action, "page_domain": final.registrable_domain},
                )
            )

    if (
        final.scheme == "http"
        and collects_secrets
        and not any(f.category == "insecure_form" for f in findings)
    ):
        findings.append(
            FindingData(
                "medium",
                "insecure_form",
                "Asks for a password or card details over an unencrypted connection",
                "The page itself is served over http://, so anything entered can be intercepted.",
                SOURCE,
                {"url": final.normalized},
            )
        )

    for behaviour in facts.obfuscation:
        findings.append(
            FindingData(
                "medium" if "miner" in behaviour else "low",
                "suspicious_script",
                f"Page script {behaviour}",
                "Obfuscated scripts are common in phishing kits and malicious pages, though some "
                "legitimate sites use similar techniques to protect their code.",
                SOURCE,
                {},
            )
        )

    if facts.hidden_iframes:
        findings.append(
            FindingData(
                "low",
                "hidden_iframe",
                "Page loads content in an invisible frame",
                "Invisible frames are sometimes used to load tracking or malicious content "
                "without the visitor noticing.",
                SOURCE,
                {"frames": facts.hidden_iframes[:5]},
            )
        )

    if facts.meta_refresh and "url=" in facts.meta_refresh.lower():
        findings.append(
            FindingData(
                "info",
                "redirect",
                "Page immediately forwards visitors elsewhere",
                "The page uses a refresh instruction to send browsers to another address. "
                "Qalaa did not follow it.",
                SOURCE,
                {"refresh": facts.meta_refresh},
            )
        )
    return findings


def _dns_records(host: str, outcome: Outcome) -> None:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT_SECONDS
    records: dict[str, list[str]] = {}
    failures = 0
    for record_type in _DNS_RECORD_TYPES:
        try:
            answer = resolver.resolve(host, record_type)
            records[record_type] = [str(item)[:200] for item in answer][:_MAX_RECORDS]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[record_type] = []
        except (dns.exception.DNSException, OSError):
            failures += 1
    outcome.details["dns"] = records
    if failures == len(_DNS_RECORD_TYPES):
        outcome.checks.append(
            Check("dns", "DNS records", DNS_SOURCE, "unavailable", "The DNS lookup did not answer.")
        )
        return
    outcome.checks.append(
        Check(
            "dns",
            "DNS records",
            DNS_SOURCE,
            "completed",
            f"Looked up {', '.join(records)} records for {host}.",
        )
    )


def _page_check(final: ParsedUrl, page: Hop | None, outcome: Outcome) -> None:
    label = "Page content"
    if page is None or page.body is None:
        reason = (
            "The destination could not be reached."
            if page is None
            else "The destination did not return an HTML page."
        )
        outcome.checks.append(
            Check("page", label, SOURCE, "failed" if page is None else "skipped", reason)
        )
        outcome.limitations.append(f"The page itself was not inspected. {reason}")
        return

    facts = inspect_html(
        page.body, final.normalized, charset_of(page.headers.get("content-type", ""))
    )
    outcome.findings += _page_findings(final, facts)
    outcome.details["page"] = _page_summary(facts, page)
    outcome.checks.append(
        Check(
            "page",
            label,
            SOURCE,
            "completed",
            f"Read {len(page.body) // 1024 or 1} KB of HTML and inspected its forms, scripts and "
            "frames without running anything.",
        )
    )
    if page.body_truncated:
        outcome.limitations.append("Only the first 2 MB of the page were inspected.")


def _page_summary(facts: PageFacts, page: Hop) -> dict[str, Any]:
    return {
        "title": facts.title,
        "description": facts.description,
        "generator": facts.generator,
        "forms": [
            {
                "action": form.action,
                "method": form.method,
                "asks_for_password": form.has_password,
                "asks_for_card": form.has_card_fields,
            }
            for form in facts.forms[:10]
        ],
        "external_script_hosts": sorted(
            {src.split("/")[2] for src in facts.script_sources if src.count("/") >= 2}
        )[:20],
        "hidden_frames": facts.hidden_iframes[:5],
        "security_headers": {
            label: header in page.headers for header, label in _SECURITY_HEADERS.items()
        },
    }


def _mail_policy_check(domain: str, outcome: Outcome) -> None:
    """SPF and DMARC say whether a domain protects itself against forged email.
    Their absence is context for messages "from" this domain, not a threat."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT_SECONDS
    found: dict[str, str | None] = {}
    try:
        for label, name, prefix in (
            ("spf", domain, "v=spf1"),
            ("dmarc", f"_dmarc.{domain}", "v=dmarc1"),
        ):
            try:
                texts = [
                    b"".join(item.strings).decode("utf-8", "replace")
                    for item in resolver.resolve(name, "TXT")
                ]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                texts = []
            found[label] = next((t[:300] for t in texts if t.lower().startswith(prefix)), None)
    except (dns.exception.DNSException, OSError):
        outcome.checks.append(
            Check(
                "mail_policy",
                "Email protection (SPF and DMARC)",
                DNS_SOURCE,
                "unavailable",
                "The DNS lookup did not answer.",
            )
        )
        return
    outcome.details["mail_policy"] = found
    dmarc = (found.get("dmarc") or "").lower().replace(" ", "")
    enforced = "p=reject" in dmarc or "p=quarantine" in dmarc
    if not found.get("spf") and not found.get("dmarc"):
        detail = "This domain publishes no SPF or DMARC policy."
        outcome.findings.append(
            FindingData(
                "info",
                "email_security",
                "Anyone can send email that claims to come from this domain",
                "The domain does not publish SPF or DMARC records, so mail providers cannot "
                "tell forged messages from real ones. Be careful with emails claiming to be "
                "from it.",
                DNS_SOURCE,
                {"domain": domain},
            )
        )
    elif not enforced:
        detail = "SPF or DMARC is published, but forged mail is not rejected."
    else:
        detail = "SPF and an enforcing DMARC policy are published."
    outcome.checks.append(
        Check("mail_policy", "Email protection (SPF and DMARC)", DNS_SOURCE, "completed", detail)
    )


def _visual_check(final: ParsedUrl, screenshot: bytes | None, outcome: Outcome) -> None:
    references = load_references()
    if not screenshot or not references:
        return
    try:
        page_hash = dhash(screenshot)
    except OSError:
        return
    match = closest_match(page_hash, final.registrable_domain, references)
    outcome.details.setdefault("page", {})["visual_hash"] = f"{page_hash:016x}"
    if match is None:
        return
    reference, gap = match
    name = brand_name(reference.brand)
    outcome.findings.append(
        FindingData(
            "high",
            "visual_impersonation",
            f"Page looks like {name}'s sign-in page",
            f"The page is visually almost identical to {name}'s real sign-in page, but it is "
            f"hosted on “{final.registrable_domain}”, which does not belong to {name}. Copying the "
            "look of a real page is how phishing kits work.",
            "Qalaa visual comparison",
            {"brand": name, "domain": final.registrable_domain, "difference": f"{gap}/64"},
        )
    )


def _rendered_check(final: ParsedUrl, outcome: Outcome) -> bool:
    """Load the page in the isolated browser and inspect what scripts built.
    Returns True when the rendered page was inspected."""
    label, provider = "Page as a browser shows it", "Qalaa isolated browser"
    if not rendering_enabled():
        return False
    try:
        result = render_page(final.normalized)
    except RenderingUnavailableError as exc:
        outcome.checks.append(Check("rendered_page", label, provider, "unavailable", f"{exc}."))
        return False
    facts = inspect_html(result.html.encode("utf-8"), result.final_url, "utf-8")
    known = {(f.category, f.title) for f in outcome.findings}
    for finding in _page_findings(final, facts):
        if (finding.category, finding.title) not in known:
            outcome.findings.append(finding)
    _visual_check(final, result.screenshot, outcome)
    rendered = outcome.details.setdefault("page", {})
    rendered["rendered"] = {
        "title": result.title,
        "final_url": result.final_url,
        "resources_loaded": result.requests,
        "requests_refused": result.refused[:10],
        "forms_after_scripts": len(facts.forms),
    }
    detail = (
        f"Opened the page in an isolated browser with no access to private networks and "
        f"inspected it after scripts ran ({result.requests} resources loaded"
        + (f", {len(result.refused)} requests refused" if result.refused else "")
        + ")."
    )
    outcome.checks.append(Check("rendered_page", label, provider, "completed", detail))
    if result.truncated:
        outcome.limitations.append(
            "The page loaded more resources than the isolated browser allows, so it was only "
            "partly rendered."
        )
    return True


def analyze_website(payload: dict[str, Any], db: Session) -> Outcome:
    outcome, final, page = analyze_url_target(parse_url(payload["url"]), db, read_page=True)
    _page_check(final, page, outcome)
    rendered = page is not None and _rendered_check(final, outcome)
    if not final.is_ip_address:
        _dns_records(final.host, outcome)
        _mail_policy_check(final.registrable_domain, outcome)
    if not rendered:
        outcome.limitations.append(
            "The page was read as text; scripts were not run, so content that a script would "
            "load or change was not seen."
            + ("" if rendering_enabled() else " Isolated browser inspection is not enabled.")
        )
    return outcome
