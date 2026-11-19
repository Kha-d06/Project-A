"""Checking one email: its headers, its links and its wording.

Used by the desktop app's mailbox scanner and the Thunderbird add-on. They send
the few headers that matter, the text, and each link with the text it shows.
Nothing is stored. The wording and the links go through the same analysis as a
pasted message; this module adds what only an email has:

- the receiving server's verdict on SPF, DKIM and DMARC (Authentication-Results);
- a sender name that claims a brand, or shows an address, the sender is not;
- replies going to a different domain from the one the message came from;
- a link whose visible text names one site while it opens another.
"""

import re
from email.utils import parseaddr
from typing import Any

from sqlalchemy.orm import Session

from app.analyzers.message_scan import analyze_message
from app.analyzers.types import Check, FindingData, Outcome
from app.analyzers.url_heuristics import BRAND_DOMAINS, brand_name
from app.analyzers.urls import InvalidUrlError, parse_url

SOURCE = "Qalaa email analysis"
_AUTH_RESULT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_ADDRESS_IN_NAME = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_DOMAIN_TEXT = re.compile(
    r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/:?#]\S*)?$", re.I
)
_MAX_LINKS = 50


def _domain(address: str) -> str:
    _name, email = parseaddr(address)
    if "@" not in email:
        return ""
    host = email.rsplit("@", 1)[1].strip().lower().rstrip(".")
    try:
        return parse_url(host).registrable_domain
    except InvalidUrlError:
        return host


def _same_site(left: str, right: str) -> bool:
    """Equal, or one is a subdomain of the other (for names without a known suffix)."""
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")


def auth_results(header: str) -> dict[str, str]:
    """The first result for each method, as the receiving server reported it."""
    results: dict[str, str] = {}
    for method, result in _AUTH_RESULT.findall(header or ""):
        results.setdefault(method.lower(), result.lower())
    return results


def _authentication_findings(results: dict[str, str]) -> list[FindingData]:
    if results.get("dmarc") == "fail":
        return [
            FindingData(
                "high",
                "email_authentication",
                "The sender's domain says this email is not from it",
                "Your mail provider checked this message against the published rules of the "
                "domain in the From address (DMARC), and it failed. Forged senders look like this.",
                SOURCE,
                {"dmarc": "fail"},
            )
        ]
    if results.get("spf") in ("fail", "softfail") and results.get("dkim") not in ("pass", None):
        return [
            FindingData(
                "medium",
                "email_authentication",
                "This email could not prove where it came from",
                "Both the sending-server check (SPF) and the signature check (DKIM) failed. "
                "Genuine mail from large companies normally passes at least one.",
                SOURCE,
                {"spf": results["spf"], "dkim": results.get("dkim", "")},
            )
        ]
    return []


def _sender_findings(from_header: str, reply_to: str | None) -> list[FindingData]:
    findings: list[FindingData] = []
    display, address = parseaddr(from_header or "")
    sender_domain = _domain(from_header or "")
    if not sender_domain:
        return findings

    shown = _ADDRESS_IN_NAME.search(display or "")
    if shown and not _same_site(_domain(f"x@{shown.group(1)}"), sender_domain):
        findings.append(
            FindingData(
                "high",
                "sender_mismatch",
                "The sender's name shows a different address",
                f"The name reads “{display}”, but the message was sent from {address}. "
                "Putting an address in the name is a common way to hide the real sender.",
                SOURCE,
                {"display_name": display, "address": address},
            )
        )

    words = {w for w in re.split(r"[^a-z0-9]+", (display or "").lower()) if len(w) >= 3}
    squashed = re.sub(r"[^a-z0-9]", "", (display or "").lower())
    for brand, domains in BRAND_DOMAINS.items():
        if (brand in words or brand == squashed) and sender_domain not in domains:
            findings.append(
                FindingData(
                    "high",
                    "brand_impersonation",
                    f"The sender claims to be {brand_name(brand)}",
                    f"The name says {brand_name(brand)}, but the message came from "
                    f"{sender_domain}, which is not one of its domains.",
                    SOURCE,
                    {"brand": brand, "sender_domain": sender_domain},
                )
            )
            break

    reply_domain = _domain(reply_to or "")
    if reply_domain and not _same_site(reply_domain, sender_domain):
        findings.append(
            FindingData(
                "medium",
                "reply_to_mismatch",
                "Replies would go to a different domain",
                f"The message is from {sender_domain}, but replying sends your answer to "
                f"{reply_domain}. Scammers do this to receive replies to a borrowed name.",
                SOURCE,
                {"from": sender_domain, "reply_to": reply_domain},
            )
        )
    return findings


def _link_findings(links: list[dict[str, str]]) -> list[FindingData]:
    findings: list[FindingData] = []
    for link in links[:_MAX_LINKS]:
        shown = _DOMAIN_TEXT.match((link.get("text") or "").strip())
        if not shown:
            continue
        try:
            target = parse_url(link.get("href") or "")
            claimed = parse_url(shown.group(1))
        except InvalidUrlError:
            continue
        if not _same_site(claimed.registrable_domain, target.registrable_domain):
            findings.append(
                FindingData(
                    "high",
                    "link_mismatch",
                    "A link shows one address but opens another",
                    f"The link reads “{claimed.host}” but opens {target.host}.",
                    SOURCE,
                    {"shown": claimed.host, "opens": target.host},
                )
            )
            break  # one is enough to make the point
    return findings


def analyze_email(payload: dict[str, Any], db: Session) -> Outcome:
    links: list[dict[str, str]] = payload.get("links") or []
    hrefs = "\n".join(link.get("href", "") for link in links[:_MAX_LINKS])
    content = "\n".join(p for p in (payload.get("subject") or "", payload["text"], hrefs) if p)
    outcome = analyze_message({"content": content, "locale": payload.get("locale")}, db)

    results = auth_results(payload.get("authentication_results") or "")
    outcome.findings += _authentication_findings(results)
    outcome.findings += _sender_findings(payload.get("from_header") or "", payload.get("reply_to"))
    outcome.findings += _link_findings(links)
    outcome.checks.append(
        Check(
            "email_headers",
            "Sender and authentication",
            SOURCE,
            "completed",
            "Compared the sender name, address and reply address, and read the mail "
            "provider's SPF, DKIM and DMARC results"
            + ("." if results else " (the provider did not include any)."),
        )
    )
    if not results:
        outcome.limitations.append(
            "The mail provider's authentication results were not available, so a forged "
            "sender address could not be ruled out."
        )
    return outcome
