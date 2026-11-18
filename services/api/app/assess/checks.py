"""Read-only security checks for a website the account owns.

Every function here is pure: it is given data already fetched by the runner and
returns findings. Nothing here makes a request, changes anything, or sends a
crafted payload. The checks are the kind a site owner would run against their
own site: configuration review, not exploitation.

A finding's severity follows common web-security practice. The report never
calls a site "secure"; the best result is "no issues found in the checks that
ran", which the summary states plainly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    explanation: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


# --- TLS and HTTPS ---------------------------------------------------------------------


def check_https(
    *,
    http_redirects_to_https: bool | None,
    cert_valid_until: str | None,
    now: datetime | None = None,
) -> list[Finding]:
    now = now or datetime.now(UTC)
    findings: list[Finding] = []
    if http_redirects_to_https is False:
        findings.append(
            Finding(
                "high",
                "tls",
                "Plain HTTP is not redirected to HTTPS",
                "The site answers on http:// without sending visitors to https://. "
                "Anyone on the same network can read or change the unencrypted traffic.",
                "Redirect every http:// request to https:// with a 301, and add HSTS.",
            )
        )
    if cert_valid_until:
        expiry = _parse_cert_date(cert_valid_until)
        if expiry is not None:
            days = (expiry - now).days
            if days < 0:
                findings.append(
                    Finding(
                        "critical",
                        "tls",
                        "The TLS certificate has expired",
                        f"The certificate expired on {cert_valid_until}. Browsers now show a "
                        "full-page warning, and visitors cannot reach the site safely.",
                        "Renew it now, and automate renewal (for example with Let's Encrypt).",
                        {"valid_until": cert_valid_until},
                    )
                )
            elif days < 14:
                findings.append(
                    Finding(
                        "medium",
                        "tls",
                        f"The TLS certificate expires in {days} day(s)",
                        f"The certificate expires on {cert_valid_until}. If it lapses, visitors "
                        "see a security warning.",
                        "Renew it now and set up automatic renewal.",
                        {"valid_until": cert_valid_until},
                    )
                )
            elif days < 30:
                findings.append(
                    Finding(
                        "low",
                        "tls",
                        f"The TLS certificate expires in {days} days",
                        f"The certificate expires on {cert_valid_until}.",
                        "Make sure automatic renewal is working.",
                        {"valid_until": cert_valid_until},
                    )
                )
    return findings


def _parse_cert_date(value: str) -> datetime | None:
    # OpenSSL format, e.g. "Jan  5 12:00:00 2027 GMT".
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        parsed = parsedate_to_datetime(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return None


# --- Security headers ------------------------------------------------------------------


def check_headers(headers: dict[str, str]) -> list[Finding]:
    """`headers` are the final HTTPS response headers, names lower-cased."""
    findings: list[Finding] = []
    h = {k.lower(): v for k, v in headers.items()}

    hsts = h.get("strict-transport-security")
    if not hsts:
        findings.append(
            Finding(
                "medium",
                "headers",
                "No HSTS header",
                "Without Strict-Transport-Security, a visitor's first request can be "
                "downgraded to http:// by an attacker on the network.",
                "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            )
        )
    elif "max-age=0" in hsts.replace(" ", "") or _hsts_max_age(hsts) < 2592000:
        findings.append(
            Finding(
                "low",
                "headers",
                "HSTS max-age is short",
                "A short HSTS lifetime weakens the protection; browsers forget it quickly.",
                "Use max-age of at least 31536000 (one year).",
                {"header": hsts[:200]},
            )
        )

    if not h.get("content-security-policy"):
        findings.append(
            Finding(
                "medium",
                "headers",
                "No Content-Security-Policy",
                "A Content-Security-Policy is the strongest defence against cross-site "
                "scripting (XSS). Without it, an injected script runs with no restriction.",
                "Add a Content-Security-Policy, starting in report-only mode to find breakage.",
            )
        )

    xcto = (h.get("x-content-type-options") or "").lower()
    if "nosniff" not in xcto:
        findings.append(
            Finding(
                "low",
                "headers",
                "No X-Content-Type-Options: nosniff",
                "Without nosniff, browsers may guess a response's type and run a file as a "
                "script that the server meant to be plain data.",
                "Send 'X-Content-Type-Options: nosniff'.",
            )
        )

    xfo = (h.get("x-frame-options") or "").lower()
    csp = (h.get("content-security-policy") or "").lower()
    if "deny" not in xfo and "sameorigin" not in xfo and "frame-ancestors" not in csp:
        findings.append(
            Finding(
                "medium",
                "headers",
                "No clickjacking protection",
                "The page can be framed by any site, so it can be used in a clickjacking "
                "attack that tricks your users into clicking hidden controls.",
                "Send 'X-Frame-Options: DENY', or a CSP 'frame-ancestors' directive.",
            )
        )

    if not h.get("referrer-policy"):
        findings.append(
            Finding(
                "low",
                "headers",
                "No Referrer-Policy",
                "Without a Referrer-Policy, full URLs (which can contain tokens) may be sent "
                "to other sites your pages link to.",
                "Send 'Referrer-Policy: strict-origin-when-cross-origin'.",
            )
        )

    disclosed = _version_disclosure(h)
    if disclosed:
        findings.append(
            Finding(
                "low",
                "disclosure",
                "Server software version is disclosed",
                "Response headers reveal exact software versions, which makes it easy for an "
                "attacker to look up known vulnerabilities for them.",
                "Remove version numbers from the Server and X-Powered-By headers.",
                {"headers": disclosed},
            )
        )
    return findings


def _hsts_max_age(value: str) -> int:
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return 0
    return 0


def _version_disclosure(headers: dict[str, str]) -> dict[str, str]:
    import re

    out: dict[str, str] = {}
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = headers.get(name)
        if value and re.search(r"\d+\.\d+", value):
            out[name] = value[:120]
    return out


# --- Cookies ---------------------------------------------------------------------------


def check_cookies(set_cookie_headers: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        if not name:
            continue
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        looks_session = any(
            word in name.lower() for word in ("sess", "sid", "auth", "token", "login")
        )
        if "secure" not in attrs:
            findings.append(
                Finding(
                    "medium" if looks_session else "low",
                    "cookies",
                    f"Cookie '{name}' is not marked Secure",
                    "A cookie without the Secure flag can be sent over plain http:// and read "
                    "by anyone on the network.",
                    "Add the Secure attribute to this cookie.",
                    {"cookie": name},
                )
            )
        if "httponly" not in attrs and looks_session:
            findings.append(
                Finding(
                    "medium",
                    "cookies",
                    f"Session cookie '{name}' is not HttpOnly",
                    "Without HttpOnly, a cross-site scripting bug can steal this cookie and with "
                    "it the user's session.",
                    "Add the HttpOnly attribute to this cookie.",
                    {"cookie": name},
                )
            )
        if not any(a.startswith("samesite") for a in attrs):
            findings.append(
                Finding(
                    "low",
                    "cookies",
                    f"Cookie '{name}' has no SameSite attribute",
                    "SameSite limits when the cookie is sent with cross-site requests, which "
                    "helps prevent cross-site request forgery.",
                    "Add 'SameSite=Lax' (or Strict) to this cookie.",
                    {"cookie": name},
                )
            )
    return findings


# --- Exposed paths ---------------------------------------------------------------------

# Paths that should never be readable on a production site. Each is fetched with a
# single GET; a 200 with matching content is the finding. These are the owner's own
# pages, and only common, well-known locations are tried — no brute forcing.
SENSITIVE_PATHS: tuple[dict[str, Any], ...] = (
    {
        "path": "/.git/config",
        "severity": "critical",
        "needle": "[core]",
        "title": "The .git directory is publicly readable",
        "explanation": "Anyone can download your full source code and its history, which often "
        "contains passwords and keys committed by mistake.",
        "recommendation": "Block access to /.git, and move the working copy outside the web root.",
    },
    {
        "path": "/.env",
        "severity": "critical",
        "needle": "=",
        "title": "An .env file is publicly readable",
        "explanation": "Environment files hold database passwords, API keys and app secrets.",
        "recommendation": "Remove the file from the web root and rotate every secret it contained.",
    },
    {
        "path": "/.svn/entries",
        "severity": "high",
        "needle": "",
        "title": "A Subversion directory is publicly readable",
        "explanation": "It can expose your source code.",
        "recommendation": "Block access to /.svn and keep source outside the web root.",
    },
    {
        "path": "/server-status",
        "severity": "medium",
        "needle": "Apache Server Status",
        "title": "The Apache server-status page is public",
        "explanation": "It lists live requests, visitor addresses and the URLs they are viewing.",
        "recommendation": "Restrict mod_status to localhost.",
    },
    {
        "path": "/phpinfo.php",
        "severity": "high",
        "needle": "phpinfo()",
        "title": "A phpinfo() page is public",
        "explanation": "It reveals the full server configuration, paths and loaded modules.",
        "recommendation": "Delete the file.",
    },
    {
        "path": "/.well-known/security.txt",
        "severity": "info",
        "needle": "",
        "title": "A security.txt contact file is published",
        "explanation": "Good practice: it tells security researchers how to report issues to you.",
        "recommendation": "No action needed.",
        "good": True,
    },
)


def check_exposed_path(entry: dict[str, Any], status: int | None, body: str) -> Finding | None:
    """Decide whether one fetched sensitive path is a finding."""
    if status != 200:
        return None
    needle = entry.get("needle") or ""
    if needle and needle.lower() not in body.lower():
        return None
    return Finding(
        entry["severity"],
        "exposure" if not entry.get("good") else "good_practice",
        entry["title"],
        entry["explanation"],
        entry["recommendation"],
        {"path": entry["path"]},
    )


def check_directory_listing(path: str, status: int | None, body: str) -> Finding | None:
    if status == 200 and ("Index of /" in body or "<title>Directory listing for" in body):
        return Finding(
            "low",
            "exposure",
            f"Directory listing is enabled at {path}",
            "The server lists the files in this folder, which can reveal files you did not "
            "mean to publish.",
            "Turn off automatic directory listing (for example 'Options -Indexes' in Apache).",
            {"path": path},
        )
    return None


# --- DNS and email ---------------------------------------------------------------------


def check_dns(
    *, txt_records: list[str], dmarc_records: list[str], has_mx: bool, dnssec: bool | None
) -> list[Finding]:
    findings: list[Finding] = []
    spf = [r for r in txt_records if r.lower().startswith("v=spf1")]
    dmarc = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]

    if has_mx and not spf:
        findings.append(
            Finding(
                "low",
                "email",
                "No SPF record",
                "Without an SPF record, anyone can send email that claims to be from your "
                "domain, which helps phishing.",
                "Publish an SPF TXT record listing the servers allowed to send your mail.",
            )
        )
    if not dmarc:
        findings.append(
            Finding(
                "medium" if has_mx else "low",
                "email",
                "No DMARC record",
                "DMARC tells receiving mail servers what to do with forged email from your "
                "domain. Without it, impersonation is easy and you get no reports.",
                "Publish a _dmarc TXT record, starting with 'v=DMARC1; p=none' and a reporting "
                "address, then tighten to quarantine or reject.",
            )
        )
    elif any("p=none" in r.lower().replace(" ", "") for r in dmarc):
        findings.append(
            Finding(
                "low",
                "email",
                "DMARC policy is 'none'",
                "A DMARC policy of p=none only monitors; it does not stop forged email being "
                "delivered.",
                "Once your reports look clean, move the policy to 'quarantine' then 'reject'.",
            )
        )
    if dnssec is False:
        findings.append(
            Finding(
                "info",
                "dns",
                "DNSSEC is not enabled",
                "DNSSEC signs your DNS so answers cannot be forged. It is optional and not all "
                "registrars support it.",
                "Enable DNSSEC at your DNS provider if it is available.",
            )
        )
    return findings


# --- Summary ---------------------------------------------------------------------------


def summarise(findings: list[Finding]) -> tuple[str, str]:
    """Return (result, summary sentence). Never claims the site is secure.

    Only critical/high/medium/low findings count as "issues". Info findings are
    informational notes (for example DNSSEC being off) and are listed but do not
    change the headline from "no issues"."""
    graded = [f for f in findings if f.category != "good_practice"]
    issues = [f for f in graded if f.severity != "info"]
    notes = len(graded) - len(issues)
    if not issues:
        extra = f" {notes} informational note(s) are listed below." if notes else ""
        return (
            "no_issues",
            "No issues were found by the checks that ran. This is not a guarantee that the "
            "site is secure — these checks look only at common configuration mistakes." + extra,
        )
    worst = sorted(issues, key=lambda f: _ORDER[f.severity])[0].severity
    counts: dict[str, int] = {}
    for f in graded:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = [
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if s in counts
    ]
    return worst, (
        f"Found {len(issues)} issue(s) to review: {', '.join(parts)}. "
        "They are configuration weaknesses on your own site, listed below with how to fix each."
    )


# --- Light active tests (opt-in, confirmed per scan) ------------------------------------
#
# Three GET requests to the site's own homepage. They send harmless markers, never
# exploit code, never submit forms or credentials, and change nothing on the site.

REDIRECT_CANARY = "https://sentinel-redirect-test.invalid/"
_REDIRECT_PARAMS = ("next", "url", "redirect", "return", "returnUrl", "continue")
_SQL_ERRORS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query()",
    "psycopg2.errors",
    "sqlstate[",
    "ora-01756",
    "ora-00933",
    "sqlite3.operationalerror",
    "syntax error at or near",
)


def probe_marker(token: str) -> str:
    """A marker with characters that must be escaped in HTML. Not script."""
    return f"sntl{token}\"'<x>"


def probe_paths(token: str) -> dict[str, str]:
    from urllib.parse import quote, urlencode

    marker = probe_marker(token)
    return {
        "reflection": "/?" + urlencode({"q": marker, "s": marker, "search": marker}),
        "redirect": "/?" + urlencode(dict.fromkeys(_REDIRECT_PARAMS, REDIRECT_CANARY)),
        "sql": f"/?id=1{quote(chr(39))}&q={quote(chr(39))}",
    }


def check_reflection(token: str, status: int | None, body: str) -> Finding | None:
    if status is None or not body:
        return None
    if probe_marker(token) in body:
        return Finding(
            "high",
            "active",
            "Text from the address is shown on the page without escaping",
            "Qalaa put a harmless marker containing < > and quotes in the page address, "
            "and the page displayed it unchanged. An attacker could put script there instead "
            "(reflected cross-site scripting) and send the link to your users.",
            "Escape everything from the URL before writing it into HTML (most templating "
            "engines do this by default), and add a Content-Security-Policy.",
            {"marker": f"sntl{token}"},
        )
    return None


def check_open_redirect(status: int | None, location: str | None) -> Finding | None:
    if (
        status in (301, 302, 303, 307, 308)
        and location
        and location.startswith(REDIRECT_CANARY.rstrip("/"))
    ):
        return Finding(
            "medium",
            "active",
            "The homepage redirects to any address given in the URL",
            "A link to your own site can send visitors anywhere, which phishing campaigns use "
            "to make malicious links look trustworthy (an open redirect).",
            "Only redirect to your own paths, or to an allow-list of addresses.",
            {"location": location[:200]},
        )
    return None


def check_sql_errors(body: str) -> Finding | None:
    lowered = body.lower()
    hit = next((signature for signature in _SQL_ERRORS if signature in lowered), None)
    if hit:
        return Finding(
            "high",
            "active",
            "A database error message is shown to visitors",
            "Adding a single quote to the address made the page show a database error. That "
            "usually means input reaches the database without being handled safely (a sign of "
            "possible SQL injection), and it reveals details about your database.",
            "Use parameterised queries everywhere, and show a generic error page instead of "
            "database errors.",
            {"signature": hit},
        )
    return None
