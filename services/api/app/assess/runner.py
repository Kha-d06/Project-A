"""Runs one security assessment against a domain the account owns.

Order matters: ownership is confirmed again before anything is probed. If that
fails, the assessment stops with a clear message and makes no requests to the
site. Every request after that is a plain GET to the owner's own domain, spaced
out, reading only what the server returns.
"""

from __future__ import annotations

import logging
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.analyzers import safe_fetch
from app.assess import checks, verify
from app.models import Assessment, VerifiedDomain
from app.models.base import utcnow

logger = logging.getLogger(__name__)

PAUSE_BETWEEN_REQUESTS = 0.4


@dataclass
class FetchResult:
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    tls_valid_until: str | None = None
    body: str = ""
    redirect_location: str | None = None
    error: str | None = None


Fetcher = Callable[[str], FetchResult]


def _default_fetch(url: str) -> FetchResult:
    try:
        hop = safe_fetch.fetch_resource(url)
    except safe_fetch.UnsafeDestinationError as exc:
        return FetchResult(status=None, error=f"unsafe: {exc}")
    except safe_fetch.ResolutionError:
        return FetchResult(status=None, error="unresolved")
    except Exception as exc:  # noqa: BLE001 - any network error is just "unreachable"
        return FetchResult(status=None, error=type(exc).__name__)
    set_cookies = [value for name, value in hop.raw_headers if name == "set-cookie"]
    return FetchResult(
        status=hop.status,
        headers=hop.headers,
        set_cookies=set_cookies,
        tls_valid_until=(hop.tls or {}).get("valid_until"),
        body=(hop.body or b"")[: checks_body_limit()].decode("utf-8", "replace"),
        redirect_location=hop.location,
    )


def checks_body_limit() -> int:
    return 256 * 1024


@dataclass
class _Runner:
    fetch: Fetcher
    resolver: verify.TxtResolver
    has_mx: Callable[[str], bool]
    dnssec: Callable[[str], bool | None]
    pause: float = PAUSE_BETWEEN_REQUESTS

    findings: list[checks.Finding] = field(default_factory=list)
    records: list[dict[str, str]] = field(default_factory=list)
    pages: int = 0

    def _check(self, key: str, label: str, status: str, detail: str) -> None:
        self.records.append({"key": key, "label": label, "status": status, "detail": detail})

    def _sleep(self) -> None:
        if self.pause:
            time.sleep(self.pause)

    def run_probes(self, domain: str) -> None:
        """The opt-in active tests: three GETs to the homepage, nothing more."""
        token = secrets.token_hex(4)
        paths = checks.probe_paths(token)
        self._sleep()
        reflected = self.fetch(f"https://{domain}{paths['reflection']}")
        self.pages += 1
        self._sleep()
        redirect = self.fetch(f"https://{domain}{paths['redirect']}")
        self.pages += 1
        self._sleep()
        sql = self.fetch(f"https://{domain}{paths['sql']}")
        self.pages += 1
        for finding in (
            checks.check_reflection(token, reflected.status, reflected.body),
            checks.check_open_redirect(redirect.status, redirect.redirect_location),
            checks.check_sql_errors(sql.body),
        ):
            if finding:
                self.findings.append(finding)
        self._check(
            "active",
            "Light active tests (XSS reflection, open redirect, database errors)",
            "completed",
            "3 requests",
        )

    def run(self, domain: str) -> None:
        https = self.fetch(f"https://{domain}/")
        self.pages += 1
        if https.status is None:
            self._check(
                "reach", "Reach the site over HTTPS", "unavailable", https.error or "unreachable"
            )
        else:
            self._check("reach", "Reach the site over HTTPS", "completed", f"HTTP {https.status}")
            self.findings += checks.check_headers(https.headers)
            self._check("headers", "Security response headers", "completed", "checked")
            self.findings += checks.check_cookies(https.set_cookies)
            self._check(
                "cookies",
                "Cookie flags",
                "completed",
                f"{len(https.set_cookies)} cookie(s) checked",
            )
            listing = checks.check_directory_listing("/", https.status, https.body)
            if listing:
                self.findings.append(listing)

        # HTTP should redirect to HTTPS.
        self._sleep()
        http = self.fetch(f"http://{domain}/")
        self.pages += 1
        redirects = None
        if http.status is not None:
            location = (http.redirect_location or "").lower()
            redirects = http.status in (301, 302, 307, 308) and location.startswith("https://")
            self._check(
                "https_redirect",
                "Redirect HTTP to HTTPS",
                "completed",
                "redirects" if redirects else "no redirect",
            )
        else:
            self._check(
                "https_redirect", "Redirect HTTP to HTTPS", "unavailable", "no HTTP service"
            )
        self.findings += checks.check_https(
            http_redirects_to_https=redirects, cert_valid_until=https.tls_valid_until
        )
        self._check(
            "tls",
            "TLS certificate",
            "completed" if https.tls_valid_until else "unavailable",
            https.tls_valid_until or "not read",
        )

        # Exposed sensitive paths.
        exposed = 0
        for entry in checks.SENSITIVE_PATHS:
            self._sleep()
            result = self.fetch(f"https://{domain}{entry['path']}")
            self.pages += 1
            finding = checks.check_exposed_path(entry, result.status, result.body)
            if finding:
                self.findings.append(finding)
                exposed += 1
        self._check(
            "exposure",
            "Sensitive files and pages",
            "completed",
            f"{len(checks.SENSITIVE_PATHS)} path(s) checked",
        )

        # DNS and email.
        try:
            txt = self.resolver(domain)
            dmarc = self.resolver(f"_dmarc.{domain}")
            mx = self.has_mx(domain)
            dnssec = self.dnssec(domain)
            self.findings += checks.check_dns(
                txt_records=txt, dmarc_records=dmarc, has_mx=mx, dnssec=dnssec
            )
            self._check("dns", "DNS and email (SPF, DMARC)", "completed", "checked")
        except Exception as exc:  # noqa: BLE001
            self._check("dns", "DNS and email (SPF, DMARC)", "failed", type(exc).__name__)


def run_assessment(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    fetch: Fetcher | None = None,
    resolver: verify.TxtResolver | None = None,
    has_mx: Callable[[str], bool] | None = None,
    dnssec: Callable[[str], bool | None] | None = None,
) -> None:
    job = db.get(Assessment, assessment_id)
    if job is None or job.status != "queued":
        return
    job.status = "running"
    job.started_at = utcnow()
    db.commit()

    fetch = fetch or _default_fetch
    resolver = resolver or verify.dns_resolver
    has_mx = has_mx or verify.has_mx
    dnssec = dnssec or verify.dnssec_enabled

    domain_ref = db.get(VerifiedDomain, job.domain_id)
    if domain_ref is None:
        _fail(db, job, "This domain is no longer on your account.")
        return

    # The gate: confirm ownership again before touching the site.
    method = verify.verify(
        job.domain,
        domain_ref.token,
        resolver=resolver,
        file_fetcher=lambda d, p: _fetch_file(fetch, d, p),
    )
    domain_ref.last_checked_at = utcnow()
    if method is None:
        domain_ref.verified_at = None
        domain_ref.verified_method = None
        db.commit()
        _fail(
            db,
            job,
            "We could not confirm that you still control this domain, so nothing was scanned. "
            "Add the verification record again and re-verify the domain.",
        )
        return
    domain_ref.verified_at = utcnow()
    domain_ref.verified_method = method
    db.commit()

    runner = _Runner(fetch=fetch, resolver=resolver, has_mx=has_mx, dnssec=dnssec)
    try:
        runner.run(job.domain)
        if job.active_probes:
            runner.run_probes(job.domain)
    except Exception:  # noqa: BLE001 - a crash must still leave a truthful record
        logger.exception("Assessment %s failed", assessment_id)
        _fail(db, job, "The assessment could not be completed because of an internal error.")
        return

    result, summary = checks.summarise(runner.findings)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    job.findings = [f.as_dict() for f in sorted(runner.findings, key=lambda f: order[f.severity])]
    job.checks = runner.records
    job.pages_checked = runner.pages
    job.result = result
    job.summary = summary
    job.status = "completed"
    job.finished_at = utcnow()
    db.commit()


def _fetch_file(fetch: Fetcher, domain: str, path: str) -> tuple[int | None, str]:
    result = fetch(f"https://{domain}{path}")
    return result.status, result.body


def _fail(db: Session, job: Assessment, message: str) -> None:
    job.status = "failed"
    job.error = message
    job.finished_at = utcnow()
    db.commit()


def recent_count(db: Session, user_id: uuid.UUID, since: datetime) -> int:
    from sqlalchemy import func, select

    return (
        db.scalar(
            select(func.count())
            .select_from(Assessment)
            .where(Assessment.user_id == user_id, Assessment.created_at >= since)
        )
        or 0
    )


def month_start(now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
