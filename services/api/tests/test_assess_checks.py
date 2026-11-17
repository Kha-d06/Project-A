from datetime import UTC, datetime

from app.assess import checks


def codes(findings: list[checks.Finding]) -> list[str]:
    return [f.title for f in findings]


def test_https_and_certificate() -> None:
    now = datetime(2026, 11, 17, tzinfo=UTC)
    assert not checks.check_https(
        http_redirects_to_https=True, cert_valid_until="Jan  5 00:00:00 2028 GMT", now=now
    )
    no_redirect = checks.check_https(http_redirects_to_https=False, cert_valid_until=None, now=now)
    assert no_redirect[0].severity == "high"
    expired = checks.check_https(
        http_redirects_to_https=True, cert_valid_until="Jan  5 00:00:00 2026 GMT", now=now
    )
    assert expired[0].severity == "critical"
    soon = checks.check_https(
        http_redirects_to_https=True, cert_valid_until="Nov 25 00:00:00 2026 GMT", now=now
    )
    assert soon[0].severity == "medium"


def test_security_headers() -> None:
    bare = checks.check_headers({})
    titles = codes(bare)
    assert "No HSTS header" in titles
    assert "No Content-Security-Policy" in titles
    assert "No clickjacking protection" in titles
    assert "No X-Content-Type-Options: nosniff" in titles
    # A well-configured site raises none of these.
    good = checks.check_headers(
        {
            "strict-transport-security": "max-age=63072000; includeSubDomains",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
        }
    )
    assert good == []


def test_version_disclosure() -> None:
    findings = checks.check_headers(
        {
            "server": "Apache/2.4.29 (Ubuntu)",
            "x-powered-by": "PHP/7.2.1",
            "strict-transport-security": "max-age=63072000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
        }
    )
    disclosure = [f for f in findings if f.category == "disclosure"]
    assert disclosure and disclosure[0].evidence["headers"]["server"].startswith("Apache/2.4")


def test_cookies() -> None:
    findings = checks.check_cookies(["sessionid=abc; Path=/", "theme=dark; Secure; SameSite=Lax"])
    session = [f for f in findings if f.evidence.get("cookie") == "sessionid"]
    assert any("Secure" in f.title for f in session)
    assert any("HttpOnly" in f.title for f in session)
    # The Secure+SameSite theme cookie only lacks HttpOnly, which we do not flag for non-session cookies.
    theme = [f for f in findings if f.evidence.get("cookie") == "theme"]
    assert theme == []


def test_exposed_paths_and_listing() -> None:
    env = next(e for e in checks.SENSITIVE_PATHS if e["path"] == "/.env")
    assert (
        checks.check_exposed_path(env, 200, "SECRET_KEY=hunter2\nDB=postgres").severity
        == "critical"
    )
    assert checks.check_exposed_path(env, 404, "") is None
    git = next(e for e in checks.SENSITIVE_PATHS if e["path"] == "/.git/config")
    assert (
        checks.check_exposed_path(git, 200, "<html>not a git file</html>") is None
    )  # needle must match
    security_txt = next(e for e in checks.SENSITIVE_PATHS if e["path"].endswith("security.txt"))
    good = checks.check_exposed_path(security_txt, 200, "Contact: mailto:x@example.com")
    assert good.category == "good_practice"
    assert (
        checks.check_directory_listing(
            "/uploads/", 200, "<title>Index of /uploads</title>"
        ).severity
        == "low"
    )


def test_dns_email() -> None:
    missing = checks.check_dns(txt_records=[], dmarc_records=[], has_mx=True, dnssec=False)
    titles = codes(missing)
    assert "No SPF record" in titles
    assert "No DMARC record" in titles
    assert "DNSSEC is not enabled" in titles
    p_none = checks.check_dns(
        txt_records=["v=spf1 include:_spf.google.com ~all"],
        dmarc_records=["v=DMARC1; p=none; rua=mailto:dmarc@example.com"],
        has_mx=True,
        dnssec=True,
    )
    assert codes(p_none) == ["DMARC policy is 'none'"]


def test_summary_never_claims_secure() -> None:
    result, summary = checks.summarise([])
    assert result == "no_issues"
    assert "not a guarantee" in summary.lower()
    assert "secure" not in summary.lower().split("not a guarantee")[0]
    result, summary = checks.summarise(
        [
            checks.Finding("critical", "exposure", "x", "y", "z"),
            checks.Finding("low", "headers", "a", "b", "c"),
        ]
    )
    assert result == "critical"
    assert "1 critical" in summary and "1 low" in summary
    # Only good-practice findings still counts as no issues.
    result, _ = checks.summarise([checks.Finding("info", "good_practice", "security.txt", "", "")])
    assert result == "no_issues"
