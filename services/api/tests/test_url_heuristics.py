import pytest

from app.analyzers.url_heuristics import analyze_url_text
from app.analyzers.urls import InvalidUrlError, parse_url


def categories(url: str) -> dict[str, str]:
    return {finding.category: finding.severity for finding in analyze_url_text(parse_url(url))}


def test_ordinary_sites_raise_nothing() -> None:
    for url in ("https://www.wikipedia.org/wiki/Phishing", "https://www.paypal.com/signin"):
        assert analyze_url_text(parse_url(url)) == []


def test_typosquatted_brand_is_high_severity() -> None:
    assert categories("https://paypa1.com/")["typosquatting"] == "high"
    assert categories("https://paypa1-secure.com/")["brand_impersonation"] == "medium"
    assert categories("https://microsfot.com/login")["typosquatting"] == "high"
    assert categories("https://paypall.com/")["typosquatting"] == "high"


def test_brand_name_on_unrelated_domain() -> None:
    found = categories("https://paypal.account-verify.example.net/login")
    assert found["brand_impersonation"] == "medium"


def test_punycode_homograph_of_a_brand() -> None:
    # "pаypal" with a Cyrillic "а"
    host = "pаypal.com".encode("idna").decode()
    assert categories(f"https://{host}/")["homograph"] == "high"


def test_ip_address_and_hidden_destination() -> None:
    assert categories("http://203.0.113.9/invoice")["url_pattern"] == "medium"
    findings = analyze_url_text(parse_url("https://www.bank.com@evil.example/login"))
    assert any("@" in finding.title for finding in findings)


def test_shortener_is_informational_only() -> None:
    assert categories("https://bit.ly/3abcd") == {"shortener": "info"}


def test_normalization_drops_credentials_fragment_and_default_port() -> None:
    parsed = parse_url("HTTPS://user:secret@Example.COM:443/Path?q=1#frag")
    assert parsed.normalized == "https://example.com/Path?q=1"
    assert parsed.has_credentials


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "http://",
        "http://localhost",
        "exa mple.com",
        "https://example.com/" + "a" * 2100,
    ],
)
def test_unsupported_or_malformed_urls_are_rejected(value: str) -> None:
    with pytest.raises(InvalidUrlError):
        parse_url(value)
