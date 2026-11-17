import pytest
from fastapi.testclient import TestClient

from app.analyzers.arabic import CATALOGUE, translate_finding
from app.analyzers.types import FindingData

ARABIC = {"Accept-Language": "ar"}


@pytest.mark.parametrize(
    ("english", "expected"),
    [
        ("Domain is a look-alike of “paypal.com”", "النطاق تقليد لـ«paypal.com»"),
        ("Domain was registered 3 days ago", "سُجّل النطاق قبل 3 أيام"),
        ("This exact link is listed by URLhaus", "هذا الرابط مدرج بالضبط لدى URLhaus"),
        (
            "41 of 70 antivirus engines flag this file",
            "41 من أصل 70 من محركات مكافحة الفيروسات تصنّف هذا الملف ضارًا",
        ),
        ("PDF contains JavaScript that runs when the file opens", "يحتوي ملف PDF على JavaScript"),
    ],
)
def test_titles_are_translated_with_their_values(english: str, expected: str) -> None:
    finding = FindingData("high", "x", english, "English explanation", "src")
    assert translate_finding(finding)
    assert finding.title == expected
    assert finding.explanation != "English explanation"


def test_unknown_titles_stay_untouched() -> None:
    finding = FindingData("low", "x", "Something new", "Explanation", "src")
    assert not translate_finding(finding)
    assert finding.title == "Something new"


def test_catalogue_never_calls_anything_safe() -> None:
    for entry in CATALOGUE:
        assert "آمن " not in entry.explanation


def test_arabic_scan_report_is_in_arabic(client: TestClient) -> None:
    response = client.post(
        "/api/v1/scans/url", json={"url": "https://paypa1.com/login"}, headers=ARABIC
    )
    scan = response.json()
    titles = [finding["title"] for finding in scan["findings"]]
    assert titles and all(any("؀" <= c <= "ۿ" for c in title) for title in titles), titles
    assert scan["details"]["findings_language"] == "ar"
    assert any(check["label"] == "أنماط العنوان" for check in scan["checks"])


def test_check_details_and_limitations_are_arabic(client: TestClient) -> None:
    scan = client.post(
        "/api/v1/scans/url", json={"url": "https://example.org/"}, headers=ARABIC
    ).json()
    patterns = next(check for check in scan["checks"] if check["key"] == "url_patterns")
    assert patterns["detail"].startswith("فُحص العنوان")
    assert all(any("؀" <= c <= "ۿ" for c in item) for item in scan["limitations"]), scan[
        "limitations"
    ]


def test_composite_sentences_keep_their_values() -> None:
    from app.analyzers.arabic import translate_text

    text = translate_text(
        "We could not reach the destination, so redirects were not fully checked. The site did not respond."
    )
    assert text == "تعذّر الوصول إلى الوجهة، لذا لم تُفحص إعادة التوجيه بالكامل. لم يستجب الموقع."
    assert (
        translate_text("example.com was registered on 2024-01-02.")
        == "سُجّل النطاق example.com في 2024-01-02."
    )
