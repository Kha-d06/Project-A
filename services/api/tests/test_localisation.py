from fastapi.testclient import TestClient

ARABIC = {"Accept-Language": "ar"}


def test_arabic_page_gets_arabic_summary_advice_and_rule_text(client: TestClient) -> None:
    scan = client.post(
        "/api/v1/scans/message",
        json={"content": "عزيزي العميل تم إيقاف بطاقتك البنكية، يرجى تحديث بياناتك فوراً"},
        headers=ARABIC,
    ).json()
    assert scan["risk"] == "suspicious"
    assert scan["summary"].startswith("وُجدت")
    assert "هذه الرسالة" in scan["summary"]
    assert scan["recommendations"][0].startswith("لا تُدخل")
    titles = {finding["title"] for finding in scan["findings"]}
    assert "تهدّد بإيقاف حساب أو إغلاقه" in titles


def test_english_remains_the_default(client: TestClient) -> None:
    scan = client.post(
        "/api/v1/scans/message",
        json={"content": "Hi Sam, are we still meeting for lunch on Thursday?"},
    ).json()
    assert scan["summary"].startswith("No known threat was detected")


def test_arabic_inconclusive_link_summary(client: TestClient) -> None:
    scan = client.post(
        "/api/v1/scans/url",
        json={"url": "https://example.org/"},
        headers={"Accept-Language": "ar-SA,ar;q=0.9"},
    ).json()
    assert scan["risk"] == "inconclusive"
    assert "هذا الرابط" in scan["summary"]
