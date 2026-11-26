"""The address checks the extension runs locally must agree with the server's.
Both read tests/fixtures/url-vectors.json."""

import json
from pathlib import Path

import pytest

from app.analyzers.url_heuristics import RULES, analyze_url_text, arabic_fold
from app.analyzers.urls import parse_url

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "url-vectors.json").read_text("utf-8"))[
    "vectors"
]


@pytest.mark.parametrize("vector", VECTORS, ids=[v["url"] for v in VECTORS])
def test_server_matches_shared_vectors(vector: dict) -> None:
    url = parse_url(vector["url"])
    assert url.normalized == vector["normalized"]
    assert url.registrable_domain == vector["registrableDomain"]
    got = [
        {"severity": f.severity, "category": f.category, "title": f.title}
        for f in analyze_url_text(url)
    ]
    assert got == vector["findings"]


def test_arabic_folding_merges_letter_variants_and_drops_marks() -> None:
    assert arabic_fold("إبشـر") == "ابشر"
    assert arabic_fold("مَدرسة") == "مدرسه"
    assert arabic_fold("٠١٢٣") == "0123"


def test_generic_arabic_words_are_not_brands() -> None:
    # Ordinary words that are also brand names would flag countless real sites.
    for word in ("كريم", "سالك", "نفاذ", "طلبات", "اتصالات", "مسقط"):
        assert word not in RULES["arabic"]["brands"]


def test_every_arabic_brand_points_at_a_known_brand() -> None:
    for name, brand in RULES["arabic"]["brands"].items():
        assert brand in RULES["brands"], name
        assert arabic_fold(name) == name, name
