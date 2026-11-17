"""Phone numbers: which country they belong to, and what that suggests.

Used by the phone lookup and message scans. This is about context, not
judgement: a foreign number is not a scam, but a "local bank" calling from
abroad is a well-known warning sign.
"""

from dataclasses import dataclass

COUNTRY_CODES: dict[str, tuple[str, str]] = {
    "971": ("United Arab Emirates", "الإمارات العربية المتحدة"),
    "966": ("Saudi Arabia", "المملكة العربية السعودية"),
    "974": ("Qatar", "قطر"),
    "965": ("Kuwait", "الكويت"),
    "973": ("Bahrain", "البحرين"),
    "968": ("Oman", "عُمان"),
    "20": ("Egypt", "مصر"),
    "962": ("Jordan", "الأردن"),
    "961": ("Lebanon", "لبنان"),
    "212": ("Morocco", "المغرب"),
    "213": ("Algeria", "الجزائر"),
    "216": ("Tunisia", "تونس"),
    "964": ("Iraq", "العراق"),
    "963": ("Syria", "سوريا"),
    "967": ("Yemen", "اليمن"),
    "249": ("Sudan", "السودان"),
    "44": ("United Kingdom", "المملكة المتحدة"),
    "1": ("United States or Canada", "الولايات المتحدة أو كندا"),
    "91": ("India", "الهند"),
    "92": ("Pakistan", "باكستان"),
    "63": ("Philippines", "الفلبين"),
    "234": ("Nigeria", "نيجيريا"),
    "880": ("Bangladesh", "بنغلاديش"),
    "84": ("Vietnam", "فيتنام"),
    "855": ("Cambodia", "كمبوديا"),
    "95": ("Myanmar", "ميانمار"),
}

# International premium-rate and shared-cost ranges that "missed call" scams use.
PREMIUM_PREFIXES = ("882", "883", "881", "979", "808")


@dataclass(frozen=True)
class PhoneInfo:
    normalized: str
    country_code: str | None
    country: str | None
    country_ar: str | None
    international_format: bool
    premium: bool


def phone_info(normalized: str) -> PhoneInfo:
    """`normalized` is digits with an optional leading + (see normalize_phone)."""
    digits = normalized.lstrip("+")
    international = normalized.startswith("+") or normalized.startswith("00")
    if normalized.startswith("00"):
        digits = digits[2:]
    code = None
    if international:
        for length in (3, 2, 1):
            if digits[:length] in COUNTRY_CODES:
                code = digits[:length]
                break
    country = COUNTRY_CODES.get(code or "")
    return PhoneInfo(
        normalized=normalized,
        country_code=code,
        country=country[0] if country else None,
        country_ar=country[1] if country else None,
        international_format=international,
        premium=international and digits.startswith(PREMIUM_PREFIXES),
    )
