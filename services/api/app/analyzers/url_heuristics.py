"""Checks that only look at the text of a URL. No network access."""

import unicodedata

from app.analyzers.types import FindingData
from app.analyzers.urls import ParsedUrl

SOURCE = "Qalaa URL pattern analysis"

# Frequently impersonated brands and the domains they actually use. Kept short on
# purpose: a larger list raises the odds of flagging an unrelated legitimate site.
BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.me"}),
    "google": frozenset({"google.com", "google.co.uk", "googleapis.com", "google.ae"}),
    "microsoft": frozenset({"microsoft.com", "microsoftonline.com", "live.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "amazon": frozenset({"amazon.com", "amazon.co.uk", "amazon.ae", "amazon.sa", "amazon.eg"}),
    "facebook": frozenset({"facebook.com", "fb.com"}),
    "instagram": frozenset({"instagram.com"}),
    "whatsapp": frozenset({"whatsapp.com", "whatsapp.net"}),
    "netflix": frozenset({"netflix.com"}),
    "linkedin": frozenset({"linkedin.com"}),
    "binance": frozenset({"binance.com"}),
    "coinbase": frozenset({"coinbase.com"}),
    "dhl": frozenset({"dhl.com", "dhl.de"}),
    "fedex": frozenset({"fedex.com"}),
    "aramex": frozenset({"aramex.com"}),
    "outlook": frozenset({"outlook.com", "live.com", "office.com"}),
    "dropbox": frozenset({"dropbox.com"}),
    "steam": frozenset({"steampowered.com", "steamcommunity.com"}),
    # Gulf banks, telecoms, government services and delivery firms: the names most
    # often copied in local phishing. Only official domains we are sure of are listed.
    "emiratesnbd": frozenset({"emiratesnbd.com"}),
    "bankfab": frozenset({"bankfab.com"}),
    "mashreq": frozenset({"mashreq.com", "mashreqbank.com"}),
    "rakbank": frozenset({"rakbank.ae"}),
    "alrajhi": frozenset({"alrajhibank.com.sa"}),
    "alahli": frozenset({"alahli.com"}),
    "riyadbank": frozenset({"riyadbank.com"}),
    "alinma": frozenset({"alinma.com"}),
    "bankmuscat": frozenset({"bankmuscat.com"}),
    "etisalat": frozenset({"etisalat.ae", "eand.com"}),
    "mobily": frozenset({"mobily.com.sa"}),
    "ooredoo": frozenset({"ooredoo.qa", "ooredoo.com", "ooredoo.om"}),
    "omantel": frozenset({"omantel.om"}),
    "batelco": frozenset({"batelco.com"}),
    "absher": frozenset({"absher.sa"}),
    "uaepass": frozenset({"uaepass.ae"}),
    "nafath": frozenset({"nafath.sa", "iam.gov.sa"}),
    "dubaipolice": frozenset({"dubaipolice.gov.ae"}),
    "salik": frozenset({"salik.ae"}),
    "emiratespost": frozenset({"emiratespost.ae"}),
    "splonline": frozenset({"splonline.com.sa"}),
    "smsaexpress": frozenset({"smsaexpress.com"}),
    "nusuk": frozenset({"nusuk.sa"}),
    "careem": frozenset({"careem.com"}),
    "talabat": frozenset({"talabat.com"}),
}

# How brands are named in findings, where the lookup key is not the usual name.
BRAND_NAMES: dict[str, str] = {
    "paypal": "PayPal", "linkedin": "LinkedIn", "whatsapp": "WhatsApp", "dhl": "DHL",
    "fedex": "FedEx",
    "emiratesnbd": "Emirates NBD", "bankfab": "First Abu Dhabi Bank", "rakbank": "RAKBANK",
    "alrajhi": "Al Rajhi Bank", "alahli": "Saudi National Bank (AlAhli)", "riyadbank": "Riyad Bank",
    "alinma": "Alinma Bank", "bankmuscat": "Bank Muscat", "etisalat": "e& (Etisalat)",
    "uaepass": "UAE Pass", "dubaipolice": "Dubai Police", "emiratespost": "Emirates Post",
    "splonline": "Saudi Post (SPL)", "smsaexpress": "SMSA Express", "nusuk": "Nusuk",
}  # fmt: skip


def brand_name(brand: str) -> str:
    return BRAND_NAMES.get(brand, brand.title())


# Short brand names turn up inside ordinary words ("dhl" is rare, "apple" is not),
# so near-miss matching is limited to names long enough to be distinctive.
_MIN_TYPOSQUAT_LENGTH = 6

URL_SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
        "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "lnkd.in", "s.id", "v.gd",
    }
)  # fmt: skip

_CREDENTIAL_PATH_WORDS = ("login", "signin", "sign-in", "verify", "account", "secure", "update",
                          "password", "wallet", "confirm", "unlock", "billing")  # fmt: skip
_RISKY_DOWNLOAD_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".msi", ".vbs", ".js", ".jar",
                              ".apk", ".ps1", ".hta", ".lnk", ".iso", ".img")  # fmt: skip
_MAX_ORDINARY_SUBDOMAIN_DEPTH = 3
_LONG_HOST_LENGTH = 60

# Characters from other scripts that render like Latin letters.
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
        "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "α": "a", "ο": "o", "ν": "v",
        "ρ": "p", "τ": "t", "ı": "i", "0": "o", "1": "l",
    }
)  # fmt: skip


def _edit_distance(left: str, right: str) -> int:
    """Optimal string alignment distance: edits plus adjacent transpositions."""
    rows = len(left) + 1
    cols = len(right) + 1
    table = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        table[i][0] = i
    for j in range(cols):
        table[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if left[i - 1] == right[j - 1] else 1
            table[i][j] = min(table[i - 1][j] + 1, table[i][j - 1] + 1, table[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and left[i - 1] == right[j - 2] and left[i - 2] == right[j - 1]:
                table[i][j] = min(table[i][j], table[i - 2][j - 2] + 1)
    return table[rows - 1][cols - 1]


def _unicode_label(label: str) -> str:
    if not label.startswith("xn--"):
        return label
    try:
        return label.encode().decode("idna")
    except UnicodeError:
        return label


def _scripts(text: str) -> set[str]:
    scripts = set()
    for char in text:
        if char.isalpha():
            scripts.add(unicodedata.name(char, "UNKNOWN").split(" ")[0])
    return scripts


def _skeleton(text: str) -> str:
    return text.translate(_CONFUSABLES)


def _homograph_findings(url: ParsedUrl) -> list[FindingData]:
    label = _unicode_label(url.domain_label)
    if label == url.domain_label:
        return []
    skeleton = _skeleton(label)
    evidence = {"displayed_as": label, "actual_domain": url.registrable_domain}
    for brand, domains in BRAND_DOMAINS.items():
        if skeleton == brand and url.registrable_domain not in domains:
            return [
                FindingData(
                    "high",
                    "homograph",
                    f"Domain uses look-alike characters to imitate “{brand}”",
                    "The domain is written with letters from another alphabet that look almost "
                    f"identical to the letters in “{brand}”. This technique is used to make a "
                    "fake site appear to be a well-known one.",
                    SOURCE,
                    {**evidence, "imitates": brand},
                )
            ]
    if len(_scripts(label)) > 1:
        return [
            FindingData(
                "medium",
                "homograph",
                "Domain mixes letters from different alphabets",
                "Mixing alphabets inside one domain name is unusual for legitimate sites and is "
                "a common way to disguise a look-alike address.",
                SOURCE,
                evidence,
            )
        ]
    return []


def _brand_findings(url: ParsedUrl) -> list[FindingData]:
    if url.is_ip_address:
        return []
    label = _skeleton(url.domain_label.replace("-", ""))
    context = _skeleton(f"{url.subdomain}.{url.domain_label}".lower())

    if any(url.registrable_domain in domains for domains in BRAND_DOMAINS.values()):
        return []

    for brand in BRAND_DOMAINS:
        if len(brand) < _MIN_TYPOSQUAT_LENGTH:
            continue
        # Either a near miss ("paypall"), or the brand itself spelled with digits or
        # hyphens ("paypa1", "pay-pal").
        disguised = label == brand and url.domain_label != brand
        if disguised or _edit_distance(label, brand) == 1:
            return [
                FindingData(
                    "high",
                    "typosquatting",
                    f"Domain is a look-alike of “{brand}”",
                    f"“{url.registrable_domain}” is not a domain used by {brand_name(brand)}, "
                    "but it is spelled almost the same. Look-alike domains are a common way "
                    "to collect passwords and payment details.",
                    SOURCE,
                    {"domain": url.registrable_domain, "resembles": brand},
                )
            ]

    for brand in BRAND_DOMAINS:
        if len(brand) >= 5 and brand in context:
            return [
                FindingData(
                    "medium",
                    "brand_impersonation",
                    f"“{brand}” appears in the address, but the site is not {brand_name(brand)}'s",
                    f"The real domain here is “{url.registrable_domain}”. Putting a familiar "
                    "brand name elsewhere in the address is a common way to make a link look "
                    "official.",
                    SOURCE,
                    {"domain": url.registrable_domain, "brand": brand, "host": url.host},
                )
            ]
    return []


def analyze_url_text(url: ParsedUrl) -> list[FindingData]:
    findings: list[FindingData] = []
    findings += _homograph_findings(url)
    findings += _brand_findings(url)

    if url.is_ip_address:
        findings.append(
            FindingData(
                "medium",
                "url_pattern",
                "Link points to a numeric IP address instead of a domain name",
                "Legitimate services almost always use a domain name. Raw IP addresses are "
                "common in phishing and malware links because they are cheap to set up and "
                "hard to recognise.",
                SOURCE,
                {"host": url.host},
            )
        )
    if url.has_credentials:
        findings.append(
            FindingData(
                "medium",
                "url_pattern",
                "Link hides its real destination behind an “@” sign",
                "Everything before the “@” in a web address is ignored by the browser. This "
                f"link really goes to “{url.host}”, whatever the text before it suggests.",
                SOURCE,
                {"actual_host": url.host},
            )
        )
    if url.registrable_domain in URL_SHORTENERS:
        findings.append(
            FindingData(
                "info",
                "shortener",
                "Link uses a URL shortener",
                "Shortened links hide where they lead. That is not harmful in itself, but you "
                "cannot judge the destination from the link text.",
                SOURCE,
                {"service": url.registrable_domain},
            )
        )
    if url.port is not None:
        findings.append(
            FindingData(
                "low",
                "url_pattern",
                f"Link uses an unusual port ({url.port})",
                "Most public websites use the default web ports. A custom port is not proof of "
                "a problem, but it is uncommon for consumer services.",
                SOURCE,
                {"port": url.port},
            )
        )

    depth = len(url.subdomain.split(".")) if url.subdomain else 0
    if depth > _MAX_ORDINARY_SUBDOMAIN_DEPTH or len(url.host) > _LONG_HOST_LENGTH:
        findings.append(
            FindingData(
                "low",
                "url_pattern",
                "Unusually long or deeply nested address",
                "Very long host names can push the real domain out of view, especially on "
                f"phones. The real domain here is “{url.registrable_domain}”.",
                SOURCE,
                {"host": url.host, "subdomain_levels": depth},
            )
        )

    path = url.path.lower()
    if path.endswith(_RISKY_DOWNLOAD_EXTENSIONS):
        findings.append(
            FindingData(
                "low",
                "download",
                "Link downloads a program or script",
                "This link points directly at a file type that can run code on your device. "
                "Only open it if you were expecting it from a source you trust.",
                SOURCE,
                {"path": url.path},
            )
        )
    if url.scheme == "http" and any(word in path for word in _CREDENTIAL_PATH_WORDS):
        findings.append(
            FindingData(
                "low",
                "url_pattern",
                "Sign-in or account page without an encrypted connection",
                "The address suggests a sign-in or account page, but it uses http://. Anything "
                "typed there can be read by others on the network.",
                SOURCE,
                {"path": url.path},
            )
        )
    return findings
