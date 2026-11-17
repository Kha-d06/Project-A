"""QR code analysis: decode an uploaded image, then check what the code contains.

Decoded links are never opened in a browser. They are checked from the server by
the link scanner, which follows redirects behind the SSRF protections.
"""

import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import zxingcpp
from PIL import Image, UnidentifiedImageError
from sqlalchemy.orm import Session

from app.analyzers.types import Check, FindingData, Outcome
from app.analyzers.url_scan import analyze_url_target
from app.analyzers.urls import InvalidUrlError, parse_url
from app.core.config import get_settings

SOURCE = "SENTINEL QR analysis"
DECODER = "zxing-cpp"
# Decompression bombs: refuse images whose pixel count would exhaust memory.
MAX_PIXELS = 40_000_000
_MAX_TEXT = 2000
_CRYPTO_SCHEMES = ("bitcoin", "ethereum", "litecoin", "monero", "tron", "solana", "dogecoin")


def decode_image(path: Path) -> list[str]:
    # Checked from the header before any pixels are decoded. Pillow's own global
    # limit is left alone so one analyzer's setting cannot affect another's.
    with Image.open(path) as image:
        if image.width * image.height > MAX_PIXELS:
            raise Image.DecompressionBombError(
                f"Image size ({image.width * image.height} pixels) exceeds the limit"
            )
        image.load()
        return [result.text for result in zxingcpp.read_barcodes(image) if result.text]


def _emv_fields(payload: str) -> dict[str, str]:
    """Parse EMVCo merchant-presented QR data (ID, length, value triplets)."""
    fields: dict[str, str] = {}
    position = 0
    while position + 4 <= len(payload):
        tag, length = payload[position : position + 2], payload[position + 2 : position + 4]
        if not length.isdigit():
            break
        value = payload[position + 4 : position + 4 + int(length)]
        fields[tag] = value
        position += 4 + int(length)
    return fields


def classify(content: str) -> tuple[str, dict[str, Any]]:
    """Return (kind, details) for decoded QR content."""
    text = content.strip()
    lower = text.lower()
    scheme = lower.split(":", 1)[0] if ":" in lower[:20] else ""

    if scheme in ("http", "https") or re.match(r"^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(/|$)", lower):
        return "url", {"url": text}
    if scheme == "upi":
        query = parse_qs(urlsplit(text).query)
        return "upi_payment", {
            "payee_address": query.get("pa", [""])[0],
            "payee_name": query.get("pn", [""])[0],
            "amount": query.get("am", [""])[0],
            "currency": query.get("cu", [""])[0],
        }
    if scheme in _CRYPTO_SCHEMES:
        parts = urlsplit(text)
        address = (parts.path or parts.netloc).split("?")[0]
        return "crypto_payment", {
            "network": scheme,
            "address": address,
            "amount": parse_qs(parts.query).get("amount", [""])[0],
        }
    if text.startswith("000201"):
        fields = _emv_fields(text)
        return "merchant_payment", {
            "merchant_name": fields.get("59", ""),
            "merchant_city": fields.get("60", ""),
            "amount": fields.get("54", ""),
            "currency_code": fields.get("53", ""),
        }
    if lower.startswith("wifi:"):
        security = re.search(r"T:([^;]*)", text)
        name = re.search(r"S:([^;]*)", text)
        return "wifi", {
            "network_name": name.group(1) if name else "",
            "security": (security.group(1) if security else "") or "none",
        }
    if scheme in ("tel", "sms", "smsto", "mailto"):
        return "contact_action", {"action": scheme, "target": text.split(":", 1)[1][:200]}
    if lower.startswith("begin:vcard"):
        return "contact_card", {}
    return "text", {}


def _payment_findings(kind: str, details: dict[str, Any]) -> list[FindingData]:
    if kind == "crypto_payment":
        return [
            FindingData(
                "medium",
                "payment",
                f"QR code asks for a {details['network']} payment",
                "Cryptocurrency payments cannot be reversed and the recipient cannot be "
                "identified. QR codes for crypto payments are a common feature of investment, "
                "giveaway and fake-invoice scams.",
                SOURCE,
                {"address": details["address"], "amount": details["amount"] or None},
            )
        ]
    if kind in ("upi_payment", "merchant_payment"):
        payee = details.get("payee_name") or details.get("merchant_name") or "an unnamed payee"
        return [
            FindingData(
                "low",
                "payment",
                f"QR code starts a payment to {payee}",
                "Scanning it opens a payment request. Check that the name and amount match what "
                "you expect before approving; fraudsters stick their own codes over genuine ones. "
                "Receiving money never requires scanning a code or entering your PIN.",
                SOURCE,
                {k: v for k, v in details.items() if v},
            )
        ]
    return []


def analyze_qr(payload: dict[str, Any], db: Session) -> Outcome:
    path = get_settings().upload_dir / payload["storage_name"]
    try:
        contents = decode_image(path)
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError) as exc:
        outcome = Outcome()
        message = (
            "The image is too large to process safely."
            if isinstance(exc, Image.DecompressionBombError)
            else "The file is not an image that can be read."
        )
        outcome.checks.append(Check("qr_decode", "Read the QR code", DECODER, "failed", message))
        outcome.limitations.append(message)
        return outcome

    if not contents:
        outcome = Outcome()
        outcome.checks.append(
            Check(
                "qr_decode",
                "Read the QR code",
                DECODER,
                "failed",
                "No QR code could be read. Try a sharper, well-lit photo showing the whole code.",
            )
        )
        outcome.limitations.append("No QR code was found in the image, so nothing was checked.")
        return outcome

    content = contents[0][:_MAX_TEXT]
    kind, kind_details = classify(content)
    decode_check = Check(
        "qr_decode",
        "Read the QR code",
        DECODER,
        "completed",
        "Decoded the code."
        + (
            f" The image contains {len(contents)} codes; the first was checked."
            if len(contents) > 1
            else ""
        ),
        # For links, the link checks decide the verdict; for anything else, reading
        # the content is the check.
        core=kind != "url",
    )

    if kind == "url":
        try:
            url = parse_url(content if "://" in content else f"http://{content}")
        except InvalidUrlError:
            kind = "text"
        else:
            outcome, final, _ = analyze_url_target(url, db)
            outcome.checks.insert(0, decode_check)
            outcome.details.update({"qr_content": content, "qr_kind": "url"})
            outcome.findings.append(
                FindingData(
                    "info",
                    "qr_destination",
                    f"QR code opens {final.host}",
                    "SENTINEL checked this address from its own server. It was not opened on your "
                    "device.",
                    SOURCE,
                    {"link": url.normalized},
                )
            )
            outcome.limitations.append(
                "The linked page's content was not inspected. Use the website analyzer for that."
            )
            return outcome

    outcome = Outcome(details={"qr_content": content, "qr_kind": kind, **kind_details})
    outcome.checks.append(decode_check)
    outcome.findings += _payment_findings(kind, kind_details)
    if kind == "wifi" and kind_details.get("security", "").lower() in ("", "none", "nopass"):
        outcome.findings.append(
            FindingData(
                "low",
                "wifi",
                "QR code joins an open Wi-Fi network",
                "Anyone nearby can see unencrypted traffic on an open network. Avoid signing in "
                "or paying while connected to it.",
                SOURCE,
                {"network_name": kind_details.get("network_name")},
            )
        )
    outcome.limitations.append(
        "The QR code's content was checked; who created or placed the code cannot be verified."
    )
    return outcome
