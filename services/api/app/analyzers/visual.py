"""Visual comparison of a rendered page with known sign-in pages.

Phishing kits copy the look of a brand's sign-in page exactly, even when the
text and code are changed to dodge filters. Each rendered page is reduced to a
64-bit difference hash (dHash) of its first screen and compared with reference
hashes of real sign-in pages. A close match on a domain that is not the brand's
is a strong sign of a copy.

References are hashes only (no images), stored in a JSON file. Operators add
them with:  python -m app.cli add-brand-reference <brand> <domain,...> <url>
which renders the real page through the same isolated browser.
"""

import io
import json
from dataclasses import dataclass
from pathlib import Path

from PIL import Image

from app.core.config import get_settings

HASH_SIZE = 8
# Out of 64 bits. Below this, two screens are near-identical in layout and colour.
MATCH_DISTANCE = 6


@dataclass(frozen=True)
class Reference:
    brand: str
    domains: frozenset[str]
    dhash: int
    source_url: str


def dhash(png: bytes) -> int:
    """Difference hash: compares neighbouring pixels of a small greyscale image."""
    with Image.open(io.BytesIO(png)) as image:
        if image.width * image.height > 40_000_000:
            raise OSError("Screenshot too large")
        image.draft("L", (HASH_SIZE * 32, HASH_SIZE * 32))
        small = image.convert("L").resize((HASH_SIZE + 1, HASH_SIZE), Image.Resampling.LANCZOS)
        pixels = list(small.tobytes())
    value = 0
    for row in range(HASH_SIZE):
        for col in range(HASH_SIZE):
            left = pixels[row * (HASH_SIZE + 1) + col]
            right = pixels[row * (HASH_SIZE + 1) + col + 1]
            value = (value << 1) | (1 if left > right else 0)
    return value


def distance(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def reference_file() -> Path:
    configured = get_settings().brand_reference_file
    return configured or Path(__file__).resolve().parent.parent / "rules" / "brand_references.json"


def load_references(path: Path | None = None) -> list[Reference]:
    try:
        raw = json.loads((path or reference_file()).read_text())
    except (OSError, ValueError):
        return []
    return [
        Reference(
            item["brand"],
            frozenset(item["domains"]),
            int(item["dhash"], 16),
            item.get("source_url", ""),
        )
        for item in raw
        if isinstance(item, dict) and {"brand", "domains", "dhash"} <= item.keys()
    ]


def save_reference(reference: Reference, path: Path | None = None) -> None:
    target = path or reference_file()
    items = [
        r
        for r in load_references(target)
        if not (r.brand == reference.brand and r.source_url == reference.source_url)
    ]
    items.append(reference)
    target.write_text(
        json.dumps(
            [
                {
                    "brand": r.brand,
                    "domains": sorted(r.domains),
                    "dhash": f"{r.dhash:016x}",
                    "source_url": r.source_url,
                }
                for r in items
            ],
            indent=2,
        )
    )


def closest_match(
    page_hash: int, registrable_domain: str, references: list[Reference]
) -> tuple[Reference, int] | None:
    """The most similar reference whose brand does not own this domain."""
    best: tuple[Reference, int] | None = None
    for reference in references:
        if registrable_domain in reference.domains:
            continue
        gap = distance(page_hash, reference.dhash)
        if gap <= MATCH_DISTANCE and (best is None or gap < best[1]):
            best = (reference, gap)
    return best
