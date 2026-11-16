"""Static inspection of a fetched HTML page.

The page is parsed with the standard-library HTML tokenizer only: nothing is
rendered, no script runs, and no linked resource is requested.
"""

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

_MAX_TAGS = 50_000
_INLINE_SCRIPT_LIMIT = 200_000
_CARD_FIELD = re.compile(r"card|cc-?num|cvv|cvc|expir|iban|security.?code", re.I)
_CREDENTIAL_FIELD = re.compile(r"pass|pin|otp|login|user", re.I)

OBFUSCATION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "decodes and runs hidden code",
        re.compile(r"eval\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(", re.I),
    ),
    (
        "writes decoded markup into the page",
        re.compile(r"document\.write\s*\(\s*(unescape|atob)\s*\(", re.I),
    ),
    ("builds code from character codes", re.compile(r"String\.fromCharCode\s*\((\s*\d+\s*,){40,}")),
    (
        "contains a cryptocurrency miner",
        re.compile(r"coinhive|cryptonight|coin-hive|webminepool", re.I),
    ),
)


@dataclass
class Form:
    action: str
    method: str
    has_password: bool = False
    has_card_fields: bool = False
    field_names: list[str] = field(default_factory=list)


@dataclass
class PageFacts:
    title: str = ""
    description: str = ""
    generator: str = ""
    meta_refresh: str | None = None
    forms: list[Form] = field(default_factory=list)
    script_sources: list[str] = field(default_factory=list)
    hidden_iframes: list[str] = field(default_factory=list)
    resource_hosts: set[str] = field(default_factory=set)
    obfuscation: list[str] = field(default_factory=list)
    headings: list[str] = field(default_factory=list)


class _Parser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.facts = PageFacts()
        self._form: Form | None = None
        self._capture: str | None = None
        self.script_text: list[str] = []
        self._tags = 0

    def _absolute(self, value: str | None) -> str:
        return urljoin(self.base_url, value or "")

    def _note_resource(self, value: str | None) -> None:
        if value:
            host = urlsplit(self._absolute(value)).hostname
            if host:
                self.facts.resource_hosts.add(host.lower())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._tags += 1
        if self._tags > _MAX_TAGS:
            return
        a = {name.lower(): (value or "") for name, value in attrs}
        if tag == "title":
            self._capture = "title"
        elif tag in ("h1", "h2"):
            self._capture = "heading"
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name in ("description", "og:description"):
                self.facts.description = a.get("content", "")[:300]
            elif name == "generator":
                self.facts.generator = a.get("content", "")[:100]
            elif a.get("http-equiv", "").lower() == "refresh":
                self.facts.meta_refresh = a.get("content", "")[:300]
        elif tag == "form":
            self._form = Form(
                action=self._absolute(a.get("action")), method=(a.get("method") or "get").lower()
            )
            self.facts.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            kind = a.get("type", "text").lower()
            label = " ".join(
                filter(
                    None, (a.get("name"), a.get("id"), a.get("autocomplete"), a.get("placeholder"))
                )
            )
            if kind == "password":
                self._form.has_password = True
            if _CARD_FIELD.search(label):
                self._form.has_card_fields = True
            if label and len(self._form.field_names) < 20:
                self._form.field_names.append(label[:60])
        elif tag == "script":
            if a.get("src"):
                src = self._absolute(a["src"])
                self.facts.script_sources.append(src[:300])
                self._note_resource(src)
            else:
                self._capture = "script"
        elif tag == "iframe":
            style = a.get("style", "").replace(" ", "").lower()
            tiny = a.get("width") in ("0", "1") or a.get("height") in ("0", "1")
            if tiny or "display:none" in style or "visibility:hidden" in style or "hidden" in a:
                self.facts.hidden_iframes.append(self._absolute(a.get("src"))[:300])
            self._note_resource(a.get("src"))
        elif tag in ("img", "link"):
            self._note_resource(a.get("src") or a.get("href"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        if tag in ("title", "h1", "h2", "script"):
            self._capture = None

    def handle_data(self, data: str) -> None:
        if self._capture == "title" and len(self.facts.title) < 300:
            self.facts.title += data
        elif self._capture == "heading" and len(self.facts.headings) < 10:
            text = " ".join(data.split())
            if text:
                self.facts.headings.append(text[:120])
        elif self._capture == "script" and sum(map(len, self.script_text)) < _INLINE_SCRIPT_LIMIT:
            self.script_text.append(data)


def inspect_html(body: bytes, base_url: str, charset: str | None = None) -> PageFacts:
    text = body.decode(charset or "utf-8", errors="replace")
    parser = _Parser(base_url)
    try:
        parser.feed(text)
        parser.close()
    except (AssertionError, ValueError):
        # Malformed markup: keep whatever was gathered before the parser gave up.
        pass
    facts = parser.facts
    facts.title = " ".join(facts.title.split())[:200]
    scripts = "".join(parser.script_text)
    facts.obfuscation = [
        label for label, pattern in OBFUSCATION_PATTERNS if pattern.search(scripts)
    ]
    return facts


def charset_of(content_type: str) -> str | None:
    match = re.search(r"charset=([\w-]+)", content_type, re.I)
    if not match:
        return None
    try:
        "".encode(match.group(1))
    except LookupError:
        return None
    return match.group(1)
