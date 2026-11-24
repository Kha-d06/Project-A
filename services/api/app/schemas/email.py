from pydantic import BaseModel, Field

MAX_LINKS = 50


class LinkCheckRequest(BaseModel):
    """Bare links found in one email. Clients strip query strings and fragments
    first; the server strips them again in case one did not."""

    urls: list[str] = Field(max_length=MAX_LINKS)


class LinkFinding(BaseModel):
    severity: str
    title: str
    explanation: str


class LinkResult(BaseModel):
    url: str
    host: str
    findings: list[LinkFinding]


class LinkCheckOut(BaseModel):
    results: list[LinkResult]
    feed_available: bool


class RuleOut(BaseModel):
    category: str
    severity: str
    title: str
    explanation: str
    title_ar: str
    explanation_ar: str
    patterns: list[str]


class BrandOut(BaseModel):
    name: str
    domains: list[str]


class RulePack(BaseModel):
    """Everything a client needs to check an email on the device itself."""

    version: str
    rules: list[RuleOut]
    brands: dict[str, BrandOut]
    shorteners: list[str]
