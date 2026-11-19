from pydantic import BaseModel, Field

MAX_EMAIL_TEXT = 20_000


class EmailLink(BaseModel):
    href: str = Field(max_length=2048)
    text: str = Field(default="", max_length=300)


class EmailCheckRequest(BaseModel):
    """The parts of one email that matter for a check. The text should be the
    plain-text body (or the HTML with tags removed); attachments are not sent."""

    from_header: str = Field(max_length=500)
    reply_to: str | None = Field(default=None, max_length=500)
    subject: str = Field(default="", max_length=1000)
    authentication_results: str = Field(default="", max_length=4000)
    text: str = Field(default="", max_length=MAX_EMAIL_TEXT)
    links: list[EmailLink] = Field(default_factory=list, max_length=200)


class EmailFinding(BaseModel):
    severity: str
    title: str
    explanation: str


class EmailCheckOut(BaseModel):
    risk: str
    confidence: str
    summary: str
    recommendations: list[str]
    findings: list[EmailFinding]
    limitations: list[str]
