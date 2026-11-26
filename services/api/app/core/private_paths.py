"""Keep privacy-sensitive lookups out of the web server's access log.

Uvicorn logs every request with the client's address and the full path. For the
k-anonymous hash lookup and the email link check, that would pair an address
with what was looked up, so those lines are dropped.
"""

import logging

PRIVATE_PREFIXES = (
    "/api/v1/intelligence/hash-prefix/",
    "/api/v1/email/",
    "/api/v1/relay/",
    # The extension's hash lookups and the explicit "check on the server": the
    # bodies are never logged, and the line saying when an address asked is dropped too.
    "/api/v1/extension/threat-hashes",
    "/api/v1/extension/check-url",
    "/api/v1/extension/check-download",
)


class PrivatePathFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args if isinstance(record.args, tuple) else ()
        path = str(args[2]) if len(args) >= 3 else ""
        return not path.startswith(PRIVATE_PREFIXES)


def install() -> None:
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, PrivatePathFilter) for f in access.filters):
        access.addFilter(PrivatePathFilter())
