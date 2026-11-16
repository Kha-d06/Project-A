"""Adapters for external services queried during a scan.

Each adapter either returns real data or raises ProviderUnavailableError with a
reason that is shown to the user. Nothing here ever substitutes a made-up answer.
"""

import socket
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from app.core.config import get_settings

_TIMEOUT_SECONDS = 8
_CLAMAV_CHUNK_BYTES = 64 * 1024
_CLAMAV_TIMEOUT_SECONDS = 60


class ProviderUnavailableError(Exception):
    pass


# --- URLhaus live lookup ------------------------------------------------------------


@dataclass(frozen=True)
class UrlhausResult:
    listed: bool
    threat: str | None = None
    status: str | None = None
    date_added: str | None = None
    reference: str | None = None
    tags: tuple[str, ...] = ()


def urlhaus_lookup(url: str) -> UrlhausResult:
    auth_key = get_settings().urlhaus_auth_key
    if not auth_key:
        raise ProviderUnavailableError(
            "Live URLhaus lookups need a free abuse.ch Auth-Key, which is not configured"
        )
    try:
        response = httpx.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": auth_key},
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        body: dict[str, Any] = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ProviderUnavailableError(f"URLhaus did not answer ({type(exc).__name__})") from exc

    status = body.get("query_status")
    if status == "no_results":
        return UrlhausResult(listed=False)
    if status != "ok":
        raise ProviderUnavailableError(f"URLhaus rejected the lookup ({status})")
    return UrlhausResult(
        listed=True,
        threat=body.get("threat"),
        status=body.get("url_status"),
        date_added=body.get("date_added"),
        reference=body.get("urlhaus_reference"),
        tags=tuple(body.get("tags") or ()),
    )


# --- Domain registration date (RDAP) ------------------------------------------------


def domain_registration_date(domain: str) -> datetime:
    """Registration date from the registry's RDAP service, via the rdap.org redirector."""
    try:
        response = httpx.get(
            f"{get_settings().rdap_base_url}/domain/{domain}",
            timeout=_TIMEOUT_SECONDS,
            follow_redirects=True,
            headers={"Accept": "application/rdap+json"},
        )
    except httpx.HTTPError as exc:
        raise ProviderUnavailableError(
            f"The registry lookup did not answer ({type(exc).__name__})"
        ) from exc
    if response.status_code == httpx.codes.NOT_FOUND:
        raise ProviderUnavailableError("The registry for this domain does not publish RDAP records")
    try:
        response.raise_for_status()
        events = response.json().get("events", [])
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        raise ProviderUnavailableError("The registry returned an unreadable answer") from exc

    for event in events:
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            try:
                return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                break
    raise ProviderUnavailableError("The registry record does not include a registration date")


# --- ClamAV -------------------------------------------------------------------------


@dataclass(frozen=True)
class ClamavResult:
    infected: bool
    signature: str | None = None


def clamav_scan(path: Path) -> ClamavResult:
    """Stream a file to clamd (INSTREAM). The file is never executed or written elsewhere."""
    settings = get_settings()
    if not settings.clamav_host:
        raise ProviderUnavailableError("No ClamAV service is configured")
    try:
        with socket.create_connection(
            (settings.clamav_host, settings.clamav_port), timeout=_CLAMAV_TIMEOUT_SECONDS
        ) as connection:
            connection.sendall(b"zINSTREAM\0")
            with path.open("rb") as sample:
                while chunk := sample.read(_CLAMAV_CHUNK_BYTES):
                    connection.sendall(struct.pack("!I", len(chunk)) + chunk)
            connection.sendall(struct.pack("!I", 0))
            reply = b""
            while not reply.endswith(b"\0"):
                received = connection.recv(4096)
                if not received:
                    break
                reply += received
    except OSError as exc:
        raise ProviderUnavailableError(f"ClamAV is not reachable ({type(exc).__name__})") from exc

    text = reply.rstrip(b"\0").decode(errors="replace").strip()
    if text.endswith("OK"):
        return ClamavResult(infected=False)
    if text.endswith("FOUND"):
        return ClamavResult(infected=True, signature=text.removeprefix("stream:").strip()[:-6])
    raise ProviderUnavailableError(f"ClamAV could not scan the file ({text[:120]})")


# --- MobSF --------------------------------------------------------------------------

_MOBSF_TIMEOUT_SECONDS = 120


def mobsf_scan(path: Path) -> dict[str, Any]:
    """Upload an APK to a self-hosted MobSF instance and return its scorecard summary.

    MobSF runs inside the operator's own infrastructure; the sample is not shared
    with any third party.
    """
    settings = get_settings()
    if not settings.mobsf_url or not settings.mobsf_api_key:
        raise ProviderUnavailableError("No MobSF server is configured")
    headers = {"Authorization": settings.mobsf_api_key}
    base = settings.mobsf_url.rstrip("/")
    try:
        with httpx.Client(timeout=_MOBSF_TIMEOUT_SECONDS, headers=headers) as client:
            with path.open("rb") as sample:
                upload = client.post(
                    f"{base}/api/v1/upload",
                    files={"file": (f"{path.name}.apk", sample, "application/octet-stream")},
                )
            upload.raise_for_status()
            scan_hash = upload.json()["hash"]
            client.post(f"{base}/api/v1/scan", data={"hash": scan_hash}).raise_for_status()
            scorecard = client.post(f"{base}/api/v1/scorecard", data={"hash": scan_hash})
            scorecard.raise_for_status()
            body: dict[str, Any] = scorecard.json()
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        raise ProviderUnavailableError(
            f"MobSF did not complete the analysis ({type(exc).__name__})"
        ) from exc
    return {
        "security_score": body.get("security_score"),
        "high": len(body.get("high", []) or []),
        "warning": len(body.get("warning", []) or []),
        "trackers": body.get("trackers"),
    }


# --- Google Web Risk ----------------------------------------------------------------

_WEB_RISK_THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]


def web_risk_lookup(url: str) -> list[str]:
    """Threat types Google Web Risk lists for this exact URL (empty if none)."""
    key = get_settings().web_risk_api_key
    if not key:
        raise ProviderUnavailableError("Google Web Risk needs an API key, which is not configured")
    try:
        response = httpx.get(
            "https://webrisk.googleapis.com/v1/uris:search",
            params={"uri": url, "key": key, "threatTypes": _WEB_RISK_THREATS},
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        body: dict[str, Any] = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ProviderUnavailableError(
            f"Google Web Risk did not answer ({type(exc).__name__})"
        ) from exc
    return list((body.get("threat") or {}).get("threatTypes") or [])


# --- Certificate transparency (crt.sh) ----------------------------------------------


def first_certificate_seen(domain: str) -> datetime | None:
    """Earliest issuance date of any publicly logged certificate for the domain."""
    try:
        response = httpx.get(
            f"{get_settings().crtsh_base_url}/",
            params={"q": domain, "output": "json"},
            timeout=15,
        )
        response.raise_for_status()
        entries = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ProviderUnavailableError(f"crt.sh did not answer ({type(exc).__name__})") from exc
    dates = []
    for entry in entries[:5000] if isinstance(entries, list) else []:
        try:
            dates.append(datetime.fromisoformat(str(entry["not_before"])).replace(tzinfo=UTC))
        except (KeyError, ValueError):
            continue
    return min(dates) if dates else None


# --- VirusTotal (hash lookups only, with the user's consent) ------------------------


@dataclass(frozen=True)
class VirusTotalResult:
    known: bool
    malicious: int = 0
    suspicious: int = 0
    engines: int = 0
    label: str | None = None


def virustotal_hash(sha256: str) -> VirusTotalResult:
    """Looks up a fingerprint only. The file itself is never uploaded."""
    key = get_settings().virustotal_api_key
    if not key:
        raise ProviderUnavailableError("VirusTotal needs an API key, which is not configured")
    try:
        response = httpx.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": key},
            timeout=_TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as exc:
        raise ProviderUnavailableError(f"VirusTotal did not answer ({type(exc).__name__})") from exc
    if response.status_code == httpx.codes.NOT_FOUND:
        return VirusTotalResult(known=False)
    if response.status_code == httpx.codes.TOO_MANY_REQUESTS:
        raise ProviderUnavailableError("The VirusTotal quota for this server is used up")
    try:
        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        raise ProviderUnavailableError("VirusTotal returned an unreadable answer") from exc
    stats = attributes.get("last_analysis_stats") or {}
    return VirusTotalResult(
        known=True,
        malicious=int(stats.get("malicious", 0)),
        suspicious=int(stats.get("suspicious", 0)),
        engines=sum(int(v) for v in stats.values() if isinstance(v, int)),
        label=(attributes.get("popular_threat_classification") or {}).get("suggested_threat_label"),
    )
