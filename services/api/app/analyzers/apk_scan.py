"""Static analysis of Android app packages (APK).

Reads the manifest and the compiled code as data. The app is never installed or
run, so this shows what the app is allowed and built to do, not what it does.
"""

import logging
import re
import zipfile
from pathlib import Path
from typing import Any

from pyaxmlparser import APK
from sqlalchemy.orm import Session

from app.analyzers.file_scan import antivirus_check, hash_reputation_check, sha256_of
from app.analyzers.types import Check, FindingData, Outcome, Severity
from app.analyzers.url_heuristics import brand_name
from app.analyzers.urls import InvalidUrlError, parse_url
from app.analyzers.yara_scan import yara_check
from app.core.config import get_settings
from app.intel import providers
from app.intel.lookup import find_indicators

logger = logging.getLogger(__name__)
SOURCE = "SENTINEL APK analysis"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_MAX_DEX_BYTES = 64 * 1024 * 1024
_MAX_HOSTS = 100
_URL_IN_CODE = re.compile(rb"https?://([A-Za-z0-9.-]{4,253})(?::\d{1,5})?(?:/[\x21-\x7e]*)?")
# Hosts that appear in nearly every app (XML namespaces, Android and W3C schemas).
_BENIGN_HOSTS = frozenset(
    {"schemas.android.com", "www.w3.org", "ns.adobe.com", "xml.org", "www.apache.org",
     "play.google.com", "developer.android.com", "www.google.com", "goo.gl", "localhost"}
)  # fmt: skip

# Plain-language meaning of permissions that matter to users.
SENSITIVE_PERMISSIONS: dict[str, str] = {
    "READ_SMS": "Read your text messages, including one-time codes",
    "RECEIVE_SMS": "Receive text messages as they arrive",
    "SEND_SMS": "Send text messages, which can cost money",
    "READ_CALL_LOG": "Read your call history",
    "READ_CONTACTS": "Read your contacts",
    "RECORD_AUDIO": "Record audio with the microphone",
    "CAMERA": "Take pictures and video",
    "ACCESS_FINE_LOCATION": "Know your precise location",
    "ACCESS_BACKGROUND_LOCATION": "Know your location even when the app is closed",
    "READ_PHONE_STATE": "Read phone status and identifiers",
    "CALL_PHONE": "Make phone calls without you dialling",
    "SYSTEM_ALERT_WINDOW": "Draw over other apps (can fake login screens)",
    "REQUEST_INSTALL_PACKAGES": "Install other apps",
    "QUERY_ALL_PACKAGES": "See every app installed on the device",
    "MANAGE_EXTERNAL_STORAGE": "Read and change all files on the device",
    "READ_EXTERNAL_STORAGE": "Read files and photos on the device",
    "RECEIVE_BOOT_COMPLETED": "Start automatically when the phone starts",
    "PACKAGE_USAGE_STATS": "See which apps you use and when",
    "USE_FULL_SCREEN_INTENT": "Show full-screen notifications over everything",
    "BIND_ACCESSIBILITY_SERVICE": "Read the screen and act on your behalf (accessibility)",
    "BIND_DEVICE_ADMIN": "Become a device administrator (hard to uninstall, can lock the phone)",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "Read all notifications, including codes and messages",
}

# Official package names for brands whose apps are commonly imitated.
OFFICIAL_PACKAGES: dict[str, frozenset[str]] = {
    "whatsapp": frozenset({"com.whatsapp", "com.whatsapp.w4b"}),
    "paypal": frozenset({"com.paypal.android.p2pmobile"}),
    "facebook": frozenset({"com.facebook.katana", "com.facebook.lite"}),
    "instagram": frozenset({"com.instagram.android", "com.instagram.lite"}),
    "netflix": frozenset({"com.netflix.mediaclient"}),
    "telegram": frozenset({"org.telegram.messenger", "org.telegram.messenger.web"}),
    "binance": frozenset({"com.binance.dev"}),
    "chrome": frozenset({"com.android.chrome"}),
    "google play": frozenset({"com.android.vending"}),
}

# Third-party SDKs recognisable by their class paths in compiled code. Listed for
# transparency (who the app talks to); presence is not a finding on its own.
KNOWN_SDKS: dict[bytes, str] = {
    b"Lcom/google/firebase/analytics": "Firebase Analytics",
    b"Lcom/google/android/gms/ads": "Google Mobile Ads",
    b"Lcom/facebook/ads": "Meta Audience Network",
    b"Lcom/facebook/appevents": "Meta App Events",
    b"Lcom/appsflyer": "AppsFlyer",
    b"Lcom/adjust/sdk": "Adjust",
    b"Lcom/unity3d/ads": "Unity Ads",
    b"Lcom/applovin": "AppLovin",
    b"Lcom/ironsource": "ironSource",
    b"Lio/sentry": "Sentry",
    b"Lcom/onesignal": "OneSignal",
}


def _is_apk(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
    except (zipfile.BadZipFile, OSError):
        return False
    return "AndroidManifest.xml" in names


def _android(element: Any, attribute: str) -> str:
    return str(element.get(f"{ANDROID_NS}{attribute}") or "")


def _manifest_facts(apk: APK) -> dict[str, Any]:
    manifest = apk.get_android_manifest_xml()
    target_sdk = int(apk.get_target_sdk_version() or 0)
    components: dict[str, int] = {}
    exported: list[str] = []
    bound: set[str] = set()
    if manifest is not None:
        for kind in ("activity", "service", "receiver", "provider"):
            for element in manifest.iter(kind):
                components[kind] = components.get(kind, 0) + 1
                name = _android(element, "name")
                flag = _android(element, "exported").lower()
                has_filter = element.find("intent-filter") is not None
                # Before Android 12, a component with an intent filter was exported by default.
                if flag == "true" or (flag == "" and has_filter and target_sdk < 31):
                    exported.append(f"{kind}: {name}")
                permission = _android(element, "permission").rsplit(".", 1)[-1]
                if permission.startswith("BIND_"):
                    bound.add(permission)
    permissions = sorted({p.rsplit(".", 1)[-1] for p in apk.get_permissions()} | bound)
    return {
        "package": apk.package,
        "app_name": (apk.application or "")[:100],
        "version": apk.version_name,
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": target_sdk or None,
        "permissions": permissions,
        "components": components,
        "exported_components": exported[:30],
    }


def _permission_findings(facts: dict[str, Any]) -> list[FindingData]:
    granted = set(facts["permissions"])
    findings: list[FindingData] = []

    def add(severity: Severity, title: str, explanation: str, needed: set[str]) -> None:
        findings.append(
            FindingData(
                severity, "permissions", title, explanation, SOURCE, {"permissions": sorted(needed)}
            )
        )

    if "BIND_ACCESSIBILITY_SERVICE" in granted and "SYSTEM_ALERT_WINDOW" in granted:
        add(
            "high",
            "Can read your screen and draw fake screens over other apps",
            "Accessibility access together with drawing over other apps is the signature of "
            "Android banking trojans: they watch which app you open and cover it with a fake "
            "login. Very few legitimate apps need both.",
            {"BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"},
        )
    elif "BIND_ACCESSIBILITY_SERVICE" in granted:
        add(
            "medium",
            "Asks to use accessibility features",
            "Accessibility access lets an app read everything on screen and tap for you. It is "
            "meant for assistive tools and is widely abused by malware.",
            {"BIND_ACCESSIBILITY_SERVICE"},
        )
    sms = granted & {"READ_SMS", "RECEIVE_SMS"}
    if sms and "INTERNET" in granted:
        add(
            "medium",
            "Can read your text messages and send data online",
            "Reading SMS lets an app collect one-time passcodes from your bank. Unless this is "
            "your messaging app, that access is a serious red flag.",
            sms | {"INTERNET"},
        )
    if "BIND_NOTIFICATION_LISTENER_SERVICE" in granted:
        add(
            "medium",
            "Can read all your notifications",
            "Notifications often contain codes, messages and banking alerts.",
            {"BIND_NOTIFICATION_LISTENER_SERVICE"},
        )
    if "BIND_DEVICE_ADMIN" in granted:
        add(
            "medium",
            "Can become a device administrator",
            "Administrator apps are hard to uninstall and can lock or wipe the phone. Malware "
            "uses this to stay installed.",
            {"BIND_DEVICE_ADMIN"},
        )
    if "REQUEST_INSTALL_PACKAGES" in granted:
        add(
            "medium",
            "Can install other apps",
            "Apps that install other apps can deliver additional software after you install "
            "this one. App stores and updaters need it; most apps do not.",
            {"REQUEST_INSTALL_PACKAGES"},
        )
    return findings


def _impersonation_findings(facts: dict[str, Any]) -> list[FindingData]:
    name = str(facts.get("app_name") or "").lower()
    package = str(facts.get("package") or "")
    for brand, packages in OFFICIAL_PACKAGES.items():
        if brand in name and package not in packages:
            return [
                FindingData(
                    "high",
                    "brand_impersonation",
                    f"App is named like {brand_name(brand)} but is not the official app",
                    f"The app calls itself “{facts['app_name']}”, but its package name "
                    f"“{package}” does not belong to {brand_name(brand)}. Fake versions of popular "
                    "apps are a common way to spread Android malware. Install apps only from "
                    "Google Play or the developer's official site.",
                    SOURCE,
                    {"app_name": facts["app_name"], "package": package},
                )
            ]
    return []


def _code_facts(path: Path) -> tuple[set[str], list[str], bool]:
    """Hosts referenced in compiled code, recognised SDKs, and debug signing."""
    hosts: set[str] = set()
    sdks: set[str] = set()
    debug_signed = False
    read = 0
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = info.filename
            if name.startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC")):
                debug_signed |= b"Android Debug" in archive.read(info)[:65536]
            if not (name.startswith("classes") and name.endswith(".dex")):
                continue
            if read + info.file_size > _MAX_DEX_BYTES:
                break
            data = archive.read(info)
            read += len(data)
            for match in _URL_IN_CODE.finditer(data):
                host = match.group(1).decode(errors="ignore").lower().strip(".")
                if "." in host and host not in _BENIGN_HOSTS and len(hosts) < _MAX_HOSTS:
                    hosts.add(host)
            sdks.update(label for marker, label in KNOWN_SDKS.items() if marker in data)
    return hosts, sorted(sdks), debug_signed


def _host_findings(db: Session, hosts: set[str]) -> list[FindingData]:
    findings = []
    for host in sorted(hosts):
        try:
            parsed = parse_url(f"http://{host}/")
        except InvalidUrlError:
            continue
        for match in find_indicators(db, "host", parsed.host):
            findings.append(
                FindingData(
                    "high",
                    "threat_intelligence",
                    f"App contains an address listed by {match.source_name}",
                    f"The app's code refers to “{parsed.host}”, which threat intelligence lists "
                    "as a malware host. Apps rarely have a legitimate reason to contact one.",
                    match.source_name,
                    match.evidence(),
                )
            )
    return findings


def _mobsf_check(path: Path, outcome: Outcome) -> None:
    label, provider = "Deep static analysis", "MobSF"
    try:
        report = providers.mobsf_scan(path)
    except providers.ProviderUnavailableError as exc:
        outcome.checks.append(Check("mobsf", label, provider, "unavailable", f"{exc}."))
        return
    outcome.details["mobsf"] = report
    if report.get("high", 0):
        outcome.findings.append(
            FindingData(
                "medium",
                "mobsf",
                f"MobSF reported {report['high']} high-severity issue(s)",
                "MobSF's static analysis found code or configuration it rates as high risk. "
                "Its full report is available to the operator of this server.",
                provider,
                {k: v for k, v in report.items() if v is not None},
            )
        )
    outcome.checks.append(
        Check(
            "mobsf",
            label,
            provider,
            "completed",
            f"Security score {report.get('security_score', 'not given')}.",
        )
    )


def analyze_apk(payload: dict[str, Any], db: Session) -> Outcome:
    path = get_settings().upload_dir / payload["storage_name"]
    sha256 = sha256_of(path)
    outcome = Outcome(
        details={
            "file_name": payload["file_name"],
            "size_bytes": path.stat().st_size,
            "sha256": sha256,
        }
    )

    if not _is_apk(path):
        outcome.checks.append(
            Check(
                "apk_manifest",
                "App manifest",
                SOURCE,
                "failed",
                "This is not an Android app package (APK).",
            )
        )
        outcome.limitations.append("Use the file scanner for files that are not Android apps.")
        return outcome

    try:
        facts = _manifest_facts(APK(str(path)))
    except Exception:  # noqa: BLE001 - malformed manifests raise many error types
        logger.info("Manifest of %s could not be parsed", payload["file_name"])
        outcome.checks.append(
            Check(
                "apk_manifest", "App manifest", SOURCE, "failed", "The manifest could not be read."
            )
        )
        facts = None

    if facts is not None:
        outcome.details["app"] = facts
        outcome.details["sensitive_permissions"] = {
            name: SENSITIVE_PERMISSIONS[name]
            for name in facts["permissions"]
            if name in SENSITIVE_PERMISSIONS
        }
        outcome.findings += _permission_findings(facts) + _impersonation_findings(facts)
        outcome.checks.append(
            Check(
                "apk_manifest",
                "Permissions and components",
                SOURCE,
                "completed",
                f"Read the manifest: {len(facts['permissions'])} permissions, "
                f"{sum(facts['components'].values())} components.",
            )
        )

    hosts, sdks, debug_signed = _code_facts(path)
    outcome.details["embedded_hosts"] = sorted(hosts)[:50]
    outcome.details["sdks"] = sdks
    outcome.findings += _host_findings(db, hosts)
    if debug_signed:
        outcome.findings.append(
            FindingData(
                "medium",
                "signing",
                "Signed with a developer test certificate",
                "Apps published in stores are signed with the developer's own release key. A debug "
                "certificate means this is a test build, or was repackaged by someone else.",
                SOURCE,
            )
        )
    outcome.checks.append(
        Check(
            "apk_code",
            "Embedded addresses and SDKs",
            SOURCE,
            "completed",
            f"Found {len(hosts)} web address host(s) and {len(sdks)} known SDK(s) in the code.",
        )
    )

    yara_check(path, outcome)
    hash_reputation_check(db, sha256, outcome)
    antivirus_check(path, outcome)
    _mobsf_check(path, outcome)
    outcome.limitations.append(
        "This is static analysis: the app was not installed or run, so behaviour that only "
        "appears at runtime (for example code downloaded later) cannot be seen."
    )
    return outcome
