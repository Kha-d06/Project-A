"""Turns raw findings into the four-way risk classification used across SENTINEL.

The rules are deliberately simple so that every verdict can be explained:

* a finding confirmed by threat intelligence or a signature  -> known_malicious
* any medium or high severity indicator                      -> suspicious
* nothing found, and at least one core check completed       -> no_known_threat
* nothing found, but no core check could run                 -> inconclusive
"""

from dataclasses import dataclass

from app.analyzers.types import Outcome

_SUBJECT = {
    "url": "link",
    "message": "message",
    "file": "file",
    "qr": "QR code",
    "website": "website",
    "apk": "app",
}


@dataclass(frozen=True)
class Assessment:
    status: str
    risk: str
    confidence: str
    summary: str
    recommendations: list[str]


_RECOMMENDATIONS: dict[tuple[str, str], list[str]] = {
    ("url", "known_malicious"): [
        "Do not open this link, and do not run anything that was downloaded from it.",
        "If you already entered a password there, change it now wherever you use it and turn "
        "on two-step verification.",
        "If you downloaded a file from it, delete the file and run a full antivirus scan.",
        "Tell the person or service the link appeared to come from, using contact details you "
        "already trust.",
    ],
    ("url", "suspicious"): [
        "Avoid opening this link. Go to the service by typing its address yourself or using "
        "its official app.",
        "Do not enter passwords, card numbers or verification codes on the page it leads to.",
        "If someone you know sent it, ask them through another channel whether they meant to.",
    ],
    ("url", "no_known_threat"): [
        "No known threat was found, which is not a guarantee. New malicious sites take time "
        "to appear in threat feeds.",
        "Before signing in or paying, check that the domain in the address bar is the one you "
        "expect.",
    ],
    ("url", "inconclusive"): [
        "Treat this link as unverified: a key check could not be completed.",
        "Try the scan again later, or reach the service through an address you already trust.",
    ],
    ("message", "known_malicious"): [
        "Do not open the links or reply. Delete the message or report it as spam or phishing.",
        "If you already followed a link and entered details, change that password and contact "
        "your bank if payment information was involved.",
        "Block the sender.",
    ],
    ("message", "suspicious"): [
        "Do not reply, open links or send codes, money or personal details.",
        "If it claims to be from a company, contact that company through its official website "
        "or app, not the details in the message.",
        "Report the message as spam or phishing in your messaging or email app, then block the "
        "sender.",
    ],
    ("message", "no_known_threat"): [
        "No common scam wording was found, which is not a guarantee that the message is genuine.",
        "Be careful with any request for money, codes or personal details, however ordinary "
        "the message looks.",
    ],
    ("message", "inconclusive"): [
        "The analysis could not be completed. Treat the message with the same care as any "
        "unexpected request.",
    ],
    ("file", "known_malicious"): [
        "Do not open the file. Delete it, and empty the recycle bin or trash.",
        "If you already opened it, disconnect the device from the network and run a full "
        "antivirus scan.",
        "Change passwords for important accounts from a different device.",
        "Warn whoever sent it; their account may be compromised.",
    ],
    ("file", "suspicious"): [
        "Do not open or run the file unless you can confirm with the sender what it is.",
        "Never click “Enable content” or “Enable macros” in a document you were not expecting.",
        "If you need the contents, ask the sender for a plain PDF or a link to an official source.",
    ],
    ("file", "no_known_threat"): [
        "No known threat was found, which is not a guarantee. New malware is often not "
        "recognised for days.",
        "Keep your device's own antivirus protection on; this scan does not replace it.",
    ],
    ("file", "inconclusive"): [
        "No malware database was available to check this file against, so it remains unverified.",
        "Scan it with the antivirus software on your device before opening it.",
    ],
    ("qr", "known_malicious"): [
        "Do not open the link in this QR code or follow its instructions.",
        "If it was on a poster, parking meter or delivery note, tell the business or venue: "
        "fraudsters often stick their own codes over genuine ones.",
        "If you already entered details or paid, contact your bank and change the password "
        "you used.",
    ],
    ("qr", "suspicious"): [
        "Do not pay or sign in through this code. Go to the business's official website or app "
        "instead.",
        "Check whether the code is a sticker placed over another one.",
    ],
    ("qr", "no_known_threat"): [
        "No known threat was found, which is not a guarantee. Check the address shown on your "
        "phone before entering any details.",
        "For payments, confirm the payee name and amount before approving.",
    ],
    ("qr", "inconclusive"): [
        "The code could not be fully checked. Do not pay or sign in through it unless you can "
        "confirm where it leads by other means.",
    ],
    ("website", "known_malicious"): [
        "Do not visit this site, and do not run anything downloaded from it.",
        "If you entered a password there, change it everywhere you use it and turn on two-step "
        "verification.",
    ],
    ("website", "suspicious"): [
        "Do not enter passwords, card numbers or personal details on this site.",
        "Reach the organisation through an address you already know, or its official app.",
    ],
    ("website", "no_known_threat"): [
        "No known threat was found, which is not a guarantee. Check the address bar before "
        "signing in or paying.",
    ],
    ("website", "inconclusive"): [
        "Key checks could not run, so treat the site as unverified and avoid entering personal "
        "details.",
    ],
    ("apk", "known_malicious"): [
        "Do not install this app. Delete the file.",
        "If it is already installed, uninstall it, run Google Play Protect, and change the "
        "passwords of accounts you used on the phone from another device.",
    ],
    ("apk", "suspicious"): [
        "Do not install this app unless you can confirm it comes from the real developer.",
        "Install apps from Google Play or the developer's official site, never from links in "
        "messages.",
        "Be very cautious about granting accessibility, SMS or device-administrator access.",
    ],
    ("apk", "no_known_threat"): [
        "No known threat was found, which is not a guarantee. Prefer installing apps from "
        "Google Play.",
        "Review the permissions listed below and refuse any the app does not obviously need.",
    ],
    ("apk", "inconclusive"): [
        "No malware database was available to check this app, so it remains unverified. Do not "
        "install it unless you trust its source.",
    ],
}


def _summary(subject: str, risk: str, outcome: Outcome) -> str:
    notable = [f for f in outcome.findings if f.severity in ("critical", "high", "medium")]
    if risk == "known_malicious":
        confirmed = next(f.title for f in notable if f.severity == "critical")
        return f"This {subject} is a known threat: {confirmed[0].lower()}{confirmed[1:]}."
    if risk == "suspicious":
        count = len(notable)
        return (
            f"This {subject} shows {count} warning sign{'s' if count != 1 else ''} often seen in "
            "scams or attacks. That is not proof it is malicious, but it calls for caution."
        )
    if risk == "no_known_threat":
        return (
            f"No known threat was detected in this {subject}. The checks listed below came back "
            "clean; that does not guarantee it is safe."
        )
    return (
        f"We could not reach a conclusion about this {subject}, because a check the result "
        "depends on was unavailable."
    )


def assess(scan_type: str, outcome: Outcome) -> Assessment:
    severities = [finding.severity for finding in outcome.findings]
    core_checks = [check for check in outcome.checks if check.core]
    core_completed = [check for check in core_checks if check.status == "completed"]

    if "critical" in severities:
        risk, confidence = "known_malicious", "high"
    elif "high" in severities or severities.count("medium") > 1:
        risk, confidence = "suspicious", "medium"
    elif "medium" in severities:
        risk, confidence = "suspicious", "low"
    elif core_completed:
        all_ran = all(check.status in ("completed", "skipped") for check in outcome.checks)
        risk, confidence = "no_known_threat", "medium" if all_ran else "low"
    else:
        risk, confidence = "inconclusive", "low"

    return Assessment(
        status="inconclusive" if risk == "inconclusive" else "completed",
        risk=risk,
        confidence=confidence,
        summary=_summary(_SUBJECT[scan_type], risk, outcome),
        recommendations=_RECOMMENDATIONS[(scan_type, risk)],
    )
