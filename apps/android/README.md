# Qalaa for Android

**A native scanner for this phone, plus the Qalaa web app.**

- **`MainActivity`** (the app's launcher icon) checks the phone itself:
  - **Installed apps:**
    - every app is fingerprinted (SHA-256 of its APK) and compared with the server's known-malware list;
    - apps installed from outside an app store are checked for the behaviour of banking trojans and stalkerware:
      - screen reading plus drawing over other apps;
      - reading SMS one-time codes;
      - device-administrator rights;
      - notification access;
      - a hidden icon combined with location and microphone or message access;
    - apps that call themselves WhatsApp, Telegram, Instagram and others without being the official package are flagged;
    - you can open Android's own uninstall prompt for any flagged app.
  - **Files:**
    - with "All files access": Downloads (quick scan) or all shared storage (full scan);
    - without it: any files you pick;
    - finds known malware, the EICAR test file, app installers, and programs disguised as documents or pictures (`invoice.pdf.apk`);
    - flagged files can be moved to an encrypted quarantine, and restored.
  - **Phone settings:**
    - security patch age;
    - screen lock;
    - developer options and USB debugging;
    - signs of root;
    - apps allowed to install other apps.
  - **Qalaa account:**
    - link with the code from Dashboard → Devices;
    - turn on **Allow scans from my Qalaa account** (off by default), and quick, full and Downloads scans, quarantine and fingerprint updates can be started from the website;
    - the phone checks in every 15 minutes (Android's shortest interval for background work), so a scan starts at its next check-in;
    - only names, verdicts, fingerprints and the settings summary are sent, never file contents or paths.
- **`LauncherActivity`** is the Qalaa web app in a Trusted Web Activity: full-screen Chrome, verified with Digital Asset Links. It opens from the scanner's "Open the Qalaa website" button, from links to your Qalaa site, and from **Share to Qalaa** in other apps. Shared text fills in the scan form and is never submitted automatically.

**English and Arabic** follow the system language.

**Layout:**

| Path | What |
| --- | --- |
| `scanner-core/` | All decisions: app risk rules, device checks, file checks, the account protocol, and the English and Arabic text. Plain Kotlin, unit-tested on the JVM. |
| `app/` | The Android side: reading installed apps and settings, storage, quarantine, the 15-minute check-in job, and the screen. Platform APIs only, with no AndroidX in the scanner. |

## Calls and messages

Both need the phone to be linked to a Qalaa account. The app then downloads two lists during its regular check-in, at most every 6 hours:
- community-verified scam numbers (`GET /devices/phone-list`);
- malicious domains and exact phishing/malware URLs (`GET /devices/blocklist`).

Matching happens on the phone. No call, message or link is ever sent to the server.

- **Call screening** (Android 10+): tap "Warn me about calls from reported scam numbers" and let Qalaa be the call-screening app. A listed number shows a warning notification. It is rejected only if "Block reported scam numbers" is on. Local number forms (0501234567) match listed international numbers.
- **Links in messages**: optional notification access lets Qalaa read links in incoming message notifications (SMS, WhatsApp, Telegram and similar). A link to a listed domain, or an exact listed page, triggers a warning that names the app and the site. Only links are looked at, and nothing is stored. Qalaa does not ask for SMS permissions, which Google Play reserves for default SMS apps.
- "Share to Qalaa" still sends a whole message to the message scanner when you want a full check.

## What it cannot do

Android limits what any app can see, and these limits apply to every antivirus:
- **No access to other apps' private data**, and no way to stop an app while it runs.
- **Apps cannot be removed for you.** Qalaa opens Android's uninstall prompt and you confirm. Remotely, only files can be quarantined, not apps.
- **Without "All files access"**, files can only be scanned when you pick them.
- **It does not replace Google Play Protect.** Keep it on.

On iPhone, apps cannot scan other apps or files at all. iPhone users get the website and the browser extension.

## Build and test

You need JDK 17 and the Android SDK (or Android Studio).

```bash
cd apps/android
gradle :scanner-core:test                                         # unit tests, no SDK needed
gradle assembleRelease -PsiteHost=qalaa.your-domain.example     # Gradle 8.10+
```

**What CI does:** on every push, CI runs the unit tests and builds a debug APK (`android` job).

**What was verified here:**
- This repository's development environment has no Android SDK.
- The Android code was type-checked here against the Android 15 framework classes (Robolectric's `android-all`).
- The scanner logic is covered by the unit tests.
- **It has not been run on a phone yet.** Try it on a test device before you publish.

## Publish on Google Play

1. **Change `applicationId`** in `app/build.gradle.kts` to your own reverse domain.
2. **Sign the release** with Play App Signing, or with your own upload key.
3. **Fill in Play Console's permission declarations.** The app's core purpose is "antivirus / security", which both policies list as allowed:
   - **`QUERY_ALL_PACKAGES`**: needed to check every installed app.
   - **`MANAGE_EXTERNAL_STORAGE`** ("All files access"): needed to scan and quarantine files in shared storage. The app asks for it only when the person taps the button, and works without it.
4. **Set these on the server** so links open full-screen without a browser bar:
   - `SENTINEL_ANDROID_PACKAGE`: your application ID;
   - `SENTINEL_ANDROID_CERT_SHA256`: from Play Console → App integrity.
5. **Upload the bundle** in Google Play Console. This needs your developer account.
