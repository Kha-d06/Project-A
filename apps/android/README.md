# SENTINEL for Android

The SENTINEL web app packaged for Android as a Trusted Web Activity (TWA): it opens
the site full-screen in the user's Chrome, with no browser bar. The site is
verified through Digital Asset Links. Everything the web app does works here, including:
- every scanner, the dashboard, Arabic and offline notices;
- **"Share to SENTINEL"** from WhatsApp, SMS, email or the browser, which fills in the scan form without submitting it.

## Why a TWA and not a native app

A native app needs its own scanner client, a separate release cycle and many more
permissions. A TWA reuses the reviewed, tested web app, needs only the Internet
permission, and still installs from Google Play. What a TWA cannot do:
- read SMS automatically: that needs a native app with SMS permissions, which Google Play restricts heavily;
- scan files on the device in the background.

## Build

Needs JDK 17 and the Android SDK (or Android Studio).

```bash
cd apps/android
gradle assembleRelease -PsiteHost=sentinel.your-domain.example   # Gradle 8.10+
```

CI builds a debug APK on every push (`android` job). This repository's
development environment had no Android SDK, so **the build has only been
checked in CI, never on a device**.

## Publish

1. Change `applicationId` in `app/build.gradle.kts` to your own reverse domain.
2. Create an upload key and sign the release (Android Studio → Generate Signed Bundle), or use Play App Signing.
3. On the server set:
   - `SENTINEL_ANDROID_PACKAGE` to your application ID;
   - `SENTINEL_ANDROID_CERT_SHA256` to the signing certificate's SHA-256 fingerprint, which Play Console shows under App integrity.

   The site then serves `/.well-known/assetlinks.json`; without it, Android shows a browser bar.
4. Upload the bundle in Google Play Console. This needs your developer account.
