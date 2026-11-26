# Code signing (Windows Authenticode, macOS Developer ID)

Platform code signing is what Windows SmartScreen and macOS Gatekeeper check
before the app first runs. It is separate from Qalaa's own update signature
([release-signing-key.md](release-signing-key.md)): both are needed.

All signing happens in `.github/workflows/release.yml`.
- **Secrets:** credentials go in **GitHub Actions secrets** (Settings → Secrets and variables → Actions → Secrets), which the workflow can use but nobody can read back.
- **Variables:** non-secret names go in **variables** (the Variables tab).
- **Never in the repository:** no certificate, private key or `.p8` file is ever committed (`scripts/check-no-private-keys.py` enforces it).
- **Verification:** after packaging, `scripts/verify-signatures.sh` (macOS) and `scripts/verify-signatures.ps1` (Windows) check the result. Set the variable `REQUIRE_SIGNED_RELEASES=true` to make a tagged release fail when anything is unsigned.

## Windows (Authenticode)

Since June 2023, public CAs issue code-signing keys only on hardware (a token or
an HSM), so a `.pfx` file you can put in a CI secret is no longer the normal
route. Two supported options:

### Option A: Azure Trusted Signing (recommended)

Microsoft holds the key in its HSMs; CI signs through an API, and no key file exists.

| Kind | Name | Value |
|---|---|---|
| secret | `AZURE_TENANT_ID` | Entra ID tenant of the signing app registration |
| secret | `AZURE_CLIENT_ID` | the app registration's client id |
| secret | `AZURE_CLIENT_SECRET` | its client secret (or switch to OIDC federation later) |
| variable | `AZURE_SIGNING_ENDPOINT` | e.g. `https://weu.codesigning.azure.net` (the account's region) |
| variable | `AZURE_SIGNING_ACCOUNT` | the Trusted Signing account name |
| variable | `AZURE_SIGNING_PROFILE` | the certificate profile name (Public Trust) |
| variable | `WIN_PUBLISHER_NAME` | the certificate's subject CN, exactly as shown in the Azure portal |

Setup:
1. Create a Trusted Signing account and pass identity validation (organisation or individual).
2. Create a Public Trust certificate profile.
3. Create an app registration and give it the **Trusted Signing Certificate Profile Signer** role on that profile only.
4. Fill in the table above.

The workflow passes these to electron-builder's `win.azureSignOptions`.

### Option B: a certificate you hold

- **Exportable certificate** (an older OV certificate, or a CA that still issues `.pfx` files): set secret `WIN_CSC_LINK` (the `.pfx`, base64-encoded: `base64 -w0 cert.pfx`), secret `WIN_CSC_KEY_PASSWORD`, and variable `WIN_PUBLISHER_NAME`.
- **Key on a USB token or cloud HSM** (DigiCert KeyLocker, SSL.com eSigner, a YubiKey with an EV certificate): this can't go in a secret. It needs a self-hosted Windows runner with the vendor's signing tool and `win.signtoolOptions.sign` pointing at a small script. Set that up with the vendor's instructions when choosing this route.

### What it gives

- The installer and app are signed and timestamped (`http://timestamp.acs.microsoft.com` for Azure, or the CA's timestamp server).
- `WIN_PUBLISHER_NAME` is also written into the app's update configuration, so the installed app **refuses an update signed by anyone else** (electron-updater's `verifyUpdateCodeSignature`, on by default).
- `verify-signatures.ps1` checks:
  - status `Valid`;
  - a timestamp present;
  - the signer's CN equals `WIN_PUBLISHER_NAME`.
- SmartScreen reputation still builds up over downloads. An EV-level certificate (or Azure Trusted Signing) shortens that.

## macOS (Developer ID + notarisation)

Requires an Apple Developer Program membership (organisation enrolment needs a D-U-N-S number).

| Kind | Name | Value |
|---|---|---|
| secret | `CSC_LINK` | the **Developer ID Application** certificate with its private key, exported from Keychain Access as `.p12`, base64-encoded |
| secret | `CSC_KEY_PASSWORD` | the `.p12` export password |
| secret | `APPLE_API_KEY_P8` | contents of the App Store Connect API key file `AuthKey_XXXX.p8` (role: Developer) |
| secret | `APPLE_API_KEY_ID` | that key's id |
| secret | `APPLE_API_ISSUER` | the issuer id shown on the App Store Connect "Keys" page |

Setup:
1. Developer account → Certificates → "+" → **Developer ID Application**.
2. Create it from a CSR made in Keychain Access on a Mac you control.
3. Export certificate + key as `.p12` with a strong password, then `base64 -i cert.p12 | pbcopy` into `CSC_LINK`.
4. Delete the exported file afterwards.
5. App Store Connect → Users and Access → Integrations → **Team Keys** → generate a key with the Developer role. Download the `.p8` once and paste its contents into `APPLE_API_KEY_P8`.

The API key is preferred over an Apple ID password: it is revocable on its own and needs no two-factor prompts.

What the build does:
- **Signs** with the hardened runtime and `build/entitlements.mac.plist`. That file grants only `com.apple.security.cs.allow-jit`, which Electron's JavaScript engine needs; nothing else.
- **Notarises** through `@electron/notarize`, using the `.p8` file written to the runner's temp folder for that job only and deleted after packaging.
- **Staples** the ticket.
- **Checks** with `verify-signatures.sh`: `codesign --verify --deep --strict`, the hardened-runtime flag, `spctl --assess`, and `stapler validate`.

## Native binaries and other platforms

- The Rust apps (`qalaa-command`, `qalaa-guardian-pet`, `qalaa-scan`) are built in CI but not packaged by electron-builder. When they ship as installers, sign them with the same identities: `signtool` / Azure Trusted Signing on Windows, and `codesign --options runtime` plus `notarytool` on macOS. The same verification scripts apply.
- Linux packages are not code-signed by the platform. Qalaa's update signature protects AppImage updates, and `.deb`/`.rpm` repositories would be signed with a separate GPG key when one is set up.
- **Android:** the release keystore secrets are already in the workflow. Keep the keystore's only copies offline and in the secret store, and enrol in Play App Signing if publishing on Google Play.

## Checklist before turning on `REQUIRE_SIGNED_RELEASES`

- [ ] A manual run of `release.yml` shows "Windows signatures verified." and "macOS signature and notarisation verified".
- [ ] The signed `.exe` installs on a clean Windows VM without a SmartScreen block (or with the reputation warning only).
- [ ] The `.dmg` opens on a clean Mac without a Gatekeeper prompt beyond "downloaded from the internet".
- [ ] An update from a signed build to the next signed build installs, and an update signed with a different certificate is refused.
