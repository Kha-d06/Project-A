# Update signing

Two things update themselves on a person's computer: the **scan engine bundle**
(rules, model, signatures) and the **desktop app**. Each is signed by a key the
server doesn't hold, so a compromised server can't push code.

## What is checked today

| | Scan bundle (`engine/scan-bundle.ts`) | Desktop app (`engine/release-verify.ts`) |
|---|---|---|
| Signed object | `manifest.json` (exact bytes) | `release-manifest.json` (exact bytes) |
| Signature | ed25519, `manifest.sig` | ed25519, `release-manifest.json.sig` |
| Trusted keys | pinned in `qalaa-scan` (`qalaa-scan keys`) | `RELEASE_KEYS` in `release-verify.ts` |
| Per-file check | SHA-256 and size of every file | SHA-512 and size of the downloaded installer |
| Rollback | version must be newer | version must equal the offered update and be newer than the running app |
| Replay of an old signed manifest | (version check) | `expires` (default 30 days after signing) |
| Then | `qalaa-scan verify` on the assembled folder, atomic swap | install only when the person clicks Install; never on quit |
| Without a key | bundle updates refused | update shown as available, with a link to the download page; nothing installs itself |

electron-updater's own SHA-512 check (from `latest.yml`) still runs. It protects
against a broken download, not against the server.

## Release procedure (desktop)

The full ceremony (offline machine, encrypted key drives, passphrase, pinning,
signing and checking each release, rotation and compromise) is in
[release-signing-key.md](release-signing-key.md). In short, on the offline machine:

```sh
node sign-release.mjs keygen /media/KEY-A/qalaa-release-1.key           # once; prints the public key to pin
node sign-release.mjs sign /media/KEY-A/qalaa-release-1.key ./release 1.4.0
```

Then, on the publishing machine, with the public key only:

```sh
node tools/release-signing/sign-release.mjs verify <public key hex> ./release
./scripts/publish-downloads.sh ./release
```

The private key is passphrase-encrypted (the tool refuses an unencrypted one) and
never leaves the offline machine and its encrypted drives.

Platform code signing (Authenticode on Windows, Developer ID and notarization on
macOS) is separate and still needed: it is what Windows SmartScreen and
Gatekeeper check before the app first runs. `release.yml` uses certificates
when the repository secrets are set.

## Next stage: The Update Framework (TUF)

TUF fits, because Qalaa has exactly its problem: many clients, one distribution
server that shouldn't be trusted, and long-lived installs. It is worth its
operational cost once there is more than one release manager. Plan:

1. **Roles and keys.**
   - `root` (2-of-3 offline keys, hardware tokens, 1-year expiry) delegates to the other roles.
   - `targets` (offline, 3 months) lists the installers and bundle files with hashes.
   - `snapshot` (online on the release server, 1 week) pins the versions of targets metadata.
   - `timestamp` (online, 1 day) proves freshness.
2. **Client.** Ship the initial `root.json` in the app. Use a maintained TUF client (python-tuf for tools, `tough` in Rust for `qalaa-scan` and the native app) rather than writing one. Reject expired, rolled-back or under-threshold metadata. Root rotation follows the TUF chain.
3. **Migration.** Publish TUF metadata next to the current signed manifests for one release cycle. Clients that understand TUF prefer it; the signed manifest stays as the fallback until all supported versions speak TUF.
4. **Bundles first.** Move `qalaa-scan` bundles to TUF before the app, since they update daily and benefit most from the timestamp role.

Not done yet. The ed25519 manifests above are the interim protection.
