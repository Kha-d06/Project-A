# Creating the update-signing key

The desktop app installs an update only if its `release-manifest.json` is signed
by a key pinned in the app (`RELEASE_KEYS` in
`apps/desktop/src/engine/release-verify.ts`; spec in [update-signing.md](update-signing.md)).
This page is the ceremony for creating that key.

**Only the public key goes into the application.** It is 64 hex characters and
safe to publish: it can check a signature but not make one. The private key
never touches the repository, the development machine, CI, the Qalaa server or
any cloud storage. `scripts/check-no-private-keys.py` fails CI if a key file or
key body is ever committed.

## 1. The offline machine

Use one of these, used for nothing else:
- a laptop whose wireless card is removed or disabled in firmware; or
- a live USB system (Debian Live or Tails) booted with networking off. Unplug Ethernet, turn Wi-Fi and Bluetooth off before booting. In Tails, don't unlock persistent storage.

What it needs:
- **Node.js 22 LTS.**
  - On an *online* machine, download the Linux x64 tarball and `SHASUMS256.txt` from nodejs.org.
  - Check `SHASUMS256.txt` against the Node release keys (`gpg --verify SHASUMS256.txt.sig`), then the tarball against it (`sha256sum -c --ignore-missing SHASUMS256.txt`).
  - Copy the tarball over on the transfer drive. On a live system, unpack it under `/tmp` and use `bin/node`.
- **The signing tool**, `tools/release-signing/sign-release.mjs`, from a reviewed commit. On the online machine:
  ```sh
  git show <commit>:tools/release-signing/sign-release.mjs > sign-release.mjs
  sha256sum sign-release.mjs        # write this down
  ```
  Copy it over and check the same SHA-256 on the offline machine. It uses Node built-ins only; there is nothing to `npm install`.
- **Three USB drives:**
  - **KEY-A** and **KEY-B**: encrypted (LUKS, or VeraCrypt if you need Windows access). They hold the private key and its backup. They are only ever plugged into the offline machine.
  - **TRANSFER**: unencrypted. It carries installers in and signed manifests out. It never holds the key.
- **Passphrase:** at least 5 random words (the tool refuses fewer than 12 characters). Written on paper and kept with the backup drive, in a different place from KEY-A.

## 2. Generate the key

On the offline machine, with KEY-A unlocked and mounted at `/media/KEY-A`:

```sh
node sign-release.mjs keygen /media/KEY-A/qalaa-release-1.key
```

- **Passphrase:** it asks for it twice, without echo.
- **The key file:** an ed25519 key encrypted with that passphrase (AES-256, PKCS#8), written with mode 0600. The tool refuses to overwrite an existing file.
- **Output:** it prints, for example:

  ```
  Public key to pin in RELEASE_KEYS: 10b9…80ac
  ```

Then:
1. Copy the key file to KEY-B (`cp /media/KEY-A/qalaa-release-1.key /media/KEY-B/`).
2. Check both copies give the same public key: `node sign-release.mjs pubkey <file>`.
3. Write the public key into a text file on TRANSFER (`echo <hex> > /media/TRANSFER/release-key-1.pub`).
4. Unmount and lock KEY-A and KEY-B, then shut the machine down.

## 3. Pin the public key (development machine)

1. Copy `release-key-1.pub` from TRANSFER.
2. In `apps/desktop/src/engine/release-verify.ts`:
   ```ts
   export const RELEASE_KEYS: string[] = ["<64 hex characters>"];
   ```
3. Commit it in a reviewed change whose message records the key's first and last 8 characters. `test/release-verify.test.ts` checks that every pinned entry is a 64-hex public key.
4. Builds from that commit on accept updates signed by this key. Installs from *before* that commit still treat updates as manual, so they need one manual download.

## 4. Sign each release

1. Let `release.yml` build the installers (signed with Authenticode and Developer ID when those are configured, see [code-signing.md](code-signing.md)).
2. On the online machine, download the artifacts and check them against the release's `SHA256SUMS.txt`, then copy them to TRANSFER.
3. On the offline machine:
   ```sh
   node sign-release.mjs sign /media/KEY-A/qalaa-release-1.key /media/TRANSFER/release 1.4.0
   ```
   This writes `release-manifest.json` and `release-manifest.json.sig` into that folder. The manifest is valid for 30 days; a fourth argument changes that.
4. Back on the online machine, check with the **public key only**, then publish:
   ```sh
   node tools/release-signing/sign-release.mjs verify <public key hex> ./release
   ./scripts/publish-downloads.sh ./release
   ```
5. Re-sign (with a new expiry) before 30 days pass if the release stays current. Otherwise installs that check after the expiry see the update as manual.

## 5. Rotation and compromise

- **Planned rotation** (yearly, or when the release manager changes):
  1. Generate `qalaa-release-2.key` the same way.
  2. Pin both keys in one release signed with key 1.
  3. Sign with key 2 from the next release on.
  4. Remove key 1 a release later.
- **Lost key** (both drives gone): pin a new key in a build distributed through the download page. Existing installs need one manual update.
- **Leaked key:**
  1. Remove it from `RELEASE_KEYS` and publish a manual-download build at once.
  2. Tell users to install it by hand.
  3. Installs that still trust the leaked key accept anything it signs until they update, which is why the TUF stage (online timestamp and revocation) is planned in update-signing.md.
- **Record-keeping:** keep a short log of each ceremony (date, people present, public key, tool SHA-256). It records nothing secret.
