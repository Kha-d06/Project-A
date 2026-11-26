# Qalaa security audit (2026-11-26)

An evidence-based audit of the whole repository. The external review's points were
treated as hypotheses and checked against the code. Each finding names the files it
rests on. Where something isn't implemented, it says so. Status words:
**Fixed** (changed and tested in this audit), **Open** (confirmed, not fixed yet),
**Accepted** (a known limit, stated in the product), **Not confirmed** (the review's
claim didn't hold up).

## Status at a glance (updated after the follow-up round)

**Completed and tested:**
- QA-01, QA-02: elevated command injection.
- QA-03: signed update check, with an encrypted-key offline tool that has `keygen`, `pubkey`, `sign` and `verify`.
- QA-04: socket folder.
- QA-05: client-side pipe check (Windows run still to do).
- QA-06 to QA-10.
- QA-20: X-Forwarded-For.
- QA-21: public-suffix autofill.
- QA-22: SHA-pinned Actions, SBOMs, private-key guard.
- QA-23: signing configuration and verification.
- Android minSdk 29.

**Blocked on something outside the repository** (owner handling):

| Item | Needs | Ready to use |
|---|---|---|
| Update-signing key (QA-03) | offline key ceremony | [release-signing-key.md](release-signing-key.md); then pin the 64-hex public key |
| Authenticode, Developer ID, notarisation (QA-23) | certificates, Apple and Azure accounts | [code-signing.md](code-signing.md), `release.yml` |
| Windows pipe check, verified (QA-05) | a Windows VM | [windows-pipe-test.md](windows-pipe-test.md), `tools/windows-pipe-test/squat.ps1` |
| Endpoint Security (QA-16) | Apple entitlement; not blocking | [macos-endpoint-security.md](macos-endpoint-security.md) |

**Waiting for approval or review** (nothing irreversible done):

| Item | Gate |
|---|---|
| Argon2id and recovery-kit migration (QA-13) | independent review of [vault-migration-spec.md](vault-migration-spec.md) §10, then owner approval for release A, then for enabling migration |
| Sharing format v2 (QA-14) | same reviewer: it changes how shared entries are encrypted |
| Same-user IPC hardening (QA-11) | design choice between peer-credential checks and a privileged service |
| Web vault delivery (QA-12) | product decision: an extension or native-only vault, or a signed web bundle |

**Open, no external dependency** (next):
- QA-19: email links by hash prefix.
- QA-24: sandbox retention.
- Daemon-side pipe DACL (QA-05).
- Reproducible builds (QA-22).

Related specifications: [update signing](update-signing.md), [vault cryptography](vault-crypto.md),
[security notes](security.md) (per-feature design, including URL-checking privacy).

---

## 1. Architecture map

| Component | Path | Runs as | Talks to |
|---|---|---|---|
| API | `services/api` (FastAPI, SQLAlchemy, Postgres, Redis, Celery) | container user | Postgres, Redis, feeds (abuse.ch), SMTP, AI provider (opt-in) |
| Scan worker / sandbox | `services/api/app/sandbox` (nsjail parsers, gVisor `runsc --network=none` detonation) | container, no network inside the jail | queue only |
| Page renderer | `app/analyzers/page_render.py` (headless Chromium) | worker container | every request goes through `safe_fetch` (SSRF policy) |
| Website + web vault | `apps/web` (Next.js 16) | Node in container | API; vault crypto runs in the browser (`lib/vault.ts`) |
| Edge | `infrastructure/caddy` | container | only service with published ports (80/443/8080) |
| Desktop engine + daemon | `apps/desktop/src/engine`, `src/core`, `daemon.ts` | **the person's user** | qalaa-ipc socket/pipe; server over HTTPS |
| Electron shell (being retired) | `apps/desktop/src/main.ts` | the person's user | renderer over Electron IPC; updater |
| Native UI | `apps/desktop-native` (Rust + Slint), `qalaa-ipc` client | the person's user | daemon over qalaa-ipc |
| Native scanner | `crates/qalaa-scan` (YARA-X, goblin, tree model, signed bundles) | the person's user | none (bundles verified by pinned ed25519 keys) |
| Root helpers (Linux) | fanotify on-access, proc connector, nftables kill switch, device locks | root, installed through one `pkexec` prompt | local only, fail open |
| Browser extension | `apps/extension` (MV3) | browser | API (hash prefixes, rules, vault ciphertext) |
| Thunderbird add-on | `apps/thunderbird` | Thunderbird | API (`/email/links`, rule pack) |
| Android | `apps/android` (Kotlin + TWA) | app sandbox | API; VpnService DNS filter |
| VPN | `infrastructure/vpn`, `app/api/vpn.py` | WireGuard container | peers |

### Traced paths (verified in code)

- **A page's address** (extension). The navigation event goes to `assessUrl` → `localCheckUrl` (`apps/extension/src/lib/local-check.ts`).
  - The rules check runs locally.
  - The SHA-256 of the address, its host and parent domains is compared with the local 4-byte prefix list.
  - Only on a prefix hit does `POST /extension/threat-hashes` get called, with the hit prefixes plus 3 decoys; the full hashes are compared locally.
  - Nothing is stored server-side, and the routes are out of the access log (`app/core/private_paths.py`).
  - The full address is sent only from the right-click "Check on the Qalaa server".
- **A DNS query** (desktop Safe DNS, `engine/safe-dns.ts`).
  - The local proxy on 127.0.0.1 checks the downloaded domain list (from the Qalaa server, whole list).
  - Allowed names go over DoH to Quad9 or the chosen resolver, not to Qalaa.
  - Local names, and queries while DoH is unreachable, go to the network's own DNS.
- **A suspicious file** (desktop). Scan (`engine/scanner.ts`, ClamAV/YARA-X/`qalaa-scan`) → `Quarantine.add`.
  - The file is encrypted with AES-256-GCM using a random key per item, which sits in the 0600 index next to it. This stops re-detection and accidental runs; it isn't a secrecy boundary.
  - `restore` decrypts to a free name, now created exclusively.
- **An app update**: electron-updater against `<server>/downloads/desktop` → **now** also `verifyDownloadedUpdate` (`engine/release-verify.ts`) before install.
- **Scan-engine update**: `engine/scan-bundle.ts`. The manifest is ed25519-signed with keys pinned in `qalaa-scan`; each file is SHA-256 checked; `qalaa-scan verify` runs before the swap.
- **Vault key** (`apps/web/src/lib/vault.ts`).
  - The key-encryption key is PBKDF2-SHA256 with 600,000 iterations and a 16-byte random salt.
  - It wraps a random AES-256-GCM vault key, with the account id and purpose as associated data.
  - The vault key is kept non-extractable in memory.
  - The server stores the wrapped key and the ciphertext only.
- **Local IPC**: a client reads the 0600 token file and sends `hello`. The daemon (`core/server.ts`) compares it in constant time; every other method needs an authenticated connection.
- **Privileged operations**: always the system's own prompt (`pkexec`, UAC `Start-Process -Verb RunAs`, `osascript … with administrator privileges`). There is no resident privileged service on Windows or macOS.

---

## 2. Trust boundaries and single points of compromise

```
 person's device                                   operator's server
 ┌──────────────────────────────────────┐          ┌──────────────────────────────────┐
 │ browser ─ extension (local checks)   │  https   │ Caddy ─ API ─ Postgres/Redis      │
 │ web vault JS  ◄──────── served by ───┼──────────┼─ web (Next.js)                    │
 │ native UI ─ qalaa-ipc ─ daemon (user)│          │ worker: nsjail / gVisor (no net)  │
 │                 │ pkexec/UAC prompt  │          │ feeds, downloads/desktop, VPN     │
 │           root helpers (Linux)       │          └──────────────────────────────────┘
 └──────────────────────────────────────┘
```

What one compromised server could do **before** this audit, and now:

| Server capability | Before | Now |
|---|---|---|
| Push code to every desktop that auto-updates | Yes: the SHA-512 came from the same server (QA-03) | Only with the offline release key; without a pinned key, nothing installs itself |
| Learn which pages people visit | Every page address (privacy mode: domain) | Only 4-byte prefixes on a list hit, mixed with decoys |
| Read vault contents | No (end-to-end), **but** it serves the vault's JavaScript (QA-12) | Unchanged: the web vault trusts the server's code |
| Read shared entries / emergency access | Yes, by substituting a recipient's public key (QA-09) | Detectable: fingerprints shown, key pinned, a change blocks until confirmed |
| Hide a person's ordinary files | Yes, via a remote "quarantine" naming a hash (QA-07) | Only files the device itself flagged |
| Run code in the sandbox host | No: `--network=none`, gVisor, no secrets | Unchanged |
| Change what's blocked | Yes (blocklists, rules) | Yes; rules can only *add* warnings, and a malicious list can block sites, not run code |

**Proposed separation** (in order of risk removed; no microservices for their own sake):

1. **Release signing off the server.** Done in code (QA-03). The key ceremony is a release-manager task ([update-signing.md](update-signing.md)).
2. **Vault code off the server.** Unlock and edit in the extension and the native app, whose code is signed and shipped separately. Treat the web vault as a convenience with a stated caveat, or serve it from a separately signed, Subresource-Integrity-pinned bundle.
3. **Threat intelligence as data, never code.** Already true (lists, JSON rules, signed scan bundles). Keep `url_rules.json` declarative.
4. **Malware samples and sandbox** in their own worker with no database credentials (already a separate role, `worker-role`). Retention is limited (see QA-24).
5. **VPN** on its own host or container, with no API credentials beyond peer provisioning.
6. **Telemetry** (if ever turned on, R7) to a separate store with time decay, never joined with accounts.

---

## 3. Findings

Severity follows impact × exploitability for this product's users. "Confidence" is how sure the finding is from the code.

### Fixed in this audit

**QA-01 · Elevated command injection when blocking a program in the firewall: High (confidence high) · Fixed**
- **Where:** `apps/desktop/src/engine/tools.ts`, `blockProgram` / `unblockProgram`.
- **Was:**
  - Windows built `cmd /c "netsh … program=<path> && netsh …"` and quoted only paths containing spaces, so `C:\x&calc.exe` ran `calc` elevated.
  - macOS spliced the path into an AppleScript string, removing only `'`, so `"` ended the string and `& do shell script "…"` ran as administrator.
- **Attack:** a crafted file or folder name, or a compromised renderer or same-user process asking to block it. The person sees an ordinary Qalaa elevation prompt.
- **Fix:**
  - Paths are checked (absolute, one line, none of `"<>|*?` or control characters).
  - Windows: netsh runs from an elevated PowerShell whose script travels as `-EncodedCommand`, with every argument a single-quoted literal. No `cmd.exe`.
  - macOS: the path is an `osascript` argument, quoted with `quoted form of`.
- **Tests:** `test/protection-tools.test.ts` decodes the elevated script and checks a hostile path survives only as a literal.

**QA-02 · Argument injection into elevated `reg.exe`: Medium (high) · Fixed**
- **Where:** `tools.ts`, `runElevatedWindows` (startup manager).
- **Was:** `Start-Process -ArgumentList` joins elements with spaces and quotes nothing. A startup entry named by malware (`x /va`) became extra arguments to an elevated `reg delete`.
- **Fix:** each argument is quoted by the `CommandLineToArgvW` rules (`windowsArg`).
- **Tests:** in the same file.

**QA-03 · Desktop app updates trusted the server alone: Critical (high) · Fixed in code; key ceremony open**
- **Where:** `apps/desktop/src/main.ts` (electron-updater, `autoInstallOnAppQuit = true`), `.github/workflows/release.yml` (code signing optional, off without secrets).
- **Was:** `latest.yml` and the installer come from the same server, and builds are unsigned by default, so anyone controlling the server or its `downloads/` folder could install code on every auto-updating desktop.
- **Fix:** `engine/release-verify.ts`.
  - An update installs only if `release-manifest.json` carries an ed25519 signature by a key pinned in the build (`RELEASE_KEYS`).
  - The manifest's version must equal the update and be newer than the running app (no downgrade).
  - It must not be expired (no indefinite replay).
  - The downloaded file's SHA-512 and size must match.
  - Install-on-quit is off.
  - Offline signing tool: `tools/release-signing/sign-release.mjs`.
- **Remaining:**
  - `RELEASE_KEYS` is empty until the release manager generates a key, so this build reports updates as manual instead of installing them. That is a deliberate secure default.
  - Platform code signing (Authenticode, Developer ID) still needs certificates.
  - TUF is staged in update-signing.md.
- **Tests:** `test/release-verify.test.ts` (tampered file, foreign key, downgrade, replay, expiry, edited manifest), signing with the real tool.

**QA-04 · IPC socket folder could be pre-created by another user: Medium (high) · Fixed**
- **Where:** `core/server.ts`, `core/paths.ts`; `crates/qalaa-ipc/src/client.rs`.
- **Was:** without `XDG_RUNTIME_DIR` the socket lives under `/tmp/qalaa-<uid>/qalaa`. Another local user could create that folder first. The daemon's `chmod` failure was ignored, so the attacker could replace the socket and receive the token from the native UI, which grants full control of the daemon.
- **Fix:** the daemon refuses to listen unless the folder is a real directory owned by the user with no group or other access, and its parent is owned by the user (not group/other-writable) or by root. The Rust client checks the same, plus the socket's owner, before it sends the token.
- **Tests:** `test/core-ipc.test.ts`, `crates/qalaa-ipc/tests/private_socket.rs`.

**QA-06 · Autofill could fill a page the tab navigated to after the check: Medium (medium) · Fixed**
- **Where:** `apps/extension/src/background.ts` (`vault-fill`), `lib/autofill.ts`.
- **Was:** the URL was compared, then the vault was read (async), then the script injected. A redirect in between received the password.
- **Fix:** the injected function re-checks `location.origin` and `window.top === window` at the moment of filling.
- **Tests:** `test/autofill.test.ts`.
- **Already sound:** fill only on click from the popup, top frame, https only, saved-site match, refused on flagged sites.

**QA-07 · A remote "quarantine" command could hide any file the computer had scanned: Medium (high) · Fixed**
- **Where:** `main.ts`, `quarantineByHash`.
- **Was:** any history entry with the named SHA-256 was moved, clean ones included. The server (or anyone holding the account) could hide documents whose hashes it knew or guessed.
- **Fix:** `quarantineCandidates` (`engine/remote.ts`) takes only entries this device marked malicious or suspicious. The file's hash is still re-checked before moving.
- **Tests:** `test/remote.test.ts`.

**QA-08 · Quarantine restore wrote through a link planted at the old name: Low (high) · Fixed**
- **Where:** `engine/quarantine.ts`, `restore`.
- **Was:** `stat` follows a dangling symlink and reports "free", and `writeFile` then created the link's target, anywhere the user can write.
- **Fix:** exclusive create (`flag: "wx"`).
- **Tests:** `test/engine.test.ts`, which fails on the old code.

**QA-09 · The server could substitute sharing and emergency-access keys: Medium (high) · Fixed (detection)**
- **Where:** `apps/web/src/lib/vault-sharing.ts`, `components/dashboard/password-vault.tsx`.
- **Was:** recipients' public keys came from the server, unverified, so a compromised server could read every share and emergency snapshot.
- **Fix:**
  - Fingerprints (128 bits of SHA-256 over the key) are shown for you and the recipient, to compare in person or by phone.
  - The recipient's fingerprint is pinned inside the encrypted vault at first share.
  - A changed key shows a warning and blocks sharing until the person confirms they checked it.
- **Tests:** `lib/vault-sharing.test.ts`, `components/dashboard/vault-sharing-keys.test.tsx`.
- **Still open:** trust on first use (first share to a swapped key is undetected unless fingerprints are compared), and QA-14.

**QA-10 · Every page address went to the server: High for privacy (high) · Fixed earlier in this round (R1)**
- **Fix:** local rules and hash-prefix lookups, as described in §1.
- **Remaining:** some feed URLs with characters the browser percent-encodes can miss the exact-link match. The domain checks are unaffected.

### Open

**QA-05 · Windows named pipe can be squatted: Medium (medium) · Fixed in code (client side); awaiting Windows verification**
- **Where:** `core/paths.ts` and `crates/qalaa-ipc/src/paths.rs` (`\\.\pipe\qalaa-daemon-<USERNAME>`), `client.rs` (no server check on Windows).
- **Attack:** a process of another user creates the pipe before the daemon starts. The daemon then refuses ("already running") and the native UI hands its token to the squatter. The token only works against the real daemon, but a squatter can also feed the UI false status.
- **Fix:**
  - Client: `GetNamedPipeServerProcessId` → `OpenProcessToken` → compare the token user's SID with its own.
  - Daemon: create the pipe with an explicit DACL (owner only) and `FILE_FLAG_FIRST_PIPE_INSTANCE`.
- **Done (client):** `check_pipe_server` in `qalaa-ipc` compares the pipe server's user SID with its own before sending anything (compile- and clippy-checked for `x86_64-pc-windows-msvc`).
- **To verify:** run the procedure in [windows-pipe-test.md](windows-pipe-test.md).
- **Still open (daemon):** Node can't set a pipe DACL, so a squatter can still stop the daemon from starting (a denial of service, not a token leak).

**QA-11 · Any program running as the person can drive the daemon: High (high) · Open (architectural)**
- **Where:** `core/server.ts`. The token file is readable by every process of that user.
- **Impact:** malware running as the user can switch off watching, Safe DNS and ransomware protection, restore quarantined files, or start elevation prompts that look like Qalaa's. There is no tamper resistance on any OS.
- **Fix, staged:**
  1. Peer credentials on each connection (`SO_PEERCRED` / `getpeereid`; on Windows, `GetNamedPipeClientProcessId`), allowing only Qalaa's own signed executables (Authenticode / code-signing requirement on macOS; on Linux the installed path owned by root).
  2. Destructive or protective-off methods confirmed in the native UI's own window, never on the daemon's word alone.
  3. A privileged service (Windows service / launchd daemon) holding protection state, with the user daemon unprivileged.
- **Limit to state:** same-user malware can always do much of this by other means. The aim is to stop Qalaa being the easiest switch.

**QA-12 · The web vault runs code served by the server that stores the ciphertext: High (high) · Open (architectural)**
- **Where:** `apps/web`. A strict nonce CSP (`src/proxy.ts`) limits XSS, but not the server itself.
- **Impact:** a compromised server can ship JavaScript that captures the master password at the next unlock.
- **Fix:**
  - Recommend the extension or the native app for vault use, and state the caveat on the vault page.
  - Later, a signed, integrity-pinned web bundle.
- See [vault-crypto.md §6](vault-crypto.md).

**QA-13 · PBKDF2 instead of a memory-hard KDF; no recovery: Medium (high) · Open (migration designed, not run)**
- PBKDF2-SHA256 at 600,000 iterations meets current OWASP guidance, but costs GPU attackers little memory. There is no recovery path: a forgotten master password loses the vault.
- **Decision (with the owner):** Argon2id plus a recovery kit. The migration re-wraps the vault key at the next unlock and never re-encrypts without a successful unlock. The plan is in [vault-crypto.md §5](vault-crypto.md). It is not shipped in this audit, because a KDF change must be reviewed before it can touch real vaults.

**QA-14 · Sharing seal uses the raw ECDH output as the AES key, with no context or sender authentication: Low (high) · Open**
- **Where:** `vault-sharing.ts`, `sharedAesKey`.
- **Detail:**
  - The ECDH output is not fed through a KDF and is not bound to the sender, recipient or purpose.
  - Anyone can seal to a public key, so the server could forge a "share from Sara". Accepting a share only adds a login, but a forged login is a phishing vector.
- **Fix:** sealing format v2:
  - HKDF-SHA256 over the ECDH secret, with `info` = format, purpose and both user ids;
  - AES-GCM with those as associated data;
  - the sender's static key signing the ephemeral key (ECDSA P-256);
  - v1 kept for opening old shares.

**QA-15 · Windows endpoint visibility is thin: Medium (high) · Accepted (positioning decided)**
- **Present:**
  - Defender status (`engine/posture.ts`, `Get-MpComputerStatus`);
  - Controlled Folder Access (`engine/cfa.ts`);
  - user-space scans, startup and persistence listing;
  - a firewall per program.
- **Absent:**
  - a process feed (`engine/process-feed.ts`: "Windows: nothing yet");
  - ETW;
  - WFP;
  - a minifilter;
  - Security Center registration;
  - tamper protection.
- **Decision:** Qalaa is a **Defender companion** on Windows and doesn't claim real-time protection there. Next steps: ETW process and image-load events from a signed admin service (QA-11 step 3); WFP is not needed for current features. No kernel driver (guardrail 2). Protected Process Light is not available without Microsoft's antimalware certification, so it is not claimed.

**QA-16 · macOS: no Endpoint Security entitlement: Medium (high) · Accepted**
- `ps` polling only, XProtect is the real-time layer, and the kill switch is not available.
- **Next:** request the ES entitlement and ship a system extension when it is granted; notarize builds (certificate needed).

**QA-17 · Linux process feed is polling unless the root helper is installed: Low (high) · Accepted, stated in the product**
- fanotify on-access and the proc connector are optional root helpers that fail open.
- eBPF/LSM are not used. A future eBPF exec/connect probe would close the "short-lived process" gap, but needs CO-RE kernels and is not justified before the Windows work.

**QA-18 · VPN kill switch is Linux-only: Medium (high) · Accepted, stated**
- `engine/vpn-guard.ts` uses an nftables `inet` output hook with `policy drop`, so IPv4 and IPv6 are both covered at the OS layer.
- Windows and macOS report it as unavailable rather than claiming it.
- **Gaps:** forwarded traffic (containers, VMs) isn't covered, and split-tunnel ranges are IPv4.

**QA-19 · Email link checks still send bare links: Medium for privacy (high) · Open (planned with the BEC/QR work, R5)**
- **Where:** `apps/thunderbird/src/lib/analysis.js`, `apps/desktop/src/engine/mail.ts` → `POST /email/links`.
- Scheme, host and path are sent; the query is stripped. It moves to the same prefix scheme as the extension.

**QA-20 · Rate limiting trusted the leftmost X-Forwarded-For: Low (medium) · Fixed**
- **Where:** `app/core/rate_limit.py`, `client_address`.
- This is safe only because Caddy discards client-sent headers (`infrastructure/caddy/Caddyfile`). A CDN or load balancer put in front without care would let clients pick their own address.
- **Fix:** read from the right, skipping `SENTINEL_FORWARDED_HOPS` (default 1).
- **Tests:** `tests/test_rate_limit_sliding.py`.

**QA-21 · Autofill matched by host suffix without the public-suffix list: Low (medium) · Fixed**
- **Where:** `lib/autofill.ts`, `loginsFor`.
- A login saved for a public or shared suffix (`github.io`, `herokuapp.com`) would be offered on every site under it.
- **Fix:** a login saved for a public or private suffix matches only that exact host (`isPublicSuffix`, tldts).
- **Tests:** `test/autofill.test.ts`.

**QA-22 · GitHub Actions pinned by tag; no SBOM: Low (high) · Fixed, except reproducible builds**
- 40 `uses: …@vN` references; `release.yml` has `contents: write`.
- **Done:**
  - All 42 `uses:` are pinned to the commit of the newest release in their major version, with the version as a comment; `.github/dependabot.yml` keeps them current.
  - Releases attach CycloneDX SBOMs for the desktop, extension, web, native and API parts (`npm sbom`, `scripts/sbom-from-lock.py`).
  - CI and releases fail if a private key is committed (`scripts/check-no-private-keys.py`).
- **Open:** a reproducible-build check, and moving `contents: write` to the final release job only.

**QA-23 · Desktop and Android release signing depend on secrets that aren't configured: Medium (high) · Configuration done; certificates pending**
- `release.yml` builds unsigned without them: SmartScreen warnings on Windows, and no notarization on macOS.
- **Done:**
  - `release.yml` supports Azure Trusted Signing or a certificate file on Windows, and Developer ID with API-key notarisation on macOS.
  - It verifies the results (`scripts/verify-signatures.sh` / `.ps1`), and `REQUIRE_SIGNED_RELEASES` turns unsigned tagged releases into failures.
  - Minimal hardened-runtime entitlements are in place.
- **Operator setup:** [code-signing.md](code-signing.md).

**QA-24 · Sandbox realism and retention: Low (medium) · Open (R6)**
- **Isolation verified:** gVisor, `--network=none`, no secrets, no host files. The sandbox can't reach metadata or internal services.
- **Realism gaps:** no TLS interception, no random-name NXDOMAIN behaviour, no time acceleration, x86-64 Linux only (no ARM/MIPS, no Windows).
- None of these should weaken isolation.
- Sample retention is unbounded in the uploads volume. Set a retention job, and document it on the privacy page.

### Checked and sound (no change needed)

- **Account passwords:** Argon2id (`argon2-cffi` defaults), equal-time checks for unknown accounts; login rate-limited per IP and per account.
- **Sessions:** tokens stored as SHA-256 digests; CSRF header compared in constant time (`app/api/deps.py`); production refuses the development secret (`core/config.py`).
- **SSRF:** `safe_fetch` resolves, rejects non-global addresses (embedded IPv4 in IPv6 included), pins the connection to the checked address, and re-validates every redirect. The page renderer and webhook delivery both go through it.
- **Webhooks:** HMAC-signed, delivered through the SSRF-safe POST.
- **Sandbox:** no network inside, gVisor runtime, parser jail with a seccomp allowlist.
- **Scan-engine bundles:** ed25519 over the manifest with keys pinned in `qalaa-scan`; per-file SHA-256; `qalaa-scan verify` before the swap; no downgrade.
- **Android:**
  - Exported components are the launcher, the Trusted Web Activity, and services guarded by system bind permissions (`BIND_VPN_SERVICE`, `BIND_SCREENING_SERVICE`, notification listener).
  - `allowBackup="false"`; `QUERY_ALL_PACKAGES` is justified for an antivirus.
  - minSdk raised from 23 to 29 (Android 10) in this audit.
- **Web:** nonce-based `strict-dynamic` CSP.
- **Extension:** no `externally_connectable`, so pages can't message it; vault secrets are readable only from the popup; the decrypted vault is held in memory with an auto-lock.

### The external review's hypotheses, verified

| Review point | Verdict |
|---|---|
| URL checks and DNS not genuinely local | **Correct** for URLs (fixed, QA-10). **Partly correct** for DNS: queries never went to Qalaa, but to Quad9; that is now disclosed. |
| Vault crypto spec unpublished, PBKDF2 weak | Spec **correct** (now published). PBKDF2 at 600k is **not weak** by current guidance, but Argon2id is better (QA-13). The review didn't mention the more serious **web-vault code trust** (QA-12) and **key substitution** (QA-09). |
| Windows tamper resistance and kernel visibility missing | **Correct** (QA-11, QA-15). Answer: Defender companion, user-space only. |
| Update chain should be TUF with offline keys | The **underlying risk is more severe than stated** (server-only trust, QA-03). An offline-key signed manifest is in place; TUF is staged next. |
| SSRF egress proxy for the page fetcher | **Already mitigated in code** (pinned resolution, redirect validation, renderer routed through it). A network-level egress proxy remains good defence in depth. |
| Pet is spoofable; use OS notifications | **Correct**: any window can look like the pet. Critical alerts should use OS notifications (R3). |
| Terminal hooks overstated | **Correct**; now described as a safety net. |
| Alias "server never sees mail" | **Correct**; reworded (content isn't stored or read; envelopes are logged). |
| Kill switch claims | **Not confirmed** as an overstatement: Linux enforces it at the OS layer, and other platforms say it's unavailable. |
| Android minSdk too low | **Correct**; raised to 29. |

---

## 4. Remediation roadmap

Ordered by risk removed first, then privacy, exploitability, architectural weight, effort and credibility.

| # | Item | Findings | Needs |
|---|---|---|---|
| 1 | Generate the release key offline, pin it, sign every release; turn on Authenticode and notarization | QA-03, QA-23 | Release manager; certificates |
| 2 | Windows pipe server check and owner-only DACL | QA-05 | A Windows test machine |
| 3 | Peer-credential checks and UI-confirmed protective-off methods on qalaa-ipc | QA-11 | — |
| 4 | Vault: recommend extension/native, caveat on the web vault; Argon2id + recovery kit migration (reviewed) | QA-12, QA-13 | Review of vault-crypto.md §5 |
| 5 | Sealing format v2 (HKDF, AAD, sender signature) | QA-14 | — |
| 6 | Email links by hash prefix; Arabic BEC and QR-code detection | QA-19 | — |
| 7 | TUF metadata (root, targets, snapshot, timestamp) for desktop and scan bundles | QA-03 | Offline root keys (threshold) |
| 8 | Pin Actions by SHA; SBOM (CycloneDX) per release; reproducible-build check for the extension | QA-22 | — |
| 9 | Windows ETW process feed from a signed admin service | QA-15 | Code-signing certificate |
| 10 | Public-suffix check in autofill; right-to-left XFF parsing | QA-20, QA-21 | — |
| 11 | Sandbox retention job; realism (fake TLS CA, NXDOMAIN, time) without weakening isolation | QA-24 | — |
| 12 | macOS Endpoint Security system extension | QA-16 | Apple entitlement |

Enterprise and regional items:
- SSO (OIDC/SAML), RBAC beyond owner/member, an exportable audit log, SIEM export (syslog/CEF), and MDM configuration profiles.
- A control mapping for NCA ECC, Qatar NIA, UAE IA and ISO 27001 *with evidence*. No compliance is claimed today.

---

## 5. Implementation report (this audit)

| Change | Files | Issue | Tests |
|---|---|---|---|
| Elevated firewall commands without shells | `apps/desktop/src/engine/tools.ts` | QA-01, QA-02 | `test/protection-tools.test.ts` |
| Private socket folder (daemon and client) | `apps/desktop/src/core/server.ts`; `crates/qalaa-ipc/src/client.rs`, `lib.rs`, `Cargo.toml` (libc, already in the lockfile) | QA-04 | `test/core-ipc.test.ts`, `crates/qalaa-ipc/tests/private_socket.rs` |
| Signed desktop update check | `src/engine/release-verify.ts`, `src/main.ts`, `src/renderer/app.ts`, `src/renderer/i18n.ts` (EN/AR), `tools/release-signing/*`, `scripts/publish-downloads.sh` | QA-03 | `test/release-verify.test.ts` |
| Autofill origin re-check | `apps/extension/src/lib/autofill.ts`, `background.ts` | QA-06 | `test/autofill.test.ts` |
| Remote quarantine limited to flagged files | `src/engine/remote.ts`, `src/main.ts` | QA-07 | `test/remote.test.ts` |
| Exclusive restore | `src/engine/quarantine.ts` | QA-08 | `test/engine.test.ts` |
| Sharing key fingerprints and pinning | `apps/web/src/lib/vault-sharing.ts`, `lib/vault.ts`, `components/dashboard/password-vault.tsx`, `lib/i18n/extra.ts` (EN/AR) | QA-09 | `lib/vault-sharing.test.ts`, `components/dashboard/vault-sharing-keys.test.tsx` |
| Android minSdk 29 | `apps/android/app/build.gradle.kts`, download hint (EN/AR) | — | CI Android build (not run here: no Android SDK) |
| Windows pipe server check | `crates/qalaa-ipc/src/client.rs`, `Cargo.toml` (windows-sys 0.59, already locked) | QA-05 | `cargo clippy --target x86_64-pc-windows-msvc`; Windows procedure in windows-pipe-test.md |
| Encrypted signing key, `pubkey`/`verify` | `tools/release-signing/sign-release.mjs` | QA-03 | `test/release-verify.test.ts` |
| Code-signing pipeline | `.github/workflows/release.yml`, `apps/desktop/build/entitlements.mac*.plist`, `scripts/verify-signatures.sh`, `.ps1` | QA-23 | Workflow syntax checked; real run needs certificates |
| Private-key guard | `scripts/check-no-private-keys.py`, `.gitignore`, CI and release jobs | QA-03, QA-23 | Run on all 887 tracked files; pattern self-test |
| SHA-pinned Actions, Dependabot, SBOMs | `.github/workflows/*.yml`, `.github/dependabot.yml`, `scripts/sbom-from-lock.py` | QA-22 | SBOMs generated locally (100 to 714 components each) |
| Public-suffix autofill | `apps/extension/src/lib/autofill.ts` | QA-21 | `test/autofill.test.ts` |
| X-Forwarded-For from the right | `services/api/app/core/rate_limit.py`, `config.py` | QA-20 | `tests/test_rate_limit_sliding.py` |

Remaining limitations are listed under each finding. Nothing here makes Qalaa
"secure" in the absolute. It removes the specific ways found in which one
compromised component, or one crafted file name, could turn Qalaa against the
people using it.
