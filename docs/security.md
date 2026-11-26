# Security notes

What the code does to protect users and the service, the assumptions it makes,
and what is still missing. This is not a substitute for an independent review.

## Trust boundaries

1. **Browser to Caddy.** Everything a user submits is untrusted: URLs, message text, files and file names.
2. **Caddy to web to API.** Only Caddy is published. It replaces `X-Forwarded-For` with the real client address. The web gateway forwards only that value, and the API trusts it (`SENTINEL_TRUST_FORWARDED_FOR=true`) because it is not reachable any other way. If you deploy differently, keep this property or turn the flag off; otherwise clients can choose the address their rate limits are counted against.
   - *Not yet verified:* Caddy's replacement of the header was not exercised in a running container during development. The Next.js gateway behaviour was tested.
3. **Worker to the internet.** The worker contacts attacker-chosen hosts while tracing redirects. This is the main SSRF surface (see below).
4. **Threat feeds.** Feed content is parsed as data and validated (URLs re-parsed, hashes checked for format). It is never executed or rendered as HTML.

## Authentication and sessions

- **Passwords.** Hashed with Argon2id (`argon2-cffi` defaults), re-hashed when parameters change, minimum 10 characters.
- **Constant-time login.** Unknown emails are verified against a decoy hash, so response time does not reveal which accounts exist. The error message is the same in both cases.
- **Session tokens.** 256-bit random tokens in an `HttpOnly`, `SameSite=Lax` cookie (`Secure` in production). Only their SHA-256 digest is stored, and sessions expire after 7 days.
- **CSRF.** Every state-changing request from a session must carry the per-session CSRF token in a header, compared in constant time.
- **Password changes.** Changing the password revokes every other session.
- **Rate limits.** Registration is limited per IP. Login is limited per IP and per account, password checks per account, and scans per user or IP, with a lower limit for files. Limits are counted in Redis. If Redis is down, the API fails closed with a 503 rather than dropping protection.
- **Production secret.** `SENTINEL_ENVIRONMENT=production` refuses to start with the default secret.

## SSRF defences (`app/analyzers/safe_fetch.py`)

- **Schemes and ports.** Only `http` and `https`, and only ports 80, 443, 8080 and 8443.
- **Address checks.** The host is resolved and every returned address must be public. That rejects:
  - loopback, private, link-local (including `169.254.169.254`), CGNAT, multicast, reserved and unspecified addresses;
  - IPv6 addresses that embed IPv4 (mapped, 6to4 and Teredo), which are unwrapped and checked.
- **DNS rebinding.** The connection goes to the exact address that was validated, so a second DNS answer cannot redirect it. TLS still verifies the original hostname.
- **Redirects.** Followed manually, at most 6, with loop detection and a 20-second overall budget. Every hop is validated again.
- **Body reads.** Link scans read only the status line and headers. Website scans read the final page, capped at 2 MB and time-limited.

## File handling

- **Upload limits.** Uploads are streamed to disk with the 25 MB limit enforced while streaming. Empty and oversized files are refused, and partial files are removed.
- **Storage.** Samples are stored under random names in a `0700` directory with `0600` permissions, outside anything web-served. The client's file name is kept for display only.
- **No execution.** Nothing is extracted to disk. Entries are listed from the ZIP directory to detect bombs, traversal, executables and encryption. Up to 200 members (10 MB each, 50 MB in total) are read into memory one at a time to be fingerprinted and matched against YARA rules; a member whose real size exceeds its declared size is dropped.
- **PDF streams.** Compressed (FlateDecode) streams are inflated with a 2 MB per-stream and 16 MB total limit, so decompression bombs stop early.
- **Deletion.** Samples are deleted when the scan finishes, fails or is deleted. A retention sweep also fails any scan stuck for 15 minutes and removes its sample.
- **Worker containment.** The worker runs as an unprivileged user on a read-only filesystem, with all capabilities dropped, `no-new-privileges`, and memory and CPU caps. Tasks have hard time limits.
- **No third parties.** Files are never sent to a third party. A VirusTotal lookup happens only when the user ticks the box for that scan, and sends the SHA-256 fingerprint only.

## Parser jail (`app/sandbox`)

Everything that parses an uploaded file's contents (PDF streams, Office macros, ZIP members, PE headers, YARA) runs in a fresh child process per file, never in the worker itself:

- **Environment:** only `PATH`, `LANG` and the YARA rules folder. The database URL, secret key and API tokens are never passed in, no file descriptors are inherited (so no database or Redis connection), and the working folder is `/`.
- **rlimits:** 512 MB address space, 60 s CPU, zero-byte file writes, 64 open files, no core dumps. The parent also enforces a wall-clock timeout.
- **Landlock (Linux 5.13+, unprivileged):** the child may read only the interpreter, its libraries, the app, the rules and its own sample. Other people's uploads and other processes' `/proc` entries are refused.
- **seccomp-bpf allowlist (libseccomp through ctypes), default action kill:** no `socket` or `connect`, no `fork`, `vfork` or `execve` (`clone` only with `CLONE_THREAD`), files only opened for reading.
- **Worker processes are non-dumpable**, so even on a kernel without Landlock their `/proc/<pid>/environ` is closed to the child.
- **nsjail (`SENTINEL_SANDBOX=nsjail`):** on hosts that allow namespaces, the same child runs inside nsjail with its own network, user, PID, IPC, UTS and mount namespaces, read-only binds, a private `/tmp`, `/proc` hidden, mapped to an unprivileged user, and cgroup v2 memory, PID and CPU caps where a cgroup is delegated. The default compose worker drops every capability, which nsjail's namespaces need, so there the layers above apply instead.

A file whose inspection breaks a rule or a limit gets a failed "Structure and embedded content" check and a stated limitation; nothing it produced is shown. All of this is tested inside a container with the worker's own hardening (`--cap-drop ALL`, `no-new-privileges`, read-only root) and in CI under real nsjail.

Every compose service now has a `pids_limit` and `no-new-privileges` (except the VPN, which needs its capabilities), and every Qalaa-built service drops all capabilities. Third-party images (Postgres, Redis, ClamAV, Caddy and others) keep their default capabilities, because they start as root and drop privileges themselves. Docker's default seccomp profile applies to all of them.

## Isolated page rendering (`app/analyzers/page_render.py`)

Off by default. When enabled, website scans also load the page in headless Chromium, because scripts run there:

- **No network of its own.** Every request the page makes is intercepted and fetched by `safe_fetch.fetch_resource`, which applies the full address, port and rebinding checks to each one. Redirects come back to the browser and are checked again as new requests.
- **Read-only.** Only GET and HEAD are allowed, so forms, beacons and uploads never leave the browser. WebSockets are closed, service workers blocked, downloads refused, permissions denied and WebRTC limited to proxied UDP.
- **Bounded.** 20 seconds, 150 resources and 15 MB per page, with a fresh browser for each scan.
- **Sandbox.** Chromium's own sandbox is turned off (`--no-sandbox`) because the worker container has no user namespaces. Containment rests on the container: unprivileged user, read-only filesystem, no capabilities and the restricted `sentinel_worker` database role. A browser exploit would land in that container. Run rendering workers on a separate host if your threat model needs more.

## AI message opinion

Off unless the user ticks the box for that scan. Links, email addresses and long numbers are masked before the text is sent. The model must answer with one of three fixed labels; anything else is discarded. Its answer can add at most a low-severity finding and never changes the verdict on its own.

## Output handling

- **The API.** It only returns JSON, with `nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` and a `default-src 'none'` CSP.
- **The web app.** It sets a nonce-based CSP for scripts (`strict-dynamic`, no `unsafe-inline` for scripts), `frame-ancestors 'none'`, HSTS, `Referrer-Policy` and a restrictive `Permissions-Policy`. Styles allow `unsafe-inline` because React style attributes and charts need it.
- **Evidence.** Scan evidence (matched text, URLs) is rendered as plain text and never as links, so a malicious URL in a report is not clickable.
- **Redirect safety.** The post-login redirect only accepts same-site paths.

## Data minimisation

The API keeps only what each feature needs. Message text and file contents are
not retained. Users can switch history off, export everything and delete their
account (cascading to scans and the audit log). [The privacy page](../apps/web/src/app/(site)/privacy/page.tsx)
documents exactly what is stored and shared, and must be kept in step with the
code.

### Lookups that run without the user asking

Background checks by the apps must not reveal what the person has:

- **Email** (desktop mailbox scanner, Thunderbird add-on): every check runs on
  the device with `apps/thunderbird/src/lib/analysis.js` and the public rule
  pack from `GET /email/rules`. The only request about a message is
  `POST /email/links` with bare links (scheme, host and path; the server strips
  query strings, fragments and user names again). Nothing is stored.
- **File reputation** (desktop, opt-in): k-anonymity. The client sends the first
  6 hex characters of the SHA-256 to `GET /intelligence/hash-prefix/{prefix}`,
  receives every listed hash with that prefix, and compares the full hash
  locally. The route takes no account or device token.
- **Pages in the browser extension**: checked inside the browser
  (`apps/extension/src/lib/local-check.ts`). The address rules are the server's
  own file (`app/rules/url_rules.json`, bundled and refreshed from
  `GET /extension/url-rules`) and give the same results, held to shared test
  vectors (`tests/fixtures/url-vectors.json`, run by both test suites). Known
  threats: `GET /extension/threat-prefixes` gives the first 4 bytes of the
  SHA-256 of every listed address and domain (every 6 hours). The extension
  hashes the page's normalised address, its host and each parent domain down to
  the registrable one; only on a prefix hit does it call
  `POST /extension/threat-hashes` with those prefixes plus 3 random prefixes
  from the list, and it compares the full hashes itself. Nothing about the
  request is stored. A full `POST /extension/check-url` (which sends the
  address) runs only from the right-click menu, when the person asks. Warning
  events, sent only for a linked account that turned syncing on, carry the
  site's origin, never the path or query. Limit: the browser percent-encodes
  some characters in paths (non-ASCII, quotes, braces) that the feeds may list
  unencoded, so such an exact-link listing can be missed; the domain checks
  aren't affected.
- These routes, and the extension's hash and server-check routes, are dropped from uvicorn's access log
  (`app/core/private_paths.py`), so an address is never written next to what it
  looked up. Their rate limits keep only a per-address counter that expires.

The full-hash `GET /intelligence/hash/{sha256}` remains for the website's
lookup tool, where a person deliberately pastes one fingerprint.

## Desktop privacy guards

- **Clipboard auto-clear.** A secret on the clipboard (copied from Qalaa, or recognised by shape: private keys, cloud keys, API tokens, JWTs, `.env` lines, long random strings) is wiped after 30 seconds by default, only if the clipboard still holds the same secret (compared by SHA-256). The text is never logged, stored or sent; clients only see its kind and the time left.
- **Credential guardrails.** Qalaa alerts when a program that isn't expected to opens SSH private keys, `.env` files, cloud credentials (`~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, …) or a browser's cookie and password stores. Paths follow SigmaHQ's credential-access rules (DRL 1.1, adapted): also macOS keychains (plus `security dump-keychain` / `find-*-password -w` on the command line, seen while the command is still running: a dump that finishes in milliseconds between two 15-second snapshots is missed), KeePass databases, crypto wallets (Electrum, Exodus, Ethereum keystores, MetaMask's browser storage), Discord and Telegram session tokens, `/etc/shadow`, and Windows saved credentials. One program reading a browser's `Local State` key and its passwords or cookies is raised as a high-priority stealer pattern. A default-allowed name only counts where the person's own programs can't have put it: on Linux the binary and every folder above it must be root-owned and not writable by others; on macOS it must be on a SIP-protected path or carry a valid Apple or Developer ID signature. A program the person allows is pinned by full path and SHA-256, so a changed binary is reported again. The person can pause (SIGSTOP), stop (SIGKILL) or allow the program. Before any signal Qalaa checks that the same program still runs under that process id. Only the file kind, the path with the home folder shortened to `~`, and the program are kept; file contents are never read.
  - Linux: every open while the fanotify on-access helper runs, otherwise a look at `/proc/<pid>/fd` of the person's own processes every 5 seconds.
  - macOS: `lsof` for the person's own processes every 15 seconds.
  - Polling can miss a read that starts and finishes between two looks, and the interface says so.
  - Windows: not available yet. Seeing which program holds a file open needs a system handle query from native code, which Qalaa doesn't have; the interface says so.

- **Safe DNS answers.** Every answer is read (compression pointers followed with a loop guard, lengths bounds-checked; anything unreadable is passed through as before). If any CNAME in the chain is a listed domain, the lookup is refused, so a tracker or malware host can't hide behind a harmless first name. A public name that DNS-over-HTTPS answers with a private, loopback, link-local or CGNAT address is refused as DNS rebinding. Exempt from that check: local names (single-label, `.lan`, `.home.arpa`, `.internal` and similar), services that do it by design (`plex.direct`, `nip.io`, `sslip.io`, `localtest.me`, `lvh.me`) and a per-person allow list. Answers from the network's own DNS are not rebinding-checked, because company networks answer intranet names with private addresses; CNAME uncloaking still applies to them.
- **SafePay.** Opens a banking or shopping site in Firefox, Brave, Chrome, Chromium or Edge with a brand-new profile in a private temporary folder (mode 0700). Extensions, sync, background apps, password saving and form filling are off, and the profile is deleted when the browser closes. Profiles left by a crash are removed the next time Qalaa starts. With Safe DNS on, the browser's own DNS-over-HTTPS is turned off so lookups go through Qalaa's filter; with it off, Firefox uses Quad9 over HTTPS, and Chromium-based browsers use the system's DNS (they accept a DoH server only by policy). SafePay keeps the session apart from the everyday browser. It is not a sandbox and doesn't make an infected computer safe.
  - The browser extension offers SafePay once per banking site with a notification, and the popup has an "Open in SafePay" button. The page is handed over as a `qalaa://safepay` link: the browser asks the person first, and Qalaa Desktop accepts https pages only.
  - Qalaa's native window hides its Credentials page from screenshots and screen sharing on Windows (`WDA_EXCLUDEFROMCAPTURE`) and macOS (`NSWindowSharingNone`). Linux has no way to ask for this.

- **Browser fingerprint noise (extension, off by default).** Canvas `toDataURL`/`toBlob`/`getImageData` (about one pixel in 64 shifts by one colour step), WebGL's unmasked vendor and renderer (a common value), `AudioBuffer.getChannelData` (a 1e-7 offset on a few samples), and `navigator.hardwareConcurrency`/`deviceMemory` (common values) are changed consistently: the same within a site for a browser session, different between sites and sessions, and reading twice gives the same answer. The seed is an HMAC-SHA-256 of the site's origin with a 32-byte secret held in session storage, which the browser clears on restart. The background script injects the noise into each frame as it commits, passing the seed as an argument, so the page has no way to read it.
  - Coverage: the page, same-origin frames a script creates (patched through `contentWindow`/`contentDocument` and when inserted with `appendChild`, `append` and similar, so `window[i]` is covered too), popups from `window.open`, and dedicated and shared workers (started through a wrapper that installs the noise first: `OffscreenCanvas`, worker `navigator`). Also `AudioBuffer.copyFromChannel`, `AnalyserNode` float readings and WebGL `readPixels`. WebRTC is limited to the public network interface (`chrome.privacy`, optional `privacy` permission) so pages can't learn local addresses.
  - Not covered: frames created through `innerHTML` and reached before any of the hooks above run, service workers, and workers on sites whose security policy forbids blob workers (they start unprotected rather than break).
  - Limits: the noise is injected at commit, so on a page that loads almost instantly, its first inline script can run before the noise is in place and read real values. The e2e test reports how often that happens. Patched functions report themselves as native code to `Function.prototype.toString`, but a determined script may still notice them.
  - Each site can be excluded from the toolbar popup.

- **Email aliases.** A random (10 characters from a look-alike-free alphabet) or chosen address on the operator's relay domain, or on the person's own DNS-verified domain, forwards to the account's verified email. Forwarding is done by the operator's own Postfix (`infrastructure/alias-relay`), which asks `/relay/aliases/resolve` (bearer relay token, compared in constant time, request logs filtered) for one recipient at a time. The API sees addresses and counts, never messages. The relay's Postfix does handle each message in transit: it is queued only until the next server accepts it, and, like any mail server, Postfix logs envelope senders and recipients. So the honest claim is "content isn't stored or read", not "Qalaa never sees your mail"; the relay README sets short log retention and queue lifetime. Paused aliases are refused, and deleted ones become tombstones: refused forever, never issued again, label wiped. Aliases can be created, paused and deleted on the website (Dashboard → Privacy), created from the extension's popup (never from a page's content script) and from the desktop app through the linked device. Limits: 200 per person and 30 created per hour.

- **Data-broker checklist.** A versioned catalog (`apps/desktop/src/core/data/brokers.json`) of people-search and marketing-data companies: opt-out page (https, on the company's own domain, enforced by a test), how they verify, how long removal takes, and a GDPR, CCPA or general request letter. The opt-out links have not been checked online for this version, and the page says so. The website shows the same catalog (`apps/web/src/lib/data/brokers.json`; a test fails if the two copies differ) on Dashboard → Privacy, with progress kept only in that browser's storage and never sent to the server. On the desktop, progress is kept only on this computer. A request or removal 90 days old shows a Home reminder to look again, because listings come back. Request letters are filled in with a name and email typed in at that moment and copied to the clipboard; neither is stored. No paid removal service or API is used.

## API keys and metrics

- **API keys.** Personal keys are 256-bit random values prefixed `snt_`, shown once and stored only as SHA-256 digests. They are revocable and limited to ten per account. Keys authenticate scanning, history and lookups only. Account changes, key management, extension linking and all staff functions require a website session with its CSRF token, so a leaked key cannot take over or escalate an account. Disabling an account stops its keys working immediately.
- **Metrics.** The metrics endpoint is disabled unless `SENTINEL_METRICS_TOKEN` is set. Requests without the right bearer token get the same 404 as an unknown route.

## Mobile web app

- **Service worker.** It caches only the offline notice. Pages, scan results and API responses are never stored on the device.
- **Shared content.** Content shared into Qalaa is placed in the form, not submitted. It travels in the address of a page on this site, so it is visible to this server's access logs if those are enabled.

See also [security-review.md](security-review.md) for the latest self-review.

## Native scanner (`qalaa-scan`, Wave 4.A)

`apps/desktop-native/crates/qalaa-scan` is a separate Rust program the daemon starts for each file it scans, so a parser bug triggered by a hostile file can't take the daemon down.

- **Caps.** Before reading the file it limits itself: on Linux, writable memory (`RLIMIT_DATA`, 1 GB by default; `RLIMIT_AS` would break YARA-X's engine, which reserves large address ranges it never uses), CPU seconds, no file writes, no core dumps and `no_new_privs`. macOS has the CPU, write and core-dump limits but doesn't enforce the memory one. Windows has none of these yet (a Job Object cap comes with the Windows service). On every platform the daemon kills it after 45 seconds and reads at most 1 MB of output. Files over 128 MB aren't passed to it.
- **What it does.** goblin parses PE, ELF and Mach-O headers; YARA-X matches the rule set; EMBER-style static features (byte and byte-entropy histograms, strings, headers, sections, hashed imports and exports) feed a gradient-boosted tree model. The features were written from the EMBER paper's descriptions; EMBER's AGPL code isn't used. The model is trained on EMBER's MIT-licensed data by `tools/scan-model/train.py`, which uses the same vectorizer (a fixture keeps the Rust and Python versions identical). It covers Windows PE files only and says so for anything else.
- **Verdicts.** Only rules named `MAL_`/`APT_` (or with `score >= 80`) make a file "known malicious". Other rules and the model make it "suspicious" at most, and the model's finding states its false-positive rate on the held-out set.
- **Signed bundles.** Rules and the model are loaded only from a bundle whose `manifest.json` is signed (ed25519) by a key compiled into the binary (`keys/bundle-keys.txt`), and whose every file matches its listed size and SHA-256. Paths that could leave the folder are refused. No key is pinned yet: until one is, the scanner runs without rules or a model and the app says so. Bundles are built with `tools/scan-bundle/build_bundle.py`; keep the private key offline.
- **Updates.** Differential: the desktop downloads the manifest, checks its signature and that its version is newer (no downgrades), copies unchanged files from the current bundle, downloads only changed ones and checks each hash, then has `qalaa-scan verify` accept the assembled folder before swapping it in. The previous bundle is kept; any failure leaves the current one in use. The server hosts the files at `/api/v1/updates/scan-bundle/` without authentication or identifiers, serving only names its manifest lists.

**Server side.** Uploaded Linux and macOS programs are parsed with LIEF (Apache-2.0) inside the same parser jail as every other parser (seccomp allowlist, Landlock, rlimits, or nsjail where configured): executable stacks, writable-and-executable segments, unusual loaders, libraries loaded from temporary folders, memory-only execution (`memfd_create` with `fexecve`/`execveat`), UPX packing and unsigned macOS programs. For Windows programs LIEF also checks that an Authenticode signature matches the file's contents; that shows the file wasn't changed after signing, not that the signer is trustworthy.

## Behaviour rules (Wave 4.B, first slice)

The background service checks newly started programs against process-creation rules adapted from SigmaHQ (Detection Rule License 1.1; each rule in `apps/desktop/src/core/data/behaviour-rules.json` keeps its original title and author): downloads piped into a shell, office apps starting shells (macOS), shell history being wiped, the firewall being switched off or flushed, Gatekeeper quarantine marks removed, fake AppleScript password prompts, setuid bits set, and programs running from temporary folders. The evaluator supports a stated subset of Sigma (four fields, `contains`/`startswith`/`endswith`/`re`/`all`, simple conditions) and refuses rules outside it. Every rule is tested against recorded matching and near-miss command lines, and three run as atomics in CI.

- Linux: `/proc` is read every second. macOS: `ps` every 2 seconds, the user-space fallback while Apple's Endpoint Security entitlement is pending. Windows: not available until the admin service (ETW) exists, and the app says so.
- Polling sees a program only if it is still running at the next look, so commands that finish faster are missed. The status shows this (`seesShortLived: false`).
- On Linux the person can install a small root helper (`qalaa-procwatchd.py`, one pkexec prompt, a systemd unit with `NoNewPrivileges` and `ProtectSystem=strict`). It subscribes to the kernel's netlink process connector, so every program start is reported, however short, and polling stops while it's connected. It only reports: it never blocks or changes anything, drops events while Qalaa isn't running, and forwards at most 500 a second over a socket only the person and root can open (mode 0600). A CI step runs it as root and checks it sees a command that lasts milliseconds.
- Alerts keep the rule, the program and its parent, and a command line shortened to 300 characters with passwords, tokens and long random strings masked. One alert per rule and program per 10 minutes. The person can dismiss it or stop the program; Qalaa first checks the process still runs the same command.

## Sandbox runs (Wave 4.C)

When the person ticks "Also run it in an isolated sandbox", an uploaded Linux program or shell, Python or Perl script is run in gVisor (`app/sandbox/detonation.py`). Windows and macOS programs are never run, and the report says so.

- `runsc --network=none`: only loopback exists. A fake DNS server inside the sandbox answers every name with 127.0.0.1 and a fake web server answers every request with an empty page (`app/sandbox/sink.py`), so the report can list the names and URLs a downloader wanted without anything leaving the server.
- A read-only root file system; only a 32 MB `/tmp` is writable. The sample is copied into a read-only mount. `noNewPrivileges`, an OCI memory limit (256 MB), a process limit (64), one CPU, a 30-second run inside and a hard kill from outside.
- gVisor's own syscall trace, written outside the sandbox, shows programs started, files opened for writing (including refused attempts on system files), network connections and deletions.
- Findings are behaviours seen (downloads, direct IP connections, start-up and SSH-key changes attempted, self-deletion, debugger checks, dropped executables). They never say "known malware" by themselves, and the report states that a quiet run isn't proof: malware can wait, check for a real network, or target Windows.
- Limits that hold even against a hostile sample, each checked in CI with real gVisor: a sample that never ends is stopped at the time limit together with everything it started (it runs in its own process group); memory is capped for the sample itself (`RLIMIT_AS`, enforced by gVisor), with the outer cgroup cap leaving room for gVisor and the sink so a greedy sample can't silence the report; process starts are capped inside the sandbox (`RLIMIT_NPROC`), and refused ones are reported as a flood of processes, while the host-side cgroup cap is looser because gVisor itself needs host threads; writing to the system is refused and connecting out fails.
- The report lists what the run tried to reach: names looked up, web requests, direct connections and programs started, or says plainly that a quiet run isn't proof. The website shows it as a "Sandbox run" panel; the desktop app can send one chosen file to the person's own server for a run (only when they press Send) and follows the result on its Behaviour page.
- It is off unless `SENTINEL_DETONATION_RUNSC` and `SENTINEL_DETONATION_ROOTFS` (a read-only root file system for the sandbox) are set. runsc needs root, so run it on a dedicated worker host, not in the shared API container. gVisor is pinned to release 20261102 and checked against its published SHA-512 in CI, where a dropper-shaped test script runs for real.

## Ad and tracker lists (Wave 4.D)

- **Desktop, Safe DNS.** With "Block ads and trackers" on, EasyList and EasyPrivacy are downloaded on the person's computer from easylist.to (refreshed after four days; a wrong download, such as a captive-portal page, keeps the previous copy) and matched by `qalaa-dns`, a small native helper built on adblock-rust (MPL-2.0, used unmodified as a dependency). At DNS only rules that block a whole host apply; `$third-party`, path and cosmetic rules are left to the browser. Exceptions, `$important` and `$badfilter` work as in the browser. Names behind a CNAME are checked too. The helper never delays a lookup: no answer within 250 ms, or any failure, means the name is allowed. Captive-portal checks are never filtered.
- **Browser extension.** The same lists are compiled into static declarativeNetRequest rulesets when the extension is built (`scripts/abp-dnr.mjs`), off until the person turns the option on, and matched inside the browser, so nothing about browsing is sent. Patterns, `$third-party`, `$domain=`, resource types, `$match-case`, `$important`, exceptions and `@@…$document` carry over; cosmetic filters, scriptlets, regular expressions and options like `$redirect` or `$csp` are skipped and counted. Chrome guarantees 30,000 static rules per extension, so EasyList is capped at 20,000 and EasyPrivacy at 10,000, keeping exceptions first and then whole-host rules; the rest is listed as over the cap in `rules/NOTICE.txt`. Sites on the person's allow list are exempt. CI loads the built extension in Chromium and checks that a host from the list is blocked and an ordinary request isn't.
- **Licences.** EasyList and EasyPrivacy are by The EasyList authors, dual-licensed GPLv3 / CC BY-SA 3.0. The desktop downloads them and doesn't redistribute them. The extension ships converted rulesets under CC BY-SA 3.0 with attribution (`rules/NOTICE.txt`), separate from Qalaa's own code.

## Safe DNS on Android (Wave 4.E)

A `VpnService` whose only route is a virtual DNS server (10.111.222.2), the usual DNS-only pattern, written for Qalaa (no third-party VPN code). Android sends every app's lookups there. Names on the downloaded malware and phishing domain list (the same one the desktop uses), or under one, get NXDOMAIN at once. Everything else is asked of the network's own resolver (Quad9 if there is none) through a socket protected from the VPN, so local names and captive portals keep working; Android's connectivity checks are never blocked. No other traffic enters the tunnel, nothing is logged and nothing is sent to Qalaa. The packet handling (IPv4/UDP and DNS parsing, NXDOMAIN replies, checksums) lives in `scanner-core` and is unit-tested on the JVM, including malformed and truncated packets. Limits stated in the app: Android's Private DNS (DNS-over-TLS), when on, takes over lookups and Safe DNS then has no effect; only one VPN can run at a time, so it can't be combined with another VPN app; IPv6-only lookups aren't routed in.

## Account passkeys (Wave 4.F)

People can add passkeys to their Qalaa account and sign in with them (`app/api/passkeys.py`, py_webauthn 3.0.1, BSD-3-Clause), following the OWASP Authentication Cheat Sheet:

- Challenges are 32 random bytes kept on the server, single-use (marked used before verification, so a replay fails), tied to their purpose and, for registration, to the signed-in person, and valid for five minutes.
- The relying-party id and allowed origins are configured (`SENTINEL_WEBAUTHN_RP_ID`, `SENTINEL_WEBAUTHN_ORIGINS`; by default the public URL's host and origin), so a passkey can't be used from a look-alike site.
- User verification (PIN or biometric) is required, so a passkey sign-in counts as two factors and doesn't also ask for the authenticator code. Discoverable credentials: the browser offers the account's passkeys without an email being typed.
- The signature counter must increase when the authenticator keeps one; a counter that goes backwards suggests a cloned authenticator and the sign-in is refused.
- The user handle is the account's random id, never the email. Only the public key, credential id and counter are stored. Up to ten passkeys per account; removing one needs the password. Sign-in errors don't say whether an account or passkey exists. Rate limits as for password sign-in.
- Tests use a software authenticator with real P-256 keys, so verification runs for real: wrong origins, missing user verification, replays, expired or another person's challenges, cloned counters and disabled accounts are all refused.

## Known gaps

- Admin and moderator actions are not yet protected by a second confirmation step.
- There is no encryption at rest beyond what the database volume provides.
- There has been no independent penetration test.
- qalaa-scan has no trained model or pinned signing key in the repository yet: the training needs the EMBER dataset (several GB) and the key must be generated and held by the project owner.
