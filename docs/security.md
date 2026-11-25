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
- Both routes are dropped from uvicorn's access log
  (`app/core/private_paths.py`), so an address is never written next to what it
  looked up. Their rate limits keep only a per-address counter that expires.

The full-hash `GET /intelligence/hash/{sha256}` remains for the website's
lookup tool, where a person deliberately pastes one fingerprint.

## Desktop privacy guards

- **Clipboard auto-clear.** A secret on the clipboard (copied from Qalaa, or recognised by shape: private keys, cloud keys, API tokens, JWTs, `.env` lines, long random strings) is wiped after 30 seconds by default, only if the clipboard still holds the same secret (compared by SHA-256). The text is never logged, stored or sent; clients only see its kind and the time left.
- **Credential guardrails.** Qalaa alerts when a program that isn't expected to opens SSH private keys, `.env` files, cloud credentials (`~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, …) or a browser's cookie and password stores. Paths follow SigmaHQ's credential-access rules (DRL 1.1, adapted): also macOS keychains (plus `security dump-keychain` / `find-*-password -w` on the command line), KeePass databases, crypto wallets (Electrum, Exodus, Ethereum keystores, MetaMask's browser storage), Discord and Telegram session tokens, `/etc/shadow`, and Windows saved credentials. One program reading a browser's `Local State` key and its passwords or cookies is raised as a high-priority stealer pattern. A default-allowed name only counts where the person's own programs can't have put it: on Linux the binary and every folder above it must be root-owned and not writable by others; on macOS it must be on a SIP-protected path or carry a valid Apple or Developer ID signature. A program the person allows is pinned by full path and SHA-256, so a changed binary is reported again. The person can pause (SIGSTOP), stop (SIGKILL) or allow the program. Before any signal Qalaa checks that the same program still runs under that process id. Only the file kind, the path with the home folder shortened to `~`, and the program are kept; file contents are never read.
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

- **Email aliases.** A random (10 characters from a look-alike-free alphabet) or chosen address on the operator's relay domain, or on the person's own DNS-verified domain, forwards to the account's verified email. Forwarding is done by the operator's own Postfix (`infrastructure/alias-relay`), which asks `/relay/aliases/resolve` (bearer relay token, compared in constant time, request logs filtered) for one recipient at a time. Qalaa sees addresses and counts, never messages. Paused aliases are refused, and deleted ones become tombstones: refused forever, never issued again, label wiped. Aliases can be created from the website, from the extension's popup (never from a page's content script) and from the desktop app through the linked device. Limits: 200 per person and 30 created per hour.

## API keys and metrics

- **API keys.** Personal keys are 256-bit random values prefixed `snt_`, shown once and stored only as SHA-256 digests. They are revocable and limited to ten per account. Keys authenticate scanning, history and lookups only. Account changes, key management, extension linking and all staff functions require a website session with its CSRF token, so a leaked key cannot take over or escalate an account. Disabling an account stops its keys working immediately.
- **Metrics.** The metrics endpoint is disabled unless `SENTINEL_METRICS_TOKEN` is set. Requests without the right bearer token get the same 404 as an unknown route.

## Mobile web app

- **Service worker.** It caches only the offline notice. Pages, scan results and API responses are never stored on the device.
- **Shared content.** Content shared into Qalaa is placed in the form, not submitted. It travels in the address of a page on this site, so it is visible to this server's access logs if those are enabled.

See also [security-review.md](security-review.md) for the latest self-review.

## Known gaps

- Admin and moderator actions are not yet protected by a second confirmation step.
- There is no encryption at rest beyond what the database volume provides.
- There has been no independent penetration test.
