# SENTINEL

SENTINEL helps people check links, messages and files before trusting them, and
explains what it found in plain language. It is free for everyone: there are no
paid plans, trials or locked features.

Every result is one of four verdicts, used consistently in the API and the UI:

| Verdict | Meaning |
| --- | --- |
| **Known threat** | Threat intelligence or a malware signature identifies it. |
| **Suspicious** | Warning signs were found; nothing confirms it is malicious. |
| **No known threat detected** | Checks completed without finding known indicators. Not a guarantee. |
| **Inconclusive** | A check the verdict depends on could not run. |

Nothing is ever reported as "safe".

> **Status: Phases 1–5.** Scanning (links, messages, files, QR codes, websites and
> Android apps), optional AI explanations, accounts, the dashboard, the SENTINEL
> Protect browser extension, threat-intelligence lookups, community reports with
> moderation, the admin area, an Arabic interface, an installable mobile web app,
> personal API keys and Prometheus metrics all work end to end. A native Android
> app and organisation accounts are not built; see [Roadmap](#roadmap). The code has tests but has not had an
> independent security review, so it is not yet production-ready.

## What works today

**Link scanner.** For a submitted URL, SENTINEL:

- matches it against the URLhaus feed, which is downloaded and checked locally so the link is never shared;
- optionally runs a live URLhaus lookup, if a key is configured;
- follows its redirect chain from the server behind SSRF protections, reading headers only;
- reads the TLS certificate and the domain's registration date (RDAP);
- looks for look-alike and homograph domains, brand impersonation, IP-address hosts, hidden `@` destinations, shorteners and direct program downloads.

**Message scanner.** Detects ten scam techniques in English and Arabic: credential and OTP requests, account threats, delivery fees, prizes, job and investment scams, irreversible payment methods, requests for personal data, urgency, and moves to private chat apps. It also extracts links, email addresses and phone numbers, and checks the links' addresses. Message text is discarded after analysis.

**File scanner.** Identifies the file type from its content and checks:

- extension mismatches and double extensions such as `invoice.pdf.exe`;
- Office macros, PDF JavaScript, launch actions and embedded files;
- download-and-execute and encoded-command patterns in scripts;
- archive bombs, path traversal and executables inside archives;
- the EICAR test file, the SHA-256 against the MalwareBazaar feed, and ClamAV, if configured.

Files are never opened or executed, and they are deleted when the scan finishes.

**Accounts and history.** These are optional, since every scanner works without signing up. Accounts provide:

- registration, sign-in and sign-out with Argon2 hashing, HttpOnly cookies, CSRF tokens and rate limits;
- a dashboard with an overview and a filterable history;
- per-scan deletion and a JSON report download;
- settings to switch history off, export all data, change the password (other sessions are signed out) and delete the account.

**QR scanner.** Decodes a QR code from a photo (zxing-cpp) without opening it.
- Links get the full link analysis, run from the server.
- Payment codes (UPI, EMV merchant codes, cryptocurrency) show who would be paid; crypto requests are flagged.
- Open Wi-Fi networks are noted.
- Decompression bombs are refused.

**Website analyzer.** Everything the link scanner does, plus DNS records (A, AAAA, MX, NS, TXT) and a static reading of up to 2 MB of the page's HTML through the same SSRF-protected fetcher. Scripts never run. It flags:
- sign-in or payment pages that use another brand's name or images;
- forms posting to other sites or over http;
- free-hosting phishing patterns, obfuscated scripts, crypto-miners and hidden frames.

It also reports which security headers are present.

**Android app analyzer.** Static analysis of APKs up to 100 MB:
- **Manifest:** package, SDK levels, permissions with plain-language meanings, and exported components;
- **Permission patterns:** banking-trojan combinations (accessibility plus overlay, SMS plus internet, device admin, installing apps);
- **Impersonation:** apps named like a well-known brand but not its official package;
- **Code:** hosts embedded in the code, checked against threat intelligence, plus known SDKs and debug signing;
- **Shared checks:** YARA, hash reputation and ClamAV, plus an optional self-hosted MobSF.

The app is never installed or run.

**More file analysis.**
- YARA, with SENTINEL's own rules plus optional operator rules: encoded PowerShell, download-and-execute, HTML smuggling, malicious shortcuts, credential-dumping tools, ransom notes and packers.
- olevba macro analysis (auto-run plus risky functions, Excel 4 macros, embedded indicators).
- pefile capability analysis of Windows programs (injection, keylogging, mass encryption, packing, signature presence).

**AI explanations (optional).** When `SENTINEL_OPENAI_API_KEY` and `SENTINEL_OPENAI_MODEL` are set, a user can ask for a plain-language explanation of a finished scan.
- Only the verdict and finding summaries are sent, never message text, files, evidence values or full links.
- The output is labelled as AI-written, has links stripped, and is cached on the scan.
- Without configuration the option is not shown, and everything else works as before.

**Threat intelligence lookup.** A public lookup for domains, IP addresses and SHA-256 fingerprints, at `/intelligence` and `GET /api/v1/intelligence/{domain|ip|hash}/…`. Each match shows its source, threat type and first and last seen dates. A miss counts only if the feed is fresh; otherwise the answer is "unavailable".

**Community reports and moderation.** Anyone can report a scam website, message, job offer, app, phone number or social account at `/report`.
- **Anonymous by choice.** Anonymous reports get a private tracking link, and reporters are never shown publicly.
- **Duplicates are counted** across all reports.
- **Moderated before use.** Moderators review the queue. Only verified reports are published, and then only the category and subject, with phone numbers masked.
- **Fed back into scans.** Verified websites and phone numbers feed into link, message and extension checks as strong warnings ("Suspicious"), never as "Known threat", because they rest on reports rather than catalogued malware evidence.

**Administration** (admin role, enforced by the API):
- **Health:** service health, scan workers and queue depth, stuck and failed jobs, and feed health with a manual sync.
- **Accounts:** role changes and disabling an account (which signs it out everywhere).
- **Monitoring:** rate-limit rejections per limit, and the audit log.
- **Privacy:** job monitoring never shows what people scanned.

The first administrator is created with `python -m app.cli set-role you@example.com admin`.

**Arabic interface.** The site is available in English and Arabic.
- **Language choice.** It follows the browser's language until the visitor picks one with the language switch.
- **Layout.** Arabic gets a proper right-to-left layout: direction-aware spacing, mirrored arrows and tab keys, an Arabic typeface, and addresses and hashes kept left to right.
- **Scope of translation.** Navigation, the home page, all scanners, reports, sign-in, the dashboard, intelligence lookup and community reporting are translated. Scans submitted from an Arabic page get Arabic verdict summaries and advice, and the scam-pattern findings are written in Arabic too.
- **Still English.** Other technical findings, the long policy pages, the browser extension and the staff tools are in English for now. Arabic pages say so rather than half-translating.
- **Extending it.** Dictionaries are typed (`apps/web/src/lib/i18n`), so a new language has to supply every string.

**On phones.** SENTINEL is an installable web app.
- **Share target.** On Android, installing it adds SENTINEL to the system share sheet. Sharing a link or a message from any app opens the matching scanner with it filled in, and nothing is submitted until you confirm.
- **QR camera.** The QR scanner opens the rear camera directly.
- **Offline.** A minimal service worker shows an offline notice ("nothing has been checked") and caches nothing else.

There is no native Android app. Building one needs the Android SDK, which was not available, and the web app covers the main mobile flows.

**Public API.** Every endpoint is documented at `/api/v1/docs` and `/docs`.
- **Personal keys.** Keys (`Authorization: Bearer snt_…`) let scripts scan and read their owner's history.
- **Kept away from account actions.** Keys cannot reach account settings, key management or staff functions. Those always need a website session.

**Threat feeds.** URLhaus, ThreatFox and MalwareBazaar (all abuse.ch, CC0) are synchronised hourly. Any fresh feed can back a link, file or extension verdict. If abuse.ch requires an Auth-Key for downloads, set `SENTINEL_URLHAUS_AUTH_KEY`, which is sent with feed requests too.

**Monitoring.** With `SENTINEL_METRICS_TOKEN` set, `/api/v1/system/metrics` serves Prometheus metrics:
- scans in the last 24 hours by type and status, and stuck scans;
- feed age and size;
- pending reports, users and extension installations.

`docker compose --profile monitoring up` runs Prometheus with alert rules for stale feeds, stuck scans and failure spikes.

**SENTINEL Protect browser extension** (`apps/extension`, Chrome and Edge, Manifest V3):
- warns before known dangerous sites and convincing imitations load, with evidence and a way back;
- pauses risky downloads, adds a right-click "Scan link with SENTINEL", and offers optional hover checks;
- has pause and resume, allow and block lists, and a privacy mode that sends only domains;
- works without an account, enrolling anonymously with short-lived tokens, and can be linked to one with a one-time code;
- reports a check it cannot complete as "Check unavailable", never as clean.

See [apps/extension/README.md](apps/extension/README.md).

**SENTINEL Desktop** (`apps/desktop`, Electron, Windows, macOS and Linux): on-demand file and folder scanning, a Downloads watcher, encrypted quarantine with restore, and English and Arabic. Engines:
- known-malware fingerprints from the server's hash list;
- heuristics for disguised programs, droppers, risky PDFs, macros and archives;
- ClamAV when installed;
- optional fingerprint lookups and full server scans.

It complements, and does not replace, the operating system's own protection. See [apps/desktop/README.md](apps/desktop/README.md).

**Visual phishing detection.** With isolated rendering on, website scans compare each page's first screen with stored fingerprints (64-bit difference hashes) of real sign-in pages. A near-identical page on someone else's domain is flagged. No images are stored, only hashes. Add references with:

```bash
python -m app.cli add-brand-reference emiratesnbd emiratesnbd.com https://<the brand's real sign-in page>
```

**Devices and remote scans.** Link SENTINEL Desktop (and the Android app) to an account with a one-time code. Dashboard → Devices then shows each device's protection status. If the device allows it, you can start a quick, full or folder scan, quarantine what was found, or update signatures from any browser.

**Password manager.** Dashboard → Passwords is an end-to-end encrypted vault. It is encrypted in the browser with a master password the server never sees. It includes a generator, a health report (reused, weak, old and breached passwords) and CSV import/export.

**Website security assessment.** An admin-enabled feature (Dashboard → Site assessment) that runs read-only security checks — TLS, security headers, cookie flags, exposed files, SPF/DMARC — against websites the account has **verified it owns**. Ownership is re-checked at scan time, and unverified domains are refused. See [docs/assessment.md](docs/assessment.md).

**VPN.** An optional self-hosted WireGuard server (`docker compose --profile vpn`). Devices are added from Dashboard → VPN with keys made in the browser. See [docs/vpn.md](docs/vpn.md).

**Android.** `apps/android` is a Trusted Web Activity for Google Play. See [apps/android/README.md](apps/android/README.md).

**Try it on your laptop.** `./scripts/demo.sh` starts everything in Docker and creates an administrator account. See [TESTING.md](TESTING.md).

**Operations.** Backups, restore, upgrades, alerts, capacity and key rotation are covered in [docs/operations.md](docs/operations.md).

**Integrations:** Telegram and WhatsApp bots, scan-by-email, signed webhooks and a bulk API. See [docs/integrations.md](docs/integrations.md).

**Honesty about providers.** `/api/v1/system/providers` reports which checks this deployment can run. The landing page shows that list live, and every report lists each check as completed, unavailable, failed or skipped.

## Repository layout

```text
apps/web/                 Next.js website and dashboard (App Router, TypeScript, Tailwind)
apps/extension/           SENTINEL Protect browser extension (Manifest V3, TypeScript, esbuild)
apps/desktop/             SENTINEL Desktop scanner (Electron, TypeScript)
services/api/             FastAPI service, Celery worker and scheduler (one Python package)
  app/analyzers/          URL, message and file analysis, verdict rules, SSRF-safe fetcher
  app/intel/              Threat-feed import, indicator lookup, provider adapters
  app/api/                HTTP routes        app/models/  SQLAlchemy models
  alembic/                Database migrations
infrastructure/caddy/     Reverse proxy and TLS configuration
docs/                     Architecture, security and design notes; the original project brief
```

## Running locally

### With Docker Compose

```bash
./scripts/up.sh          # creates .env with random secrets the first time, builds, starts and waits
# or by hand:
cp .env.example .env     # set SENTINEL_SECRET_KEY, POSTGRES_PASSWORD, WORKER_DB_PASSWORD, WORKER_SECRET_KEY
docker compose up --build
# optional: add ClamAV (needs about 1 GB of RAM and a few minutes to load signatures)
#   set SENTINEL_CLAMAV_HOST=clamav in .env, then: docker compose --profile clamav up --build
```

Open <http://localhost:8080>. The scheduler downloads the threat feeds within an
hour. To load them immediately:

```bash
docker compose exec api python -m app.cli sync-feeds
```

Until a feed has synchronised, link and file scans come back **inconclusive**.
That is deliberate: without a reputation source, a clean result would mean nothing.

> The Compose file was validated with `docker compose config`, but the stack has
> not yet been started under Docker. The same services were run and tested
> directly on the host (see below).

### Without Docker

You need Python 3.12+, Node 22, PostgreSQL 16 and Redis.

```bash
# API
cd services/api
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
export SENTINEL_DATABASE_URL=postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel
export SENTINEL_UPLOAD_DIR=$PWD/.uploads SENTINEL_SESSION_COOKIE_SECURE=false
.venv/bin/alembic upgrade head
.venv/bin/python -m app.cli sync-feeds          # needs internet access
.venv/bin/uvicorn app.main:app --port 8000      # terminal 1
.venv/bin/celery -A app.workers.celery_app worker --loglevel=INFO   # terminal 2

# Web (terminal 3)
cd apps/web && npm install && npm run dev       # http://localhost:3000
```

No internet access? `python -m app.cli load-test-fixtures` loads two indicators on
reserved `example.net` domains, labelled "Development test fixtures (not real
threat data)". They let you see a **Known threat** result for
`http://malware.example.net/payload.exe`. They never count as a reputation check,
so real links still come back inconclusive. The command refuses to run when
`SENTINEL_ENVIRONMENT=production`.

## Configuration

All settings use the `SENTINEL_` prefix. See [`.env.example`](.env.example) and
`services/api/app/core/config.py`.

| Variable | Required | Purpose |
| --- | --- | --- |
| `SENTINEL_SECRET_KEY` | yes | Unique secret; production refuses the default. |
| `SENTINEL_DATABASE_URL`, `SENTINEL_REDIS_URL` | yes | Set by Compose. |
| `SENTINEL_SESSION_COOKIE_SECURE` | prod | `true` whenever served over HTTPS. |
| `SENTINEL_SITE_ADDRESS` | prod | Public domain for Caddy's automatic TLS. |
| `SENTINEL_URLHAUS_AUTH_KEY` | no | Live URLhaus lookups (free key from abuse.ch). Sends submitted links to abuse.ch. |
| `SENTINEL_CLAMAV_HOST` | no | clamd host for antivirus signatures. |
| `SENTINEL_MOBSF_URL`, `SENTINEL_MOBSF_API_KEY` | no | Self-hosted MobSF for deeper APK analysis. |
| `SENTINEL_OPENAI_API_KEY`, `SENTINEL_OPENAI_MODEL` | no | Optional AI explanations and the opt-in AI message opinion (both required). |
| `SENTINEL_WEB_RISK_API_KEY` | no | Google Web Risk link reputation. Sends submitted links to Google. |
| `SENTINEL_VIRUSTOTAL_API_KEY` | no | VirusTotal fingerprint lookups, only when the user ticks the consent box. |
| `SENTINEL_HIBP_API_KEY` | no | Have I Been Pwned check of the user's own address. |
| `SENTINEL_TELEGRAM_*`, `SENTINEL_WHATSAPP_*` | no | Messaging bots; see [docs/integrations.md](docs/integrations.md). |
| `SENTINEL_INBOUND_EMAIL_TOKEN`, `SENTINEL_INBOUND_EMAIL_ADDRESS` | no | Scan by forwarding an email. |
| `SENTINEL_VPN_ENDPOINT`, `SENTINEL_VPN_SYNC_TOKEN` | no | Optional WireGuard VPN; see [docs/vpn.md](docs/vpn.md). |
| `WORKER_SECRET_KEY` | yes | Separate secret for the isolated scan worker. |
| `SENTINEL_BROWSER_RENDERING` | no | `true` to render pages in the isolated headless browser (image built with `WITH_BROWSER=true`). |
| `SENTINEL_YARA_RULES_DIR` | no | Extra YARA rule files, subject to their licences. |
| `SENTINEL_METRICS_TOKEN` | no | Enables the Prometheus metrics endpoint. |
| `NEXT_PUBLIC_CONTACT_URL` | no | Operator contact shown on the About page. |

### External services

| Provider | Credentials | Works out of the box |
| --- | --- | --- |
| URLhaus and MalwareBazaar feeds (abuse.ch, CC0) | none | Yes, with outbound internet access |
| RDAP domain registration (rdap.org) | none | Yes |
| URLhaus live API | free Auth-Key | No, reported as not configured |
| ClamAV | none (self-hosted) | Via the `clamav` Compose profile |

Email verification and password reset need an email delivery service, which is
not implemented yet. The settings page says so instead of pretending to send
email.

## Tests and checks

```bash
cd services/api && .venv/bin/ruff check . && .venv/bin/mypy app && .venv/bin/pytest
cd apps/web && npm run lint && npm run typecheck && npm test && npm run build
```

- **API: 103 tests.** Auth and CSRF, rate limiting, every verdict path, SSRF (private, metadata and rebinding addresses, redirect loops and limits, redirects to internal hosts), upload limits, archive bombs, path traversal, macros, PDF actions, ClamAV via a stand-in daemon, feed parsing and expiry, history privacy between accounts, export and deletion.
- **Web: 33 tests.** Verdict wording (never "safe"), the API client, form validation, every report state (scanning, known threat, no known threat, inconclusive, failed, missing), untrusted evidence rendered as text, and open-redirect protection after sign-in.

CI runs all of this plus migrations against PostgreSQL, `alembic check`,
`pip-audit` and `npm audit` (`.github/workflows/ci.yml`).

## Roadmap

1. **Phase 2 (done).** SENTINEL Protect browser extension.
2. **Phase 3 (done).** QR, website and APK analysis, YARA, macro and executable analysis, AI explanations. Download reputation checks shipped with the extension.
3. **Phase 4 (done).** Threat-intelligence lookups, community reports with moderation, admin area, Arabic interface.
4. **Phase 5 (done, with gaps).**
   - **Built:** installable mobile web app with a share target, public API keys, the ThreatFox feed, Prometheus metrics and alerts, and a Firefox build of the extension (experimental, not yet tested in Firefox).
   - **Not built:** a native Android app (the web app covers sharing and QR scanning on Android) and organisation accounts (marked "if needed later").

**Still to do:**
- **Email:** verification, password reset and two-factor sign-in, which need an email service.
- **Arabic:** translated technical findings, policy pages and extension.
- **Data-store hardening:** a separate least-privilege database role for scan workers.
- **Review:** an independent security review before production use.

See [docs/architecture.md](docs/architecture.md),
[docs/security.md](docs/security.md) and [docs/design.md](docs/design.md).
