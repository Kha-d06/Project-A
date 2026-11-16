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

> **Status: Phases 1–3.** Link, message, file, QR, website and Android app scanning,
> optional AI explanations, accounts, dashboard, history and the SENTINEL Protect
> browser extension work end to end. Community reports, the admin area and the
> Arabic interface are later phases (see [Roadmap](#roadmap)). The code has tests but has not had an
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

**SENTINEL Protect browser extension** (`apps/extension`, Chrome and Edge, Manifest V3):
- warns before known dangerous sites and convincing imitations load, with evidence and a way back;
- pauses risky downloads, adds a right-click "Scan link with SENTINEL", and offers optional hover checks;
- has pause and resume, allow and block lists, and a privacy mode that sends only domains;
- works without an account, enrolling anonymously with short-lived tokens, and can be linked to one with a one-time code;
- reports a check it cannot complete as "Check unavailable", never as clean.

See [apps/extension/README.md](apps/extension/README.md).

**Honesty about providers.** `/api/v1/system/providers` reports which checks this deployment can run. The landing page shows that list live, and every report lists each check as completed, unavailable, failed or skipped.

## Repository layout

```text
apps/web/                 Next.js website and dashboard (App Router, TypeScript, Tailwind)
apps/extension/           SENTINEL Protect browser extension (Manifest V3, TypeScript, esbuild)
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
cp .env.example .env     # set SENTINEL_SECRET_KEY and POSTGRES_PASSWORD
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
| `SENTINEL_OPENAI_API_KEY`, `SENTINEL_OPENAI_MODEL` | no | Optional AI explanations (both required). |
| `SENTINEL_YARA_RULES_DIR` | no | Extra YARA rule files, subject to their licences. |
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
3. **Phase 4.** Threat-intelligence centre, community reports with moderation, admin area, Arabic interface with RTL layout.
4. **Phase 5.** Android app, organisation tools, public API, more browsers and intelligence sources.

See [docs/architecture.md](docs/architecture.md),
[docs/security.md](docs/security.md) and [docs/design.md](docs/design.md).
