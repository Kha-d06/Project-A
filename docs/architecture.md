# Architecture

```text
 browser ──HTTPS──▶ Caddy ──▶ web (Next.js) ──/api/v1/*──▶ api (FastAPI) ──▶ PostgreSQL
                                                              │    ▲
                                                     enqueue  ▼    │ results
                                                            Redis ─▶ worker (Celery) ──▶ ClamAV (optional)
                                                              ▲         │
                                                  scheduler ──┘         └──▶ internet: redirect tracing,
                                               (feed sync, retention)        RDAP, URLhaus API (optional)
```

## Request flow for a scan

1. The browser posts to `/api/v1/scans/{url|message|file}` on the web origin.
   `apps/web/src/app/api/v1/[...path]/route.ts` forwards it to the API, so cookies
   stay first-party and the API needs no CORS.
2. The API validates the input, creates a `scan_jobs` row with status `queued`
   (files are first streamed into quarantine storage), enqueues
   `sentinel.run_scan`, and returns `202` with the scan.
3. The worker (`app/scans/runner.py`) marks the job `processing` and runs the
   analyzer for its type. Analyzers return an `Outcome`: findings, the checks
   attempted (with status), technical details and limitations.
4. `app/analyzers/verdict.py` turns the outcome into a risk level, confidence,
   summary and recommendations. The rules are short and explainable:
   - a `critical` finding gives `known_malicious`;
   - any `high` finding, or two `medium` findings, gives `suspicious` (one `medium` gives `suspicious` with low confidence);
   - no findings plus at least one completed *core* check gives `no_known_threat`;
   - anything else is `inconclusive`.
5. The worker stores the result and then deletes the sample and any transient
   input (message text, storage path) whatever the outcome.
6. The browser polls `GET /api/v1/scans/{id}` with backoff until the status is
   terminal.

*Core* checks are reputation sources: the URLhaus feed or live API for links, the
MalwareBazaar feed or ClamAV for files, and the pattern analysis for messages.
Heuristics alone never produce "no known threat" for a link or file.

## Threat intelligence

`app/intel/feeds.py` downloads the URLhaus recent-URL CSV and the MalwareBazaar
recent SHA-256 list hourly (Celery beat), deduplicates them, and stores them in
`threat_indicators` with source, first-seen and last-seen timestamps and a
reference link. Indicators that drop out of a feed expire after 90 days. A feed
older than 48 hours is treated as stale: its matches are still reported as
evidence, but a miss no longer counts as a completed check.

Lookups go through a SHA-256 digest of the normalized value, so long URLs stay
indexable.

## Data model

| Table | Purpose |
| --- | --- |
| `users`, `user_settings`, `sessions` | Accounts; sessions are stored by token digest, with a CSRF token. |
| `scan_jobs`, `findings` | One row per scan; findings are ordered by severity. Check constraints restrict type, status and risk values. |
| `threat_sources`, `threat_indicators` | Feeds with sync health, and their indicators. |
| `audit_events` | Sign-ins, failures and security changes, shown to the user. |

Migrations live in `services/api/alembic`, and CI runs `alembic check` to catch
drift from the models.

## API conventions

- Versioned under `/api/v1`. OpenAPI is served at `/api/v1/docs`.
- Errors always use `{"error": {"code", "message", "details"}}`; validation
  errors list `{field, message}` pairs.
- Mutating requests from a signed-in browser need the `X-CSRF-Token` header,
  whose value comes from `GET /auth/session`.
- Scans without an account are reachable only by their random UUID and are
  deleted after 30 days.

## Frontend

- **Routes.**
  - `(site)` holds the public pages and the anonymous scanner and report.
  - `(auth)` holds sign-in and sign-up.
  - `dashboard` is the signed-in area; its client guard redirects to sign-in.
  - Authorization is always enforced by the API.
- **Data and state.** `lib/api/client.ts` is the only place that talks to the API. `lib/session.tsx` holds the signed-in user, and `lib/risk.ts` is the single source of verdict wording.
- **Components.** `components/ui` holds the primitives, `components/scan` the scanner and report, `components/dashboard` the signed-in screens.
