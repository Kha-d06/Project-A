---
name: qalaa-architecture-guardrails
description: Qalaa's non-negotiable architecture and privacy rules. Load before changing any part of the Qalaa repo (services/api, apps/web, apps/desktop, apps/desktop-native, apps/extension, apps/thunderbird, apps/android) or planning a new feature, detector or view.
---

# Qalaa architecture guardrails

Qalaa is a free, bilingual (English and Arabic) security suite. These rules
override convenience. If a request conflicts with one, say so and propose the
compliant alternative instead of quietly bending the rule.

## Where things live
| Path | What | Checks |
|---|---|---|
| `services/api` | FastAPI, SQLAlchemy, Postgres, Alembic, Celery | `ruff check . && ruff format --check . && mypy app && pytest` |
| `apps/web` | Next.js 16 site, dashboard, PWA (read `node_modules/next/dist/docs` first) | `npm run lint && npm run typecheck && npm test && npm run build` |
| `apps/desktop` | Scanning engine (`src/engine/*.ts`), Electron shell until native parity | `npm run typecheck && npm test && xvfb-run -a node test/e2e.mjs` |
| `apps/desktop-native` | Rust + Slint native UI (`qalaa-ipc`, `qalaa-command`, `qalaa-guardian-pet`) | `cargo test && cargo clippy -- -D warnings` |
| `apps/extension` | Chrome/Firefox MV3 extension | `npm run typecheck && npm test && npm run build` |
| `apps/thunderbird` | Thunderbird MV3 add-on, plain JS, no build | `npm test` |
| `apps/android` | Kotlin app | Gradle |

## Hard rules
1. **No WebViews in new desktop UI.** No Electron, Tauri, CEF, WebView2 or
   WKWebView in `apps/desktop-native`. The Electron shell in `apps/desktop` is
   being retired: add no new views to it. Put logic in `src/engine` or `src/core`
   so the headless daemon can serve it over `qalaa-ipc`.
2. **No kernel drivers on Windows or macOS.** User-space APIs only (Controlled
   Folder Access, privacy settings, `lsof`, `GetExtendedTcpTable`). On Linux,
   fanotify and udev are allowed, through pkexec-installed helpers that fail open.
3. **No paid data brokers or credit bureaus.** Build local, self-hosted or
   guided alternatives (checklists, local parsing).
4. **Zero-knowledge and local-first.**
   - Never send message bodies, headers, addresses or file contents for
     background checks. Email analysis runs on the device
     (`apps/thunderbird/src/lib/analysis.js`); only bare links go to
     `POST /email/links`.
   - File reputation uses k-anonymity: 6 hex characters to
     `GET /intelligence/hash-prefix/{prefix}`, full compare locally.
   - Lookup routes take no account or device token, store nothing, and are
     listed in `services/api/app/core/private_paths.py` so they stay out of
     access logs.
   - Vault, family and remote-command payloads stay end-to-end encrypted.
   - ML inference is local; verify model weights by SHA-256 before loading.
5. **Graceful cross-platform degradation.** OS-specific code sits behind
   runtime capability checks (`platform/linux|windows|macos|android`). An
   unsupported action reports why in plain words; it never fails silently.
6. **Honesty in the product.** Never say "safe", "100%" or "guaranteed". State
   limits next to the feature (for example "covers linked browsers only").

## Every change
- Every new UI view or detector ships with automated tests in the same commit
  (pytest, vitest, node:test, Playwright, Slint testing backend or cargo test).
- Both languages together: English and Arabic strings, RTL checked.
- New dependencies: exact versions released at least two weeks ago; the desktop
  `npm audit --audit-level=high` gate must stay green (never loosen it).
- Database changes: hand-written Alembic migration matching the naming
  convention in `app/models/base.py`; CI runs `alembic upgrade head && alembic check`.
- Site assessment only for verified-owned domains.
- Commit and push only to the session's development branch; no PRs unless asked.
