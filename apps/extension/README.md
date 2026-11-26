# Qalaa Protect

The Qalaa browser extension (Chrome and Microsoft Edge, Manifest V3).

## What it does

- **Page checks.** Checks each page a tab opens, both before navigation and again once it commits, so server-side redirects are covered. Known dangerous sites and convincing imitations are replaced by a warning page; minor warning signs only show on the toolbar badge.
- **Warning page.** Shows the domain, the risk level, the evidence and the source. "Go back to safety" returns to the last page the tab opened without a warning. A proceed option sits behind "I understand the risk" and lasts for the browser session; it is not offered for sites on your own block list.
- **Downloads.** Pauses a download from a known dangerous source, or one with a disguised name, and lets you cancel or keep it.
- **Context menu.** "Scan link with Qalaa" and "Check this page with Qalaa".
- **Pre-load blocking.** Downloads Qalaa's list of known malicious domains (`GET /extension/blocklist`, up to 4,500 domains from ThreatFox and moderator-verified reports; whole-host listings only, never shared hosting) every six hours and installs it as `declarativeNetRequest` block rules, together with your own block list. Listed domains are stopped inside the browser before any request is made, and the warning page is shown instead. "Continue anyway" adds a session-only allow rule for that domain. Your allow list always wins.
- **On-screen assistant (optional, off by default).** A small Qalaa button in the corner of pages:
  - a warning bubble on dangerous or suspicious sites, and a second warning when you click into a password field there;
  - the site's cookies (names, owning domain, first or third party, lifetime; never values) and known advertising and analytics trackers it loaded;
  - questions answered by the server's AI provider (`POST /extension/assistant`, sending only the domain, verdict, warning titles, cookie names and tracker names) or, if none is configured, built-in answers grounded in the same facts.
  Turning it on requests `scripting`, `cookies` and access to web pages.
- **Search-result labels (optional).** On Google, Bing and DuckDuckGo, results with warning signs get a Qalaa label. Clean results are left alone.
- **Tracker blocking (optional).** Blocks about 45 well-known advertising and analytics domains when they load as third parties.
- **Family block lists.** When the linked account applies a family or organisation group's list, those domains are blocked before loading. The warning page names the group and offers no way to proceed.
- **English and Arabic.** Follows the browser's language, or the choice in settings; Arabic is laid out right to left.
- **Hover checks (optional, off by default).** Shows a warning next to dangerous links. Turning it on requests the `scripting` permission and access to web pages.
- **Popup.** Shows protection state, the current site's verdict and when it was checked, recent alerts, pause and resume, a full-scan shortcut, and links to settings and the dashboard.
- **Settings.** Privacy mode (send only domains), allow and block lists, a local alert history, cache clearing, account linking and the server address.

## How it talks to the server

1. **Enrollment.** On install the extension enrolls anonymously (`POST /api/v1/extension/enroll`) and receives a refresh token, stored in `chrome.storage.local`, plus a 15-minute access token, kept in `chrome.storage.session`. No account is needed.
2. **Checks, inside the browser** (`src/lib/local-check.ts`). Look-alike and address rules run locally from the server's own rules file (`services/api/app/rules/url_rules.json`, bundled at build time and refreshed from `GET /extension/url-rules`). Known threats come from `GET /extension/threat-prefixes`, 4-byte SHA-256 prefixes of every listed address and domain, refreshed every 6 hours. On a prefix hit, the extension sends those prefixes plus 3 random ones from the list to `POST /extension/threat-hashes` and compares the full hashes itself. The page address goes to `POST /extension/check-url` only from the right-click menu ("Check on the Qalaa server"). `test/url-rules.test.ts` and the server's `tests/test_url_vectors.py` run the same vectors (`services/api/tests/fixtures/url-vectors.json`).
3. **Linking.** This is optional. A one-time code from the dashboard (Browser protection page) links the extension to an account. Warnings are then recorded only if the user turns that on, and only as domain, verdict and action.
4. **Revocation.** Disconnecting a browser in the dashboard revokes its tokens immediately.

Checks are cached according to the server's `cache_seconds`, deduplicated while in flight and capped at 120 per minute. A 4-second timeout, being offline or a server error gives **Check unavailable**, never a clean result. Local and private-network addresses are never sent.

## Build and install

```bash
npm install
SENTINEL_SERVER=https://your-qalaa.example npm run build   # default http://localhost:8080
```

Then open `chrome://extensions` (or `edge://extensions`), turn on Developer mode, choose **Load unpacked** and select `dist/chrome`.

## Tests

```bash
npm run typecheck && npm test          # unit tests with an in-memory chrome.* fake
npm run test:e2e                       # Chromium + a mock API: pre-load blocking, assistant, Arabic
# End to end in Chromium, against a running stack with test fixtures loaded:
SENTINEL_SERVER=http://localhost:3000 npm run build
SENTINEL_SERVER=http://localhost:3000 node test/e2e.mjs
```

Each run enrolls a new installation, and the API allows 10 enrollments per IP address per hour. On a development machine, clear the counters between many runs with `redis-cli --scan --pattern 'ratelimit:*' | xargs redis-cli del`.

The end-to-end test covers:
- install and enrollment;
- the dangerous-site warning and "Go back to safety";
- the suspicious-site warning and proceeding;
- popup alerts, and pause and resume;
- linking with a code, event sync, and revocation from the dashboard.

`test:e2e` builds a test variant (`SENTINEL_TEST_BUILD=1`) that grants the optional permissions up front, because automated browsers cannot click permission prompts, and leaves the assistant's shadow root open for inspection. Never publish that build.

## Limits

- **Pages can start loading.** Domains on the downloaded blocklist are stopped before loading. For everything else, Manifest V3 extensions cannot hold a navigation while waiting for a network answer, so a dangerous page may begin loading briefly before the warning replaces it.
- **Trackers.** The assistant recognises about 45 well-known tracker domains; it is not a full tracker blocklist.
- **Downloads.** Extensions cannot read downloaded file contents, only the source address and file name. Small files may finish before they can be paused.
- **Context menu and downloads are not covered end to end.** Both rely on browser UI that the automated test cannot reach; their logic is unit-tested.
- **Firefox.** It needs a separate manifest and has not been tested.
- **Store publishing** needs the operator's own Chrome Web Store, Edge Add-ons and Firefox Add-ons developer accounts.
