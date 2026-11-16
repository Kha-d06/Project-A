# SENTINEL Protect

The SENTINEL browser extension (Chrome and Microsoft Edge, Manifest V3).

## What it does

- **Page checks.** Checks each page a tab opens, both before navigation and again once it commits, so server-side redirects are covered. Known dangerous sites and convincing imitations are replaced by a warning page; minor warning signs only show on the toolbar badge.
- **Warning page.** Shows the domain, the risk level, the evidence and the source. "Go back to safety" returns to the last page the tab opened without a warning. A proceed option sits behind "I understand the risk" and lasts for the browser session; it is not offered for sites on your own block list.
- **Downloads.** Pauses a download from a known dangerous source, or one with a disguised name, and lets you cancel or keep it.
- **Context menu.** "Scan link with SENTINEL" and "Check this page with SENTINEL".
- **Hover checks (optional, off by default).** Shows a warning next to dangerous links. Turning it on requests the `scripting` permission and access to web pages.
- **Popup.** Shows protection state, the current site's verdict and when it was checked, recent alerts, pause and resume, a full-scan shortcut, and links to settings and the dashboard.
- **Settings.** Privacy mode (send only domains), allow and block lists, a local alert history, cache clearing, account linking and the server address.

## How it talks to the server

1. **Enrollment.** On install the extension enrolls anonymously (`POST /api/v1/extension/enroll`) and receives a refresh token, stored in `chrome.storage.local`, plus a 15-minute access token, kept in `chrome.storage.session`. No account is needed.
2. **Checks.** Each check sends the page address, or only the domain in privacy mode, to `POST /extension/check-url`. The server answers from its local threat database and look-alike rules and stores nothing about the request.
3. **Linking.** This is optional. A one-time code from the dashboard (Browser protection page) links the extension to an account. Warnings are then recorded only if the user turns that on, and only as domain, verdict and action.
4. **Revocation.** Disconnecting a browser in the dashboard revokes its tokens immediately.

Checks are cached according to the server's `cache_seconds`, deduplicated while in flight and capped at 120 per minute. A 4-second timeout, being offline or a server error gives **Check unavailable**, never a clean result. Local and private-network addresses are never sent.

## Build and install

```bash
npm install
SENTINEL_SERVER=https://your-sentinel.example npm run build   # default http://localhost:8080
```

Then open `chrome://extensions` (or `edge://extensions`), turn on Developer mode, choose **Load unpacked** and select `dist/chrome`.

## Tests

```bash
npm run typecheck && npm test          # unit tests with an in-memory chrome.* fake
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

## Limits

- **Pages can start loading.** Manifest V3 extensions cannot hold a navigation while waiting for a network answer, so a dangerous page may begin loading briefly before the warning replaces it.
- **Downloads.** Extensions cannot read downloaded file contents, only the source address and file name. Small files may finish before they can be paused.
- **Context menu and downloads are not covered end to end.** Both rely on browser UI that the automated test cannot reach; their logic is unit-tested.
- **Firefox.** It needs a separate manifest and has not been tested.
