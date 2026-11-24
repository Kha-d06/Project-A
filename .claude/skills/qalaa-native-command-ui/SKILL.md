---
name: qalaa-native-command-ui
description: Rules for Qalaa's native desktop command centre (apps/desktop-native, Rust + Slint) and the headless daemon it talks to. Load when building or changing any native desktop view, the qalaa-ipc protocol, or apps/desktop/src/core and daemon.ts.
---

# Qalaa native command centre

## Shape
- `apps/desktop/src/daemon.ts`: headless Node service (no Electron import),
  packaged as a Node single executable. It serves `src/core/*` handlers.
- `apps/desktop-native/crates/qalaa-ipc`: shared message types (serde). JSON
  over a Unix domain socket (`$XDG_RUNTIME_DIR/qalaa/daemon.sock`, mode 0600)
  or a Windows named pipe restricted to the user's SID. A random token in a
  user-only file authenticates the client. Every request has an `id`; events
  are pushed with `event` names matching the existing Electron channels.
- `apps/desktop-native/crates/qalaa-command`: Slint UI. View models are plain
  Rust structs, testable without a window.
- Electron and the daemon share `src/core` until parity; then Electron goes.

## Design tokens (both themes, one source: `ui/tokens.slint`)
- Dark: base `#0B0F17`, elevated `#131A26`. Light: base `#F8FAFC`, cards `#FFFFFF`.
- Semantic only: Emerald `#10B981` protected, Amber `#F59E0B` attention,
  Crimson `#EF4444` blocked, Cobalt `#3B82F6` active scan or VPN. Never use
  them decoratively.
- Tabular numerals for every count, time and percentage.
- One elevation method (border or surface step, not both). No glows or
  gradients. Motion: ease-out `cubic-bezier(0.23,1,0.32,1)`; press scale 0.97
  over 160 ms; reduced motion means fade instead of movement.
- Icons from Lucide (2 px stroke) as SVG assets.
- Default density is calm cards; forensic detail lives in collapsible
  Inspector drawers.

## Views
Home (posture ring with per-check freshness, action queue, quick-toggle dock,
Guardian controls), LAN topology canvas, threat timeline (virtualised), vault
and privacy hub, family, utilities treemap, business compliance, and a global
`Ctrl/Cmd+K` command palette.

## Must
- Accessibility through Slint's AccessKit integration: every control has an
  accessible name and role; custom canvases expose their items.
- English and Arabic with full RTL mirroring; IBM Plex Sans + IBM Plex Sans
  Arabic, matching the web.
- "Made with Slint" credit in About (royalty-free licence requirement).
- Tests with each view: view-model unit tests, Slint testing-backend UI tests,
  `cargo clippy -- -D warnings`, and Vitest contract tests for each IPC method
  the view uses.
