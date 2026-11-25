# Qalaa native desktop

The native replacement for the Electron interface in `apps/desktop`. No browser
engine: Rust and [Slint](https://slint.dev) (royalty-free licence; the About
page shows the "Made with Slint" credit it requires).

```
crates/qalaa-ipc       client for qalaa-ipc, the local protocol to the background service
crates/qalaa-command   the command centre window: Home, Scan, Quarantine, Protection, Security posture, Privacy,
                       Email, Browsing check, Home network, VPN,
                       Ports, Credentials, Behaviour, Brokers, About (the rest of the classic views are being ported)
crates/qalaa-guardian-pet   Qalaa Guardian, the optional desktop mascot with quick actions
```

## How it fits together

The scanning engine stays in TypeScript (`apps/desktop/src/engine`). It runs as
a headless background service, `apps/desktop/dist/daemon.js`, which serves
`apps/desktop/src/core` over a Unix socket (mode 0600) or a per-user Windows
named pipe. Clients say `hello` with a token from a file only the user can read.
While the classic Electron app runs it serves the same methods itself, so the
native window works with either; only one of them ever runs.

`crates/qalaa-ipc/tests/fixtures/home.json` is written from the TypeScript Home
model and decoded by the Rust tests, so the two sides can't drift apart.

## Run it

```
cd apps/desktop && npm run build && node dist/daemon.js   # the background service
cd apps/desktop-native && cargo run -p qalaa-command       # the window
cargo run -p qalaa-command -- --lang ar                    # Arabic, right to left
```

Linux needs `libfontconfig1-dev libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev` to build.

## Checks

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

`tests/ui.rs` drives the real interface headlessly through Slint's testing
backend and finds elements by their accessible labels, as a screen reader does.

## Qalaa Guardian

`cargo run -p qalaa-guardian-pet -- --skin cyber-owl` (also `shield-fox`,
`mini-sentinel`; `--lang ar`). It only runs when started; nothing launches it
by default.

- A frameless, always-on-top window exactly the size of the pet (plus the card
  when open), resting above the taskbar in the corner of the current monitor.
- Click-through over its transparent margins via winit's `set_cursor_hittest`:
  `WS_EX_TRANSPARENT` on Windows, `ignoresMouseEvents` on macOS, the X11 input
  shape or Wayland input region on Linux. Hidden from the Windows taskbar.
- Wayland: runs through XWayland when it's there (always-on-top works on GNOME,
  KDE and wlroots that way). Without XWayland it opens as a normal window and
  the card says so.
- Moods come from the service's events (`scan.started`, `scan.finished`,
  `threat.blocked`, `alert`) through a pure state machine (`src/mood.rs`) that
  reports its next deadline, so no timer runs while nothing is happening.
- Budget, checked in CI by `scripts/pet-budget.sh`: under 30 MB resident and
  under 1% CPU over 20 idle seconds (measured here: 14.6 MB, 0.00%).

## Not done yet

- Guardian: no native wlr-layer-shell surface yet (XWayland covers it); the
  work area is assumed (a 48 px taskbar band) rather than read from the OS; it
  doesn't yet pause for fullscreen apps; drag-to-move with edge snapping exists
  as tested geometry but isn't wired to dragging; the ask box and the VPN,
  camera/mic, SafePay and TOTP actions wait for those service methods.

- Only Home and About are native. Actions that open other views say they are
  still in the classic app.
- Fonts: the window asks for IBM Plex Sans and falls back to the system font;
  the font files are not bundled yet. Tabular numerals are not set yet.
- Right-to-left: alignment and the order of the main regions are mirrored by
  hand (Slint has no layout direction yet); the score ring still fills clockwise.
