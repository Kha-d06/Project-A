# Qalaa native desktop

The native replacement for the Electron interface in `apps/desktop`. No browser
engine: Rust and [Slint](https://slint.dev) (royalty-free licence; the About
page shows the "Made with Slint" credit it requires).

```
crates/qalaa-ipc       client for qalaa-ipc, the local protocol to the background service
crates/qalaa-command   the command centre window (Home today; more views to come)
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

## Not done yet

- Only Home and About are native. Actions that open other views say they are
  still in the classic app.
- Fonts: the window asks for IBM Plex Sans and falls back to the system font;
  the font files are not bundled yet. Tabular numerals are not set yet.
- Right-to-left: alignment and the order of the main regions are mirrored by
  hand (Slint has no layout direction yet); the score ring still fills clockwise.
