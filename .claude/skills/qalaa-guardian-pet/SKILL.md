---
name: qalaa-guardian-pet
description: Rules for qalaa-guardian-pet, the native transparent click-through desktop mascot and its security copilot popover (apps/desktop-native/crates/qalaa-guardian-pet). Load when touching its windowing, sprites, state machine or popover.
---

# Qalaa Guardian pet

A toggleable Slint overlay. Off by default; one switch turns it off everywhere.

## Windowing (per platform, behind capability checks)
- Windows: `WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW`; toggle
  `WS_EX_TRANSPARENT` when the cursor leaves the sprite or popover bounds.
- macOS: borderless `NSWindow` at `NSFloatingWindowLevel`, `isOpaque = false`,
  dynamic `ignoresMouseEvents`.
- Linux X11: input shape via `XShapeCombineMask`. Wayland: `wlr-layer-shell`
  input region (KDE, wlroots). GNOME has no layer-shell: fall back to a normal
  always-on-top window and tell the person in the settings, never pretend.
- Multi-monitor aware, snaps to taskbar edges, pauses during fullscreen apps.

## Behaviour
- Pure-Rust state machine, no I/O: `idle`, `patrol`, `sleep`, `scan`,
  `defend`, `alert`, `happy`. Driven by `qalaa-ipc` events (scan started,
  threat blocked, network alert). Alerts outrank everything; sleep after idle.
- Skins: `cyber-owl`, `shield-fox`, `mini-sentinel`. Original art only.
- Popover: compact native card kept inside screen bounds. Questions go to
  Qalaa's local tools; quick actions (VPN, camera/mic lock, SafePay, copy the
  latest TOTP code only after vault unlock, snooze 2 hours) call the daemon.
  It never shows secrets without an unlocked vault and never says "safe".

## Budget and tests
- Under 30 MB RSS and under 1% idle CPU; a Linux CI job measures both.
- Headless state-transition tests, hit-testing geometry tests (point in
  sprite, point in popover, outside both), and popover placement tests at
  screen edges. Windows and macOS code must compile in CI.
