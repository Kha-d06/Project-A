---
name: qalaa-network-vpn-hardware
description: Rules for Qalaa's network, VPN and hardware defences - home network scanner, listening-port alerts, safe DNS, WireGuard kill switch and split tunnelling, USB and BadUSB gatekeeper, camera/mic locks, firmware and OS posture. Load when touching apps/desktop/src/engine/network, vpn*.ts, privacy-block.ts, posture.ts, protection.ts or services/api VPN code.
---

# Qalaa network, VPN and hardware

## Existing pieces
- Home network: `apps/desktop/src/engine/network/` (ARP/mDNS/SSDP discovery,
  ports, UPnP, default-credential check only with explicit consent), scheduled
  rescans with diff alerts.
- VPN: `engine/vpn.ts`, `vpn-guard.ts` (nftables kill switch, split tunnelling,
  auto-connect on untrusted Wi-Fi); server side in `services/api` and
  `infrastructure/vpn`. See `docs/vpn.md`.
- Camera and microphone: `engine/privacy-block.ts` (Linux udev, Windows
  privacy consent keys).
- Removable drives: `engine/protection.ts` `RemovableWatcher`.
- Posture: `engine/posture.ts`, `security.ts` (listening ports, startup items).

## Rules
- Only scan networks and devices the person owns or manages; say so in the
  UI. Credential checks need a per-device tick box.
- Privileged changes (nftables, udev, firewall rules) go through pkexec or the
  OS consent prompt, show the exact change, and are reversible from the app.
- Listening-port alerts (to build): poll `ss`/`/proc/net` on Linux,
  `GetExtendedTcpTable` on Windows, `lsof` on macOS; alert on new listeners by
  program; offer a one-click block rule (nftables/ufw, `netsh`, `pf`).
- BadUSB (to build): alert when a new HID keyboard appears (udev on Linux,
  `WM_DEVICECHANGE` on Windows, IOKit/DiskArbitration on macOS); never block
  input devices automatically.
- Safe DNS (to build): local resolver forwarding over DoH, with threat and
  optional tracker lists; easy off switch; never break captive portals.
- Posture (to build): Secure Boot, TPM 2.0, full-disk encryption, patch age.
  Read-only checks with "how to fix" text; unknown is reported as unknown.

## Tests
Parsers for every OS command output get fixture tests; firewall and udev rule
generators get exact-output tests; e2e covers the panel states.
