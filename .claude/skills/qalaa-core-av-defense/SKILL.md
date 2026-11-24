---
name: qalaa-core-av-defense
description: Rules for Qalaa's malware detection and response code: desktop scanner, fanotify on-access, ransomware blocking, Controlled Folder Access, signatures, YARA/ClamAV, local ML, file reputation and server-side file analysis. Load when changing apps/desktop/src/engine scanning code or services/api analyzers and intel.
---

# Qalaa core antivirus and defence

## Existing pieces (extend, don't duplicate)
- Scanner and verdicts: `apps/desktop/src/engine/scanner.ts`, `rules.ts`,
  `signatures.ts`, `clamav.ts`, `quarantine.ts`, `formats.ts`, `zip.ts`.
- Linux on-access: `engine/fanotify.ts` + the `onaccessd.py` helper
  (`FAN_OPEN_EXEC_PERM`, `(dev, ino, mtime)` clean cache, fail-open).
- Ransomware: `engine/ransomware.ts`, `behaviour.ts` (entropy bursts, decoys,
  SIGSTOP / NtSuspendProcess with a prompt). Windows protected folders:
  `engine/cfa.ts` (`Set-MpPreference`).
- Server analysis: `services/api/app/analyzers/*` (YARA rules in
  `app/rules/sentinel.yar`), feeds in `app/intel/`.

## Rules
- Detection never deletes. It quarantines (reversible) and explains why, in
  both languages, with the source of the evidence.
- Hash reputation: k-anonymity only (`engine/server.ts lookupHash`, 6-char
  prefix, local compare). Never send a full hash in the background.
- Crowd prevalence (to build): counts keyed by hash only, from an
  unauthenticated route with no device or account identifier; report buckets
  ("seen by fewer than 10 users"), never exact small counts.
- Local ML (to build): small LightGBM/ONNX model over static PE/ELF features
  (section entropy, headers, imports, strings). Weights downloaded with a
  pinned SHA-256 and refused on mismatch. Its verdict is "suspicious" at most;
  only signatures and threat lists say "known malicious".
- YARA-X and ClamAV updates: signed or checksummed differential downloads;
  keep the previous set if verification fails.
- Detonation sandbox (to build): ephemeral container, no egress except a
  logging sink, manual uploads only, hard time and memory limits.
- Everything degrades on unsupported platforms with a stated reason.

## Tests with every detector
- Unit tests with harmless fixtures (EICAR-style strings, crafted headers),
  never live malware in the repo.
- Behaviour detectors: scripted, scoped simulations in CI (decoy edits, burst
  writes in a temp dir, an unexpected listener on a high port), in the spirit
  of Atomic Red Team, inside the test's own temp directory only.
