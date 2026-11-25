# ATT&CK regression atomics

Each atomic does what an attacker would, and the real Qalaa background
service must report it over qalaa-ipc (or, for negative controls, must not).
The files follow [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)'s
schema (MIT); the tests themselves are Qalaa's own, with a `qalaa` block for the
expected event.

```sh
cd apps/desktop && npm run build && cd ../..
python3 tests/attack/run_atomics.py            # everything for this OS
python3 tests/attack/run_atomics.py --only T1571
```

CI runs them on Linux inside `docker run --network none`, and on fresh macOS
and Windows runners. Tests marked `gap` (not detected yet) and `fixture`
(covered by recorded-data tests instead) are listed in the summary, never
counted as passes.

| Technique | Linux | macOS | Windows |
|---|---|---|---|
| T1552.004 Private keys (held open, look-alike `ssh`, public-key negative control) | covered | covered | gap: no credential guard yet |
| T1552.004 Quick `cp` of a key | gap: polling misses it (fanotify every-open mode sees it) | gap | gap |
| T1552.001 Credentials in files (`.env`, cloud) | covered | covered | gap |
| T1555.003 Browser key + passwords (stealer pattern) | covered | — | gap |
| T1555.001 Keychain dump | — | covered while the dump runs; a millisecond dump is a gap (15 s snapshots) | — |
| T1571 New listener | covered | covered | covered |
| T1200 BadUSB | fixture (`apps/desktop/test/attack-t1200.test.ts`) | fixture | fixture |
| T1059.004 Download piped to a shell | covered (programs running ≥ 1 s) | covered (≥ 2 s) | gap: needs ETW (admin service) |
| T1562.004 Firewall switched off | covered (command line only, nothing changed) | covered | gap |
| T1070.003 Shell history cleared | covered by script or file removal; `history -c` typed at a prompt is a gap (built-in, no new program) | same | — |
| T1059.004 A sub-second command | gap: polling; needs the netlink connector (root helper) | gap: needs Endpoint Security | gap |
| T1486 Data encrypted for impact | gap: classic app's fanotify burst detector only | gap | gap |
