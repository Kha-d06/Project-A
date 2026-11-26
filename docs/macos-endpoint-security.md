# macOS Endpoint Security: future milestone

**Status: not started, and not blocking.** On macOS, Qalaa is a companion to
Apple's built-in protection (XProtect, Gatekeeper, notarisation), as it is to
Defender on Windows (audit QA-15, QA-16).
- **What works today:** on-demand and scheduled scans, the ransomware watch on chosen folders (polling), posture checks, Safe DNS and `ps`-based process polling.
- **What only Endpoint Security would add:** blocking a program *before* it runs, and seeing every process start, including short-lived ones.

No critical capability that Qalaa promises depends on it, so it stays a planned milestone.

## What it would give

- **`ES_EVENT_TYPE_AUTH_EXEC`**: allow or deny a program before it starts. This would bring the behaviour rules and scan verdicts to macOS in real time.
- **`AUTH_OPEN` / `NOTIFY_WRITE` / `NOTIFY_RENAME`**: ransomware detection on file events instead of polling.
- **`NOTIFY_EXEC`, `FORK`, `EXIT`**: a complete process tree for the behaviour rules, with no polling gaps.
- Signing identity (`es_process_t.team_id`, `signing_id`) for every process, which also helps the same-user IPC check (audit QA-11).

## Architecture

```
Qalaa Desktop.app (user)                         System Extension (root, launched by macOS)
 └─ Contents/Library/SystemExtensions/
     app.qalaa.desktop.es.systemextension  ──►   ES client: es_new_client, es_subscribe
                                                 ├─ AUTH_EXEC decision: cache → rules → allow/deny (deadline!)
                                                 └─ XPC Mach service app.qalaa.desktop.es
 daemon (user) ◄──────── XPC, peer checked by code-signing requirement (team id + bundle id) ───┘
```

- **Language:** the ES API is C. Write the extension in Swift or Rust (FFI to `libEndpointSecurity`), keep it small, and have it make no network calls.
- **Deadlines:** AUTH events have a hard deadline, and missing it gets the client killed. Decide from a local cache and allow-by-default when unsure; never wait on a scan or the network. Mute Qalaa's own processes and common system paths.
- **XPC peer check:** accept connections only from processes whose code signature satisfies `anchor apple generic and certificate leaf[subject.OU] = "<TEAMID>" and identifier "app.qalaa.desktop"`. Check the audit token, not the PID.
- **Fail-safe:** if the extension crashes or is disabled, the rest of Qalaa keeps working, and the interface says real-time blocking is off.
- **Guardrails:** a system extension runs in user space (no kernel extension), consistent with "no kernel drivers on macOS".

## Approval process

1. **Developer ID** and notarisation working first ([code-signing.md](code-signing.md)).
2. **Request the entitlement** `com.apple.developer.endpoint-security.client` through Apple's Endpoint Security entitlement request form (Apple Developer → Contact → Request entitlement). Explain the security purpose, the events needed and how decisions are made locally. Apple reviews manually; it can take weeks and may ask questions.
3. Once granted, create a **Developer ID provisioning profile** for the extension's bundle id that includes the entitlement, and embed it.
4. The app requests activation with `OSSystemExtensionRequest`. The person approves it in **System Settings → General → Login Items & Extensions** (Ventura and later).
5. The extension also needs **Full Disk Access**, granted by the person in System Settings → Privacy & Security.
6. Notarise the app with the extension inside.
7. **Organisations:** MDM can pre-approve the extension (`SystemExtensions` payload with the team id) and grant Full Disk Access (a PPPC payload). Document both for enterprise deployment.

## Testing plan (when started)

- A test macOS VM with SIP **on**. Development builds use a dev-signed extension with SIP temporarily off, but every release test runs with SIP on.
- Cases:
  - `AUTH_EXEC` deny for a test sample flagged by the rules;
  - allow within the deadline under load (compile a large project while running);
  - the extension killed → the app reports real-time protection off;
  - XPC from an unsigned client refused.
