# Windows pipe-squatting test (audit QA-05)

## What changed

On Windows the background service listens on `\\.\pipe\qalaa-daemon-<USERNAME>`.
Pipe names are global, so **another Windows user** can create that pipe before
the service starts.

Before the fix, the native app (`qalaa-command`) connected to whatever answered
and sent its `hello` with the token from the token file. Now `qalaa-ipc` calls
`check_pipe_server` (`apps/desktop-native/crates/qalaa-ipc/src/client.rs`)
after opening the pipe and **before writing anything**. It:

1. asks Windows which process serves the pipe (`GetNamedPipeServerProcessId`);
2. opens that process for a limited query and reads its token's user SID;
3. compares it with its own user SID.

Any difference, or a server it can't inspect, means it disconnects without
sending a byte and reports "the program serving the Qalaa pipe belongs to another user".

Compile-checked and clippy-clean for `x86_64-pc-windows-msvc` in CI-like
conditions. **Not yet run on Windows**: that is what this procedure is for.

## What has to be verified

| # | Behaviour | Pass when |
|---|---|---|
| V1 | Normal use still works | The app connects to the real service and shows Home |
| V2 | **A pipe made by another user gets no token** | `squat.ps1` logs `client sent 0 bytes; hello with token: False`, and the app shows the "another user" error |
| V3 | An elevated service of the same user is accepted | The app connects when the service runs "as administrator" by the same account |
| V4 | Known limit, same user | A squatter running as the *same* user is accepted (one user can't be told from itself; audit QA-11). Record the result; it isn't a failure |
| V5 | Service side, unchanged | With a squatter present, the service refuses to start ("already running"). This is a denial of service, not a token leak. Record it for the service-side follow-up |
| V6 | No second instance | While the real service runs, `squat.ps1` as the other user fails with access denied |

## Setup (a disposable VM)

1. Windows 10 22H2 or Windows 11, fully updated, not joined to a domain, used for nothing else.
2. Two **standard** (non-admin) local accounts, `victim` and `attacker`, plus your admin account.
3. Build or download, from this commit:
   - the desktop service (`apps/desktop`, `npm ci && npm run build`, then `node dist/daemon.js`);
   - the native app (`apps/desktop-native`, `cargo build --release -p qalaa-command`).
4. Copy `tools/windows-pipe-test/squat.ps1` to `C:\test\` (readable by both accounts).
5. Use only the test accounts' own data. The script logs byte counts, never the bytes, but treat the VM as disposable anyway.

## Procedure

Run each step with a fresh sign-in, and note the results in the table above.

1. **V1, baseline.**
   - Sign in as `victim`.
   - Start the service (`node dist\daemon.js`), then `qalaa-command.exe`.
   - Expect Home to load.
   - Quit both.
2. **V2, squatter from another user.**
   - Leave `victim` signed in with the service *stopped*.
   - Switch user (Win+L → Switch user) to `attacker` and run:
     ```powershell
     powershell -ExecutionPolicy Bypass -File C:\test\squat.ps1 -User victim -Seconds 300
     ```
     It prints `listening on \\.\pipe\qalaa-daemon-victim`.
   - Switch back to `victim` and start `qalaa-command.exe`.
   - **Expected:** the app reports that the program serving the Qalaa pipe belongs to another user, and the attacker's log ends with `client sent 0 bytes; hello with token: False` (exit code 0).
   - **Failure:** `hello with token: True` (exit code 1).
   - For comparison, the commit before this fix gives `True`.
3. **V5.**
   - With the squatter from step 2 still listening, start the service as `victim`.
   - Expect "Another Qalaa background service is already running."
   - Stop the squatter.
4. **V3.** Temporarily add `victim` to Administrators, so UAC gives `victim` an elevated token with the *same* user SID.
   - Start the service from "Run as administrator" (approve as `victim`).
   - Start the app normally (not elevated).
   - Expect it to connect.
   - Then remove `victim` from Administrators.
   - Also note: if a standard user approves elevation with the *admin's* password, the service runs as the admin (a different SID) and the app correctly refuses it.
5. **V4.**
   - As `victim`, with the service stopped, run `squat.ps1 -User victim` in one window and the app in another.
   - Expect the app to connect to the squatter, which logs `hello with token: True`.
   - This is the documented same-user limit.
6. **V6.**
   - As `victim`, start the service.
   - Switch to `attacker` and run `squat.ps1 -User victim -Seconds 10`.
   - Expect `could not create … Access to the path is denied` (exit code 2).

## Reporting

Send back, for each of V1 to V6:
- the result;
- the last line of `%TEMP%\qalaa-squat.log` (attacker account);
- the message the app showed;
- the Windows version (`winver`).

No tokens or logs beyond these lines are needed.

## Service-side follow-up (not done)

Node's `net.createServer` can't set a pipe DACL or `FILE_FLAG_FIRST_PIPE_INSTANCE`
explicitly, which is why V5 is a denial of service. Two options, decided after these results:
- a small native listener for the service;
- moving the pipe name under a per-session, owner-only namespace (`\\.\pipe\LOCAL\…` isn't available to Win32 desktop apps, so this means an AppContainer-style named-object directory).
