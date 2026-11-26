# Windows pipe-squatting test (audit QA-05)

## What changed

On Windows the background service listens on a named pipe. Pipe names are
global, so another Windows user could create the pipe before the service
started and receive the native app's token. Two independent protections now
apply, in this order.

**Service side** (`apps/desktop/src/core/paths.ts`, `server.ts`):
- **A fresh pipe name on every start.** `\\.\pipe\qalaa-daemon-<user>-<32 random hex>`, written after the pipe exists to `ipc-endpoint` in the user's own data folder (`%APPDATA%\Qalaa Desktop`, which only that user can read). Another user can't create the pipe in advance, because they can't know its next name.
- **No second instance.** Once the pipe exists, the default DACL doesn't let other users add instances to it. A second copy of the service sees the running one through the endpoint file and refuses to start.
- **Connection limits.** A connection must say `hello` with the token within 5 seconds or it is closed. At most 8 connections may be waiting to authenticate, and 64 in total, so connection floods are bounded. Every method except `hello` is refused before authentication.

**Client side** (`apps/desktop-native/crates/qalaa-ipc`):
- **Endpoint from the file only.** It reads the pipe name from `ipc-endpoint` and accepts only a name of exactly that shape.
- **Server identity check.** After opening the pipe and **before writing anything**, `check_pipe_server`:
  1. asks Windows which process serves the pipe (`GetNamedPipeServerProcessId`);
  2. reads that process's token user SID;
  3. compares it with its own.

  A difference, or a server it can't inspect, means it disconnects without sending a byte.

**Verification status:**
- Compile- and clippy-checked for `x86_64-pc-windows-msvc`.
- The name, file, limit and deadline logic is unit-tested on Linux (`test/ipc-hardening.test.ts`, `crates/qalaa-ipc/src/paths.rs`).
- **Not yet run on Windows.** That is what this procedure is for.

**Not protected, by design:** another program running as the *same* user can read the endpoint and token files and drive the service (audit QA-11). Telling one process of a user from another needs code-signature checks, which come with code signing.

## What has to be verified

| # | Behaviour | Pass when |
|---|---|---|
| V1 | Normal use still works | The app connects to the real service and shows Home |
| V2 | **A pipe made by another user gets no token** | `squat.ps1` logs `client sent 0 bytes; hello with token: False`, and the app shows the "another user" error |
| V3 | An elevated service of the same user is accepted | The app connects when the service runs "as administrator" by the same account |
| V4 | Known limit, same user | A squatter running as the *same* user, on the name from the endpoint file, is accepted. Record it; it isn't a failure |
| V5 | **Startup interference** | A squatter on the old fixed name, or any guessed name, doesn't stop the service starting. The service publishes a new random name and the app connects to it |
| V6 | No second instance | While the service runs, `squat.ps1 -Name <its current name>` as the other user fails with access denied, and a second copy of the service refuses to start |
| V7 | Unauthorized requests | A client sending a method before `hello`, or a wrong token, gets `unauthorized` and is disconnected |
| V8 | Hello deadline and flood limit | A connection that sends nothing is closed after about 5 seconds. With 8 such connections open, a 9th is refused, and the app still connects once they time out |
| V9 | Concurrent clients | The native app and the Guardian pet are connected at once, both get events, and a scan started from one finishes |
| V10 | Unexpected client termination | Killing the app in Task Manager during a scan leaves the service running; reopening the app reconnects |

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
2. **V2, squatter from another user.** The service now uses a random name, so make the app connect to a stranger's pipe directly.
   - As `victim`, with the service **stopped**, write the name the squatter will use into the endpoint file (simulating a stale or tampered file):
     ```powershell
     Set-Content "$env:APPDATA\Qalaa Desktop\ipc-endpoint" ("\\.\pipe\qalaa-daemon-victim-" + ("ab" * 16))
     ```
   - Switch user (Win+L → Switch user) to `attacker` and run:
     ```powershell
     powershell -ExecutionPolicy Bypass -File C:\test\squat.ps1 -Name ("qalaa-daemon-victim-" + ("ab" * 16)) -Seconds 300
     ```
   - Switch back to `victim` and start `qalaa-command.exe`.
   - **Expected:** the app reports that the program serving the Qalaa pipe belongs to another user, and the attacker's log ends with `client sent 0 bytes; hello with token: False` (exit code 0).
   - **Failure:** `hello with token: True` (exit code 1).
3. **V5, startup interference.**
   - With the squatter from step 2 still listening (and one on the old fixed name, `squat.ps1 -User victim`), start the service as `victim`.
   - Expect it to start.
   - Check that `%APPDATA%\Qalaa Desktop\ipc-endpoint` now holds a *new* name, and that the app connects.
   - Stop the squatters.
4. **V3.** Temporarily add `victim` to Administrators, so UAC gives `victim` an elevated token with the *same* user SID.
   - Start the service from "Run as administrator" (approve as `victim`).
   - Start the app normally (not elevated).
   - Expect it to connect.
   - Then remove `victim` from Administrators.
   - Also note: if a standard user approves elevation with the *admin's* password, the service runs as the admin (a different SID) and the app correctly refuses it.
5. **V4.** As `victim`, start the service, read its name from `ipc-endpoint`, stop the service, then run `squat.ps1 -Name <that name>` as `victim` and start the app. Expect it to connect to the squatter, which logs `hello with token: True`. This is the documented same-user limit.
6. **V6.**
   - As `victim`, start the service and read its name from `ipc-endpoint`.
   - Switch to `attacker` and run `squat.ps1 -Name <that name> -Seconds 10`. Expect `could not create … Access to the path is denied` (exit code 2).
   - As `victim`, start a second copy of the service. Expect "already running".
7. **V7 and V8.** As `victim`, with the service running, in PowerShell:
   ```powershell
   $name = (Get-Content "$env:APPDATA\Qalaa Desktop\ipc-endpoint").Split('\')[-1]
   $p = New-Object System.IO.Pipes.NamedPipeClientStream(".", $name, "InOut"); $p.Connect(2000)
   $w = New-Object System.IO.StreamWriter($p); $w.AutoFlush = $true
   $r = New-Object System.IO.StreamReader($p)
   $w.WriteLine('{"id":1,"method":"home.get"}'); $r.ReadLine()     # expect "unauthorized"
   $p2 = New-Object System.IO.Pipes.NamedPipeClientStream(".", $name, "InOut"); $p2.Connect(2000)
   Start-Sleep 6; $p2.IsConnected                                   # expect False (deadline)
   ```
   Open 9 connections without writing and check that the 9th is closed at once. Wait 6 seconds and check the app connects.
8. **V9 and V10.**
   - Start the native app and the Guardian pet together, and start a quick scan from the app. Both should show it running and finishing.
   - Kill `qalaa-command.exe` in Task Manager during a full scan. The service keeps running (the scan finishes), and reopening the app reconnects.

## Reporting

Send back, for each of V1 to V10:
- the result;
- the last line of `%TEMP%\qalaa-squat.log` (attacker account);
- the message the app showed;
- the Windows version (`winver`).

No tokens or logs beyond these lines are needed.

## Remaining limits

- **Same user:** another program running as the same user can do what the app does (V4, QA-11).
- **Listing names:** another user can list pipe names and see the current one once the service has started. They can open it for reading under the default DACL, but they can't authenticate (no token), and the deadline and connection limits bound how many connections they can hold.
- **A tighter DACL:** owner-only, with no read for Everyone, needs a native listener, because Node's `net` can't set one. It's worth doing if V8 shows the limits aren't enough.
