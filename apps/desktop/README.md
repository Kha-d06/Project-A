# SENTINEL Desktop

A desktop scanner for Windows, macOS and Linux, built with Electron. It checks
files on your computer against known malware and common attack techniques,
watches your Downloads folder, and keeps dangerous files in an encrypted
quarantine. English and Arabic.

## What it checks

| Engine | What it does | Needs |
| --- | --- | --- |
| Fingerprints | SHA-256 of every file (and every file inside ZIP archives) against recent malware from MalwareBazaar and ThreatFox. The list is downloaded from your SENTINEL server every six hours (`GET /api/v1/intelligence/hash-list`); nothing about your files is sent. | A SENTINEL server, for the list |
| Heuristics | Programs disguised as documents (content vs. name, double extensions, hidden text-direction characters), encoded PowerShell and download-and-run droppers, Defender tampering, PDFs that launch programs or auto-run JavaScript, Office macros, path traversal, zip bombs, password-protected archives, the EICAR test file. | Nothing |
| Containers | Looks inside ISO/IMG disk images (files fingerprinted and checked like everything else), flags Windows shortcuts (.lnk) that start PowerShell, cmd, mshta and similar, and lists 7z and RAR archives with 7-Zip when it is installed. | 7-Zip (optional, for 7z/RAR) |
| ClamAV | Used automatically when `clamdscan` or `clamscan` is installed. | ClamAV (optional) |
| Cloud lookup | Sends each file's SHA-256 (never the file) to the server, to catch samples reported since the last list update. **Off by default.** | Opt-in in Settings |
| Full server scan | Uploads one file to the SENTINEL server for YARA, Office and PE analysis, and opens the report. Only when you click it, after a confirmation. | A SENTINEL server |

Verdicts use the same words as the website: **Known malicious**, **Suspicious**, **No known threat** (never "safe") and **Could not scan**.

## Protection features

- **Downloads watcher.** New files in the watched folders are scanned once they stop changing. Partial downloads (`.crdownload`, `.part`, …) are skipped until the browser finishes them.
- **Automatic quarantine** of known-malicious files (on by default). Suspicious files are reported, and you can quarantine them yourself.
- **Quarantine.** Files are encrypted with AES-256-GCM (a random key per file) into the app's private folder, and the original is deleted. Restore puts the file back where it was, or next to it if the name is taken.
- **Ransomware watch** (detection only, on by default for Documents, Desktop and Pictures). Alerts when many files are renamed with extensions that ransomware uses, when many documents are rewritten with random-looking contents within a minute, or when ransom notes appear. It cannot stop encryption, so keep backups.
- **Wi-Fi check.** Warns when the current network is open or uses WEP. It reads `nmcli`, `netsh` or `system_profiler`.
- **Software updates.** Lists pending updates from `winget`, `softwareupdate` or `apt`. Installing them is left to the system's own tools.
- **Tray icon.** Watching continues after the window closes. Quit from the tray menu.
- **SENTINEL account and remote scans.** In Settings, type the code from the website's Dashboard → Devices page to link this computer. The website then shows its protection status. If you also turn on **Allow scans from my SENTINEL account** (off by default), you can start a quick scan (watched folders), a full scan (your home folder) or a scan of one offered folder from another device, quarantine what a scan found, and update the fingerprint list. The app offers folders by name only, refuses any folder it did not offer, checks a file's fingerprint again before quarantining it, and reports names, verdicts and fingerprints, never contents or full paths. Removing the device on the website signs the app out.

## What it does not do

It is not a replacement for Microsoft Defender, XProtect or your distribution's security tools:

- it does not monitor running programs or memory;
- it cannot stop a browser from writing a file (it scans right after);
- it has no kernel driver;
- its fingerprint list covers recently reported samples, not all malware ever seen.

Keep your operating system's built-in protection on.

## Security of the app itself

- **Window.** The window loads only the bundled local page, with context isolation, the Chromium sandbox and no Node.js. Navigation, new windows and all permission requests are refused, and a strict CSP is set.
- **Main process.** The page reaches it only through the functions in `src/preload.ts`, and every argument is validated there (settings through an allow-list).
- **Files.** Files are only read: never opened with their own program, never executed, never extracted to disk. ZIP members are inflated in memory with size limits.
- **ClamAV** runs through `execFile`, with no shell.
- **Device token.** The account link stores a device token (`sdv_…`) in `account.json` in the app's data folder, readable only by you. The server keeps only a digest of it. It can heartbeat, fetch commands for this device and report their results; it cannot reach the rest of the account.

## Develop

```bash
npm install
npm run typecheck && npm test        # engine unit tests
npm start                            # build and run
npm run build && xvfb-run -a node test/e2e.mjs   # end to end in Electron (Linux CI)
```

Point it at a server with `SENTINEL_SERVER=https://your-sentinel.example npm start`, or in Settings. Data lives in the OS app-data folder; set `SENTINEL_DESKTOP_PROFILE` to use another.

## Packaging

Installers can be built with electron-builder (`npx electron-builder --win --mac --linux`). Distributing them without security warnings needs the operator's own code-signing certificates: Windows Authenticode and Apple Developer ID with notarisation. That was not possible in this repository.
