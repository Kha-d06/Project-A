/**
 * Security posture: hardening checks in the spirit of the CIS benchmarks, scored
 * 0-100. Each check passes, fails, warns or is "unknown" (could not be read);
 * unknown checks are left out of the score rather than counted as failures.
 *
 * Read-only: nothing is changed. Each failed check says how to fix it.
 */
import { execFile } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { delimiter } from "node:path";

export type CheckStatus = "pass" | "fail" | "warn" | "unknown";

export interface PostureCheck {
  id: string;
  title: string;
  status: CheckStatus;
  detail: string | null;
  fix: string | null;
  weight: number;
}

export interface Posture {
  score: number | null;
  checks: PostureCheck[];
  checkedAt: string;
}

function run(command: string, args: string[], timeout = 15_000): Promise<{ stdout: string; ok: boolean }> {
  return new Promise((resolve) => {
    execFile(command, args, { timeout, windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (error, stdout) =>
      resolve({ stdout: String(stdout ?? ""), ok: !error }),
    );
  });
}

const ps = (script: string) => run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], 30_000);

// --- Scoring (pure) ----------------------------------------------------------------------

export function scoreChecks(checks: PostureCheck[]): number | null {
  const counted = checks.filter((c) => c.status !== "unknown");
  const total = counted.reduce((sum, c) => sum + c.weight, 0);
  if (!total) return null;
  const earned = counted.reduce((sum, c) => sum + (c.status === "pass" ? c.weight : c.status === "warn" ? c.weight / 2 : 0), 0);
  return Math.round((earned / total) * 100);
}

// --- Parsers (pure, tested) ----------------------------------------------------------------

/** Get-MpComputerStatus fields → Defender checks. */
export function defenderChecks(json: string): PostureCheck[] {
  try {
    const d = JSON.parse(json) as { AntivirusEnabled?: boolean; RealTimeProtectionEnabled?: boolean; AntivirusSignatureAge?: number };
    return [
      {
        id: "defender-realtime",
        title: "Microsoft Defender real-time protection",
        status: d.AntivirusEnabled && d.RealTimeProtectionEnabled ? "pass" : "fail",
        detail: d.RealTimeProtectionEnabled ? "On." : "Real-time protection is off.",
        fix: "Turn it on in Windows Security → Virus & threat protection.",
        weight: 15,
      },
      {
        id: "defender-signatures",
        title: "Defender virus definitions are current",
        status: typeof d.AntivirusSignatureAge !== "number" ? "unknown" : d.AntivirusSignatureAge <= 3 ? "pass" : d.AntivirusSignatureAge <= 7 ? "warn" : "fail",
        detail: typeof d.AntivirusSignatureAge === "number" ? `${d.AntivirusSignatureAge} day(s) old.` : null,
        fix: "Run Windows Update, or Check for updates in Windows Security.",
        weight: 5,
      },
    ];
  } catch {
    return [{ id: "defender-realtime", title: "Microsoft Defender real-time protection", status: "unknown", detail: "Could not read Defender's status (another antivirus may be in charge).", fix: null, weight: 15 }];
  }
}

/** `reg query ...\Policies\System` output → UAC check. */
export function uacCheck(stdout: string): PostureCheck {
  const lua = /EnableLUA\s+REG_DWORD\s+0x([0-9a-f]+)/i.exec(stdout)?.[1];
  const prompt = /ConsentPromptBehaviorAdmin\s+REG_DWORD\s+0x([0-9a-f]+)/i.exec(stdout)?.[1];
  if (lua === undefined) return { id: "uac", title: "User Account Control", status: "unknown", detail: null, fix: null, weight: 10 };
  const on = Number.parseInt(lua, 16) === 1;
  const silent = prompt !== undefined && Number.parseInt(prompt, 16) === 0;
  return {
    id: "uac",
    title: "User Account Control",
    status: !on ? "fail" : silent ? "warn" : "pass",
    detail: !on ? "UAC is turned off: programs get administrator rights without asking." : silent ? "Administrators are never asked before changes." : "On.",
    fix: "Control Panel → User Accounts → Change User Account Control settings: use the default level or higher.",
    weight: 10,
  };
}

/**
 * A service path with spaces and no quotes, like C:\Program Files\App\svc.exe,
 * lets a program planted at C:\Program.exe run instead (a classic privilege
 * escalation).
 */
export function unquotedServicePaths(rows: { Name: string; PathName: string | null }[]): string[] {
  return rows
    .filter((r) => {
      const path = (r.PathName ?? "").trim();
      if (!path || path.startsWith('"')) return false;
      const exe = /^(.*?\.exe)\b/i.exec(path)?.[1];
      return Boolean(exe && exe.includes(" ") && !/^[a-z]:\\windows\\/i.test(exe));
    })
    .map((r) => r.Name);
}

/** sshd_config → root login and password authentication checks. */
export function sshChecks(config: string): PostureCheck[] {
  const value = (key: string) => {
    const lines = config.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    const hit = lines.find((l) => l.toLowerCase().startsWith(`${key.toLowerCase()} `));
    return hit?.split(/\s+/)[1]?.toLowerCase() ?? null;
  };
  const root = value("PermitRootLogin");
  const password = value("PasswordAuthentication");
  return [
    {
      id: "ssh-root",
      title: "SSH does not allow root to sign in with a password",
      status: root === "yes" ? "fail" : "pass",
      detail: root ? `PermitRootLogin ${root}` : "Default (prohibit-password).",
      fix: 'Set "PermitRootLogin no" in /etc/ssh/sshd_config and restart sshd.',
      weight: 8,
    },
    {
      id: "ssh-passwords",
      title: "SSH uses keys rather than passwords",
      status: password === "no" ? "pass" : "warn",
      detail: password ? `PasswordAuthentication ${password}` : "Passwords are allowed (default).",
      fix: 'Set up key sign-in, then "PasswordAuthentication no".',
      weight: 4,
    },
  ];
}

// --- Collection --------------------------------------------------------------------------

export interface KnownFacts {
  firewall: "on" | "off" | "partial" | "unknown";
  encryption: "on" | "off" | "partial" | "unknown";
  pendingUpdates: number | null;
  riskyPorts: number | null;
  suspiciousStartup: number;
}

function commonChecks(f: KnownFacts): PostureCheck[] {
  const tri = (s: string): CheckStatus => (s === "on" ? "pass" : s === "partial" ? "warn" : s === "off" ? "fail" : "unknown");
  return [
    { id: "firewall", title: "Firewall is on", status: tri(f.firewall), detail: null, fix: "See Firewall in the Security centre.", weight: 15 },
    { id: "encryption", title: "System disk is encrypted", status: tri(f.encryption), detail: null, fix: "See Disk encryption in the Security centre.", weight: 12 },
    {
      id: "updates",
      title: "No pending software updates",
      status: f.pendingUpdates === null ? "unknown" : f.pendingUpdates === 0 ? "pass" : f.pendingUpdates <= 5 ? "warn" : "fail",
      detail: f.pendingUpdates === null ? null : `${f.pendingUpdates} pending.`,
      fix: "Install updates from your system's update tool.",
      weight: 10,
    },
    {
      id: "ports",
      title: "No risky services open to the network",
      status: f.riskyPorts === null ? "unknown" : f.riskyPorts === 0 ? "pass" : "fail",
      detail: f.riskyPorts ? `${f.riskyPorts} risky service(s) reachable from the network.` : null,
      fix: "Close or firewall them (see Programs accepting connections).",
      weight: 10,
    },
    {
      id: "startup",
      title: "No suspicious programs start automatically",
      status: f.suspiciousStartup === 0 ? "pass" : "warn",
      detail: f.suspiciousStartup ? `${f.suspiciousStartup} startup item(s) look suspicious.` : null,
      fix: "Review them under Programs that start automatically.",
      weight: 8,
    },
  ];
}

async function windowsChecks(): Promise<PostureCheck[]> {
  const [defender, uac, services, guest, rdp] = await Promise.all([
    ps("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress"),
    run("reg", ["query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]),
    ps("Get-CimInstance Win32_Service | Select-Object Name,PathName | ConvertTo-Json -Compress"),
    ps("(Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled"),
    run("reg", ["query", "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections"]),
  ]);
  const checks = [...defenderChecks(defender.ok ? defender.stdout : "x"), uacCheck(uac.stdout)];
  let rows: { Name: string; PathName: string | null }[] = [];
  try {
    const parsed = JSON.parse(services.stdout || "[]") as unknown;
    rows = (Array.isArray(parsed) ? parsed : [parsed]) as typeof rows;
  } catch {
    rows = [];
  }
  const unquoted = unquotedServicePaths(rows);
  checks.push({
    id: "unquoted-services",
    title: "No services with unquoted paths",
    status: services.ok ? (unquoted.length ? "fail" : "pass") : "unknown",
    detail: unquoted.length ? `Unquoted: ${unquoted.slice(0, 8).join(", ")}` : null,
    fix: "Ask the software's maker for an update, or quote the path in the service's ImagePath registry value.",
    weight: 8,
  });
  const guestOn = guest.stdout.trim();
  checks.push({ id: "guest", title: "Guest account is disabled", status: guestOn === "True" ? "fail" : guestOn === "False" ? "pass" : "unknown", detail: null, fix: "Disable it: Computer Management → Local Users and Groups.", weight: 5 });
  const deny = /fDenyTSConnections\s+REG_DWORD\s+0x([0-9a-f]+)/i.exec(rdp.stdout)?.[1];
  checks.push({
    id: "rdp",
    title: "Remote Desktop is off unless you need it",
    status: deny === undefined ? "unknown" : Number.parseInt(deny, 16) === 1 ? "pass" : "warn",
    detail: deny !== undefined && Number.parseInt(deny, 16) === 0 ? "Remote Desktop is on." : null,
    fix: "Settings → System → Remote Desktop: turn it off if you do not use it.",
    weight: 5,
  });
  return checks;
}

async function macChecks(): Promise<PostureCheck[]> {
  const [gatekeeper, sip, auto] = await Promise.all([
    run("spctl", ["--status"]),
    run("csrutil", ["status"]),
    run("defaults", ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"]),
  ]);
  return [
    { id: "gatekeeper", title: "Gatekeeper checks downloaded apps", status: /assessments enabled/i.test(gatekeeper.stdout) ? "pass" : /disabled/i.test(gatekeeper.stdout) ? "fail" : "unknown", detail: null, fix: "Run: sudo spctl --master-enable", weight: 12 },
    { id: "sip", title: "System Integrity Protection is on", status: /enabled/i.test(sip.stdout) ? "pass" : /disabled/i.test(sip.stdout) ? "fail" : "unknown", detail: null, fix: "Re-enable it from Recovery: csrutil enable", weight: 12 },
    { id: "auto-updates", title: "Automatic update checks are on", status: auto.stdout.trim() === "1" ? "pass" : auto.stdout.trim() === "0" ? "fail" : "unknown", detail: null, fix: "System Settings → General → Software Update → Automatic updates.", weight: 6 },
  ];
}

async function linuxChecks(): Promise<PostureCheck[]> {
  const checks: PostureCheck[] = [];
  const apparmor = await run("aa-enabled", []);
  const selinux = await run("getenforce", []);
  checks.push({
    id: "mac-framework",
    title: "AppArmor or SELinux is enforcing",
    status: /^yes/i.test(apparmor.stdout.trim()) || /enforcing/i.test(selinux.stdout) ? "pass" : apparmor.ok || selinux.ok ? "warn" : "unknown",
    detail: selinux.stdout.trim() || apparmor.stdout.trim() || null,
    fix: "Use your distribution's default AppArmor or SELinux profile.",
    weight: 8,
  });
  const sshd = await readFile("/etc/ssh/sshd_config", "utf8").catch(() => null);
  if (sshd !== null) checks.push(...sshChecks(sshd));
  const unattended = await readFile("/etc/apt/apt.conf.d/20auto-upgrades", "utf8").catch(() => null);
  const dnfAuto = await run("systemctl", ["is-enabled", "dnf-automatic.timer"]);
  checks.push({
    id: "auto-updates",
    title: "Security updates install automatically",
    status: (unattended && /Unattended-Upgrade\s+"1"/.test(unattended)) || dnfAuto.stdout.trim() === "enabled" ? "pass" : unattended !== null || dnfAuto.ok ? "warn" : "unknown",
    detail: null,
    fix: "Install unattended-upgrades (Debian/Ubuntu) or dnf-automatic (Fedora).",
    weight: 6,
  });
  // World-writable directories in PATH let any local program plant commands.
  const writable: string[] = [];
  for (const dir of (process.env.PATH ?? "").split(delimiter).filter(Boolean)) {
    const info = await stat(dir).catch(() => null);
    if (info?.isDirectory() && (info.mode & 0o002) !== 0 && (info.mode & 0o1000) === 0) writable.push(dir);
  }
  checks.push({ id: "path-writable", title: "No world-writable folders in PATH", status: writable.length ? "fail" : "pass", detail: writable.length ? writable.join(", ") : null, fix: "Remove write access for others: chmod o-w <folder>", weight: 6 });
  return checks;
}

export async function posture(facts: KnownFacts, platform = process.platform): Promise<Posture> {
  const extra = await (platform === "win32" ? windowsChecks() : platform === "darwin" ? macChecks() : platform === "linux" ? linuxChecks() : Promise.resolve([]));
  const checks = [...commonChecks(facts), ...extra];
  return { score: scoreChecks(checks), checks, checkedAt: new Date().toISOString() };
}
