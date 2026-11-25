/**
 * Security posture: hardening checks in the spirit of the CIS benchmarks, scored
 * 0-100. Each check passes, fails, warns or is "unknown" (could not be read);
 * unknown checks are left out of the score rather than counted as failures.
 *
 * Read-only: nothing is changed. Each failed check says how to fix it.
 */
import { execFile } from "node:child_process";
import { lstat, readFile, readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, delimiter, dirname, join } from "node:path";

import { firmwarePosture } from "./firmware";

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

/**
 * sshd's effective global settings, the way sshd reads them: the first value
 * of each keyword wins, Include pulls in other files at that point (relative
 * paths are under /etc/ssh, globs are expanded in order), and everything after
 * the first Match line applies only to some connections, so it doesn't count.
 */
export async function sshdGlobalSettings(
  config: string,
  readInclude: (pattern: string) => Promise<string[]> = async () => [],
  depth = 0,
  settings = new Map<string, string>(),
): Promise<{ settings: Map<string, string>; matched: boolean }> {
  for (const raw of config.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const [key = "", ...rest] = line.split(/\s+|=/).filter(Boolean);
    const keyword = key.toLowerCase();
    if (keyword === "match") return { settings, matched: true };
    if (keyword === "include") {
      if (depth >= 8) continue; // sshd's own limit on nesting
      for (const pattern of rest) {
        for (const text of await readInclude(pattern.startsWith("/") ? pattern : `/etc/ssh/${pattern}`)) {
          const inner = await sshdGlobalSettings(text, readInclude, depth + 1, settings);
          if (inner.matched) return inner;
        }
      }
      continue;
    }
    if (!settings.has(keyword) && rest.length) settings.set(keyword, rest.join(" ").toLowerCase());
  }
  return { settings, matched: false };
}

/** `sshd -T` prints every effective setting as "keyword value" (needs root). */
export function parseSshdT(output: string): Map<string, string> {
  const settings = new Map<string, string>();
  for (const line of output.split("\n")) {
    const m = /^(\S+)\s+(.*)$/.exec(line.trim());
    if (m && !settings.has(m[1]!.toLowerCase())) settings.set(m[1]!.toLowerCase(), m[2]!.toLowerCase());
  }
  return settings;
}

/** Root login, password sign-in and empty passwords, from sshd's effective settings. */
export function sshChecksFrom(settings: Map<string, string>, source: "sshd -T" | "config files"): PostureCheck[] {
  const root = settings.get("permitrootlogin") ?? null;
  const password = settings.get("passwordauthentication") ?? null;
  const empty = settings.get("permitemptypasswords") ?? null;
  const from = source === "sshd -T" ? " (sshd -T)" : "";
  return [
    {
      id: "ssh-root",
      title: "SSH does not allow root to sign in with a password",
      status: root === "yes" ? "fail" : "pass",
      detail: root ? `PermitRootLogin ${root}${from}` : "Default (prohibit-password).",
      fix: 'Set "PermitRootLogin no" in /etc/ssh/sshd_config (or a file it includes) and restart sshd.',
      weight: 8,
    },
    {
      id: "ssh-passwords",
      title: "SSH uses keys rather than passwords",
      status: password === "no" ? "pass" : "warn",
      detail: password ? `PasswordAuthentication ${password}${from}` : "Passwords are allowed (default).",
      fix: 'Set up key sign-in, then "PasswordAuthentication no".',
      weight: 4,
    },
    {
      id: "ssh-empty-passwords",
      title: "SSH refuses accounts with empty passwords",
      status: empty === "yes" ? "fail" : "pass",
      detail: empty ? `PermitEmptyPasswords ${empty}${from}` : null,
      fix: 'Set "PermitEmptyPasswords no".',
      weight: 6,
    },
  ];
}

/** sshd_config text alone (no includes): kept for callers and tests. */
export async function sshChecks(config: string): Promise<PostureCheck[]> {
  return sshChecksFrom((await sshdGlobalSettings(config)).settings, "config files");
}

export interface SshEntry {
  name: string;
  mode: number;
  uid: number;
  isDir: boolean;
}

/**
 * ~/.ssh permissions, as sshd and ssh expect them (Lynis-style): the folder is
 * private, private keys are readable only by you, authorized_keys can't be
 * changed by others, and everything belongs to you.
 */
export function sshPermissionsCheck(folder: SshEntry | null, files: SshEntry[], uid: number): PostureCheck {
  if (!folder) return { id: "ssh-permissions", title: "Your SSH keys are private", status: "pass", detail: "No ~/.ssh folder.", fix: null, weight: 6 };
  const problems: string[] = [];
  const fixes: string[] = [];
  if (folder.uid !== uid) problems.push("~/.ssh belongs to another user");
  if (folder.mode & 0o077) {
    problems.push(`~/.ssh is open to others (${(folder.mode & 0o777).toString(8)})`);
    fixes.push("chmod 700 ~/.ssh");
  }
  for (const f of files.filter((e) => !e.isDir)) {
    const publicFile = /\.pub$|^known_hosts(\.old)?$|^config$/.test(f.name);
    if (f.uid !== uid) problems.push(`${f.name} belongs to another user`);
    if (f.name.startsWith("authorized_keys") && f.mode & 0o022) {
      problems.push(`${f.name} can be changed by others`);
      fixes.push(`chmod 600 ~/.ssh/${f.name}`);
    } else if (!publicFile && !f.name.startsWith("authorized_keys") && f.mode & 0o077) {
      problems.push(`${f.name} can be read by others`);
      fixes.push(`chmod 600 ~/.ssh/${f.name}`);
    }
  }
  const serious = problems.some((p) => / can be (read|changed) by others| belongs to another user/.test(p));
  return {
    id: "ssh-permissions",
    title: "Your SSH keys are private",
    status: problems.length === 0 ? "pass" : serious ? "fail" : "warn",
    detail: problems.length ? problems.join("; ") : `${files.length} files checked.`,
    fix: fixes.length ? fixes.join(" && ") : problems.length ? "Make sure ~/.ssh and its files belong to you." : null,
    weight: 6,
  };
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

/** Kernel settings that make attacks harder (values from /proc/sys); null = unreadable. */
export const KERNEL_HARDENING: { key: string; path: string; ok: (value: number) => boolean; why: string }[] = [
  { key: "kernel.yama.ptrace_scope", path: "/proc/sys/kernel/yama/ptrace_scope", ok: (v) => v >= 1, why: "any program can read other programs' memory (passwords, keys)" },
  { key: "kernel.kptr_restrict", path: "/proc/sys/kernel/kptr_restrict", ok: (v) => v >= 1, why: "kernel addresses are visible, which helps exploits" },
  { key: "kernel.dmesg_restrict", path: "/proc/sys/kernel/dmesg_restrict", ok: (v) => v === 1, why: "any user can read the kernel log" },
  { key: "kernel.randomize_va_space", path: "/proc/sys/kernel/randomize_va_space", ok: (v) => v === 2, why: "memory layout randomisation is weakened" },
  { key: "fs.protected_symlinks", path: "/proc/sys/fs/protected_symlinks", ok: (v) => v === 1, why: "symbolic-link tricks in shared folders are possible" },
  { key: "fs.protected_hardlinks", path: "/proc/sys/fs/protected_hardlinks", ok: (v) => v === 1, why: "hard-link tricks on other users' files are possible" },
  { key: "kernel.unprivileged_bpf_disabled", path: "/proc/sys/kernel/unprivileged_bpf_disabled", ok: (v) => v >= 1, why: "any user can load BPF programs into the kernel" },
];

/** Network settings for a computer that isn't a router (Lynis / CIS benchmark values). */
export const NETWORK_HARDENING: { key: string; ok: (value: number) => boolean; want: number; why: string }[] = [
  { key: "net.ipv4.conf.all.rp_filter", ok: (v) => v === 1 || v === 2, want: 1, why: "packets with forged source addresses are accepted" },
  { key: "net.ipv4.conf.all.accept_redirects", ok: (v) => v === 0, want: 0, why: "any machine on the network can redirect your traffic" },
  { key: "net.ipv4.conf.default.accept_redirects", ok: (v) => v === 0, want: 0, why: "new network connections accept traffic redirects" },
  { key: "net.ipv6.conf.all.accept_redirects", ok: (v) => v === 0, want: 0, why: "any machine on the network can redirect your IPv6 traffic" },
  { key: "net.ipv4.conf.all.secure_redirects", ok: (v) => v === 0, want: 0, why: "redirects from the gateway are still accepted" },
  { key: "net.ipv4.conf.all.accept_source_route", ok: (v) => v === 0, want: 0, why: "senders can choose the route their packets take" },
  { key: "net.ipv6.conf.all.accept_source_route", ok: (v) => v === 0, want: 0, why: "senders can choose the route their IPv6 packets take" },
  { key: "net.ipv4.conf.all.send_redirects", ok: (v) => v === 0, want: 0, why: "this computer tells others to reroute traffic, which only routers should do" },
  { key: "net.ipv4.tcp_syncookies", ok: (v) => v === 1, want: 1, why: "a flood of half-open connections can exhaust the network stack" },
  { key: "net.ipv4.icmp_echo_ignore_broadcasts", ok: (v) => v === 1, want: 1, why: "broadcast pings can be used to amplify attacks" },
  { key: "net.ipv4.conf.all.log_martians", ok: (v) => v === 1, want: 1, why: "packets with impossible addresses aren't logged" },
];

export const sysctlPath = (key: string) => `/proc/sys/${key.replace(/\./g, "/")}`;

/**
 * A machine that forwards packets (a router, or a Docker or VM host) needs
 * some of these differently, so those keys are skipped there.
 */
export function networkHardeningCheck(values: Record<string, number | null>, forwarding: boolean): PostureCheck {
  const routerOnly = new Set(["net.ipv4.conf.all.send_redirects", "net.ipv4.conf.all.rp_filter"]);
  const applicable = NETWORK_HARDENING.filter((k) => !(forwarding && routerOnly.has(k.key)));
  const known = applicable.filter((k) => values[k.key] !== null && values[k.key] !== undefined);
  const weak = known.filter((k) => !k.ok(values[k.key]!));
  return {
    id: "network-hardening",
    title: "Network protections in the kernel are on",
    status: !known.length ? "unknown" : weak.length === 0 ? "pass" : weak.length <= 2 ? "warn" : "fail",
    detail: weak.length
      ? weak.map((k) => `${k.key} = ${values[k.key]}: ${k.why}`).join("; ")
      : known.length
        ? `${known.length} settings checked${forwarding ? " (this computer forwards packets, so router settings were skipped)" : ""}.`
        : null,
    fix: weak.length ? `Add to /etc/sysctl.d/90-network.conf and run "sudo sysctl --system": ${weak.map((k) => `${k.key} = ${k.want}`).join(", ")}` : null,
    weight: 6,
  };
}

export function kernelHardeningCheck(values: Record<string, number | null>): PostureCheck {
  const known = KERNEL_HARDENING.filter((k) => values[k.key] !== null && values[k.key] !== undefined);
  const weak = known.filter((k) => !k.ok(values[k.key]!));
  return {
    id: "kernel-hardening",
    title: "Kernel hardening settings are on",
    status: !known.length ? "unknown" : weak.length === 0 ? "pass" : weak.length <= 2 ? "warn" : "fail",
    detail: weak.length ? weak.map((k) => `${k.key} = ${values[k.key]}: ${k.why}`).join("; ") : known.length ? `${known.length} settings checked.` : null,
    fix: weak.length ? `Add to /etc/sysctl.d/90-hardening.conf and run "sudo sysctl --system": ${weak.map((k) => `${k.key} = ${k.key === "kernel.randomize_va_space" ? 2 : 1}`).join(", ")}` : null,
    weight: 6,
  };
}

/** Files an sshd Include pattern names, in sshd's (sorted) order. */
async function readIncluded(pattern: string): Promise<string[]> {
  const dir = dirname(pattern);
  const glob = basename(pattern);
  const re = new RegExp(`^${glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`);
  const names = glob.includes("*") || glob.includes("?") ? (await readdir(dir).catch(() => [] as string[])).filter((n) => re.test(n)).sort() : [glob];
  const texts: string[] = [];
  for (const name of names.slice(0, 64)) {
    const text = await readFile(join(dir, name), "utf8").catch(() => null);
    if (text !== null) texts.push(text);
  }
  return texts;
}

async function sshPermissions(): Promise<PostureCheck> {
  const dir = join(homedir(), ".ssh");
  const info = await stat(dir).catch(() => null);
  if (!info?.isDirectory()) return sshPermissionsCheck(null, [], process.getuid?.() ?? 0);
  const files: SshEntry[] = [];
  for (const name of (await readdir(dir).catch(() => [] as string[])).slice(0, 200)) {
    const f = await lstat(join(dir, name)).catch(() => null);
    if (f) files.push({ name, mode: f.mode, uid: f.uid, isDir: f.isDirectory() });
  }
  return sshPermissionsCheck({ name: ".ssh", mode: info.mode, uid: info.uid, isDir: true }, files, process.getuid?.() ?? info.uid);
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
  // sshd -T is exact but usually needs root; otherwise the files, includes and all.
  const effective = await run("sshd", ["-T"]);
  if (effective.ok && /^permitrootlogin /m.test(effective.stdout)) {
    checks.push(...sshChecksFrom(parseSshdT(effective.stdout), "sshd -T"));
  } else {
    const sshd = await readFile("/etc/ssh/sshd_config", "utf8").catch(() => null);
    if (sshd !== null) checks.push(...sshChecksFrom((await sshdGlobalSettings(sshd, readIncluded)).settings, "config files"));
  }
  checks.push(await sshPermissions());
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
  const sysctl: Record<string, number | null> = {};
  for (const k of KERNEL_HARDENING) {
    const raw = await readFile(k.path, "utf8").catch(() => null);
    sysctl[k.key] = raw === null || !/^\s*-?\d+/.test(raw) ? null : Number.parseInt(raw, 10);
  }
  checks.push(kernelHardeningCheck(sysctl));
  const network: Record<string, number | null> = {};
  for (const k of [...NETWORK_HARDENING.map((n) => n.key), "net.ipv4.ip_forward"]) {
    const raw = await readFile(sysctlPath(k), "utf8").catch(() => null);
    network[k] = raw === null || !/^\s*-?\d+/.test(raw) ? null : Number.parseInt(raw, 10);
  }
  checks.push(networkHardeningCheck(network, network["net.ipv4.ip_forward"] === 1));
  checks.push({ id: "path-writable", title: "No world-writable folders in PATH", status: writable.length ? "fail" : "pass", detail: writable.length ? writable.join(", ") : null, fix: "Remove write access for others: chmod o-w <folder>", weight: 6 });
  return checks;
}

export async function posture(facts: KnownFacts, platform = process.platform): Promise<Posture> {
  const [extra, firmware] = await Promise.all([
    platform === "win32" ? windowsChecks() : platform === "darwin" ? macChecks() : platform === "linux" ? linuxChecks() : Promise.resolve([]),
    firmwarePosture(platform).catch(() => []),
  ]);
  const checks = [...commonChecks(facts), ...firmware, ...extra];
  return { score: scoreChecks(checks), checks, checkedAt: new Date().toISOString() };
}
