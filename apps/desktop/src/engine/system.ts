/**
 * System checks: the current Wi-Fi network's security and outdated software.
 * Commands run through execFile (no shell) with timeouts; parsing is pure and
 * tested. Anything unexpected is reported as "unknown", never as fine.
 */
import { execFile } from "node:child_process";

export type WifiRisk = "open" | "weak" | "ok" | "none" | "unknown";

export interface WifiStatus {
  ssid: string | null;
  security: string | null;
  risk: WifiRisk;
}

function classify(security: string | null): WifiRisk {
  if (security === null) return "unknown";
  const value = security.toLowerCase();
  if (!value || value === "--" || value === "none" || value === "open") return "open";
  if (value.includes("wep")) return "weak";
  if (/wpa|sae|802\.1x|owe|enterprise/.test(value)) return "ok";
  return "unknown";
}

/** `nmcli -t -f ACTIVE,SSID,SECURITY dev wifi` */
export function parseNmcli(stdout: string): WifiStatus {
  for (const line of stdout.split(/\r?\n/)) {
    // Fields are colon-separated; colons inside values are escaped as "\:".
    const parts = line.split(/(?<!\\):/).map((part) => part.replace(/\\:/g, ":"));
    if (parts[0] === "yes") return { ssid: parts[1] || null, security: parts[2] ?? "", risk: classify(parts[2] ?? "") };
  }
  return { ssid: null, security: null, risk: "none" };
}

/** `netsh wlan show interfaces` */
export function parseNetsh(stdout: string): WifiStatus {
  if (!/^\s*State\s*:\s*connected/im.test(stdout)) return { ssid: null, security: null, risk: "none" };
  const ssid = /^\s*SSID\s*:\s*(.*)$/m.exec(stdout)?.[1]?.trim() ?? null;
  const auth = /^\s*Authentication\s*:\s*(.*)$/m.exec(stdout)?.[1]?.trim() ?? null;
  return { ssid, security: auth, risk: classify(auth) };
}

/** `system_profiler SPAirPortDataType` (macOS) */
export function parseSystemProfiler(stdout: string): WifiStatus {
  const current = stdout.split(/Current Network Information:/)[1];
  if (!current) return { ssid: null, security: null, risk: "none" };
  const ssid = /^\s*([^\n:]+):\s*$/m.exec(current)?.[1]?.trim() ?? null;
  const security = /Security:\s*(.+)$/m.exec(current)?.[1]?.trim() ?? null;
  return { ssid, security, risk: classify(security) };
}

function run(command: string, args: string[], timeout = 20_000): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout, windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (error, stdout) => {
      if (error && !stdout) reject(error);
      else resolve(String(stdout));
    });
  });
}

export async function wifiStatus(platform = process.platform): Promise<WifiStatus> {
  try {
    if (platform === "win32") return parseNetsh(await run("netsh", ["wlan", "show", "interfaces"]));
    if (platform === "darwin") return parseSystemProfiler(await run("/usr/sbin/system_profiler", ["SPAirPortDataType"], 30_000));
    return parseNmcli(await run("nmcli", ["-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"]));
  } catch {
    return { ssid: null, security: null, risk: "unknown" };
  }
}

// --- Outdated software ---------------------------------------------------------------

export interface PendingUpdate {
  name: string;
  current: string | null;
  available: string | null;
}

/** `winget upgrade` table output. */
export function parseWinget(stdout: string): PendingUpdate[] {
  const lines = stdout.split(/\r?\n/).map((line) => line.replace(/\u001b\[[0-9;]*[A-Za-z]/g, ""));
  const header = lines.findIndex((line) => /^Name\s+Id\s+Version\s+Available/.test(line));
  if (header < 0) return [];
  const columns = ["Name", "Id", "Version", "Available", "Source"].map((name) => lines[header]!.indexOf(name));
  const updates: PendingUpdate[] = [];
  for (const line of lines.slice(header + 2)) {
    if (!line.trim() || /upgrades? available|^-+$/.test(line)) continue;
    const field = (index: number) => line.slice(columns[index]!, columns[index + 1]! > 0 ? columns[index + 1]! : undefined).trim();
    const name = field(0);
    if (name) updates.push({ name, current: field(2) || null, available: field(3) || null });
  }
  return updates;
}

/** `softwareupdate -l` (macOS). */
export function parseSoftwareUpdate(stdout: string): PendingUpdate[] {
  return [...stdout.matchAll(/^\s*\*\s*Label:\s*(.+)$/gm)].map((match) => ({ name: match[1]!.trim(), current: null, available: null }));
}

/** `apt list --upgradable` (Debian and Ubuntu). */
export function parseApt(stdout: string): PendingUpdate[] {
  return stdout
    .split(/\r?\n/)
    .map((line) => /^([^/\s]+)\/\S+\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]/.exec(line))
    .filter((match): match is RegExpExecArray => match !== null)
    .map((match) => ({ name: match[1]!, available: match[2]!, current: match[3]! }));
}

export async function pendingUpdates(platform = process.platform): Promise<{ updates: PendingUpdate[]; source: string } | null> {
  try {
    if (platform === "win32") return { updates: parseWinget(await run("winget", ["upgrade", "--accept-source-agreements"], 60_000)), source: "winget" };
    if (platform === "darwin") return { updates: parseSoftwareUpdate(await run("softwareupdate", ["-l"], 120_000)), source: "softwareupdate" };
    return { updates: parseApt(await run("apt", ["list", "--upgradable"], 60_000)), source: "apt" };
  } catch {
    return null; // the tool is not available on this system
  }
}
