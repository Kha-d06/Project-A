/**
 * Security checks for this computer: firewall, programs listening on the
 * network, programs that start automatically, and which apps use the camera
 * or microphone. Commands run through execFile (no shell) with timeouts.
 * Parsing is pure and tested. Anything we cannot read is reported as
 * "unknown", never as fine.
 */
import { execFile } from "node:child_process";
import { readFile, readdir, readlink } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join } from "node:path";

function run(command: string, args: string[], timeout = 15_000): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout, windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (error, stdout) => {
      if (error && !stdout) reject(error);
      else resolve(String(stdout));
    });
  });
}

// --- Firewall ------------------------------------------------------------------------

export type FirewallState = "on" | "off" | "partial" | "unknown";
export interface FirewallStatus {
  state: FirewallState;
  detail: string | null;
  /** Tool we read it from, so the interface can say where the answer came from. */
  source: string | null;
}

/** `netsh advfirewall show allprofiles state` */
export function parseNetshFirewall(stdout: string): FirewallStatus {
  const profiles = [...stdout.matchAll(/^(\w+) Profile Settings:[\s\S]*?^State\s+(ON|OFF)/gim)].map((m) => ({ name: m[1]!, on: m[2]!.toUpperCase() === "ON" }));
  if (!profiles.length) return { state: "unknown", detail: null, source: "netsh" };
  const off = profiles.filter((p) => !p.on).map((p) => p.name);
  return {
    state: off.length === 0 ? "on" : off.length === profiles.length ? "off" : "partial",
    detail: off.length ? `Off for: ${off.join(", ")}` : null,
    source: "netsh",
  };
}

/** `socketfilterfw --getglobalstate` (macOS) */
export function parseSocketFilter(stdout: string): FirewallStatus {
  if (/enabled|State = [12]/i.test(stdout)) return { state: "on", detail: /block all|State = 2/i.test(stdout) ? "Blocking all incoming connections" : null, source: "socketfilterfw" };
  if (/disabled|State = 0/i.test(stdout)) return { state: "off", detail: null, source: "socketfilterfw" };
  return { state: "unknown", detail: null, source: "socketfilterfw" };
}

/** `ufw status` or `firewall-cmd --state` (Linux) */
export function parseLinuxFirewall(stdout: string, source: "ufw" | "firewalld"): FirewallStatus {
  if (source === "ufw") {
    if (/Status:\s*active/i.test(stdout)) return { state: "on", detail: null, source };
    if (/Status:\s*inactive/i.test(stdout)) return { state: "off", detail: null, source };
  } else {
    if (/^running/m.test(stdout)) return { state: "on", detail: null, source };
    if (/not running/.test(stdout)) return { state: "off", detail: null, source };
  }
  return { state: "unknown", detail: null, source };
}

export async function firewallStatus(platform = process.platform): Promise<FirewallStatus> {
  try {
    if (platform === "win32") return parseNetshFirewall(await run("netsh", ["advfirewall", "show", "allprofiles", "state"]));
    if (platform === "darwin") return parseSocketFilter(await run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]));
  } catch {
    return { state: "unknown", detail: null, source: null };
  }
  for (const [command, args, source] of [
    ["firewall-cmd", ["--state"], "firewalld"],
    ["ufw", ["status"], "ufw"],
  ] as const) {
    try {
      const result = parseLinuxFirewall(await run(command, [...args]), source);
      if (result.state !== "unknown") return result;
    } catch (error) {
      // firewall-cmd exits non-zero with "not running" on stderr
      const stderr = String((error as { stderr?: string }).stderr ?? "");
      if (source === "firewalld" && /not running/.test(stderr)) return { state: "off", detail: null, source };
    }
  }
  // ufw needs administrator rights to report; most desktops have no firewall front end at all.
  return { state: "unknown", detail: "Could not read the firewall without administrator rights.", source: null };
}

// --- Listening ports -----------------------------------------------------------------

export interface ListeningPort {
  port: number;
  address: string;
  process: string | null;
  pid: number | null;
  /** Reachable from other machines (bound to all interfaces or a non-loopback address). */
  exposed: boolean;
  /** Short explanation when this kind of service is a common attack target. */
  risk: string | null;
}

const RISKY_PORTS: Record<number, string> = {
  21: "FTP sends passwords unencrypted",
  23: "Telnet sends everything unencrypted",
  135: "Windows RPC is a common attack target",
  139: "File sharing (NetBIOS) is a common attack target",
  445: "File sharing (SMB) is the most attacked Windows service",
  1433: "A database should not be reachable from the network",
  2375: "An unprotected Docker API gives full control of the computer",
  3306: "A database should not be reachable from the network",
  3389: "Remote Desktop is heavily targeted by password guessing",
  5432: "A database should not be reachable from the network",
  5900: "VNC screen sharing is often weakly protected",
  6379: "Redis has no password by default",
  9200: "Elasticsearch has no password by default",
  11211: "Memcached can be abused for attacks",
  27017: "A database should not be reachable from the network",
};

function isLoopback(address: string): boolean {
  const a = address.replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  return a === "::1" || a.startsWith("127.") || a === "localhost";
}

function makePort(address: string, port: number, process: string | null, pid: number | null): ListeningPort {
  const exposed = !isLoopback(address);
  return { port, address, process, pid, exposed, risk: exposed ? (RISKY_PORTS[port] ?? null) : null };
}

/** Splits "0.0.0.0:22", "[::]:22", "*:22", "::1.631" style endpoints. */
function splitEndpoint(endpoint: string): { address: string; port: number } | null {
  const match = /^(.*)[:.](\d+)$/.exec(endpoint.trim());
  if (!match) return null;
  return { address: match[1] === "*" ? "0.0.0.0" : match[1]!.replace(/^\[|\]$/g, ""), port: Number(match[2]) };
}

function dedupe(ports: ListeningPort[]): ListeningPort[] {
  const seen = new Map<string, ListeningPort>();
  for (const port of ports) {
    const key = `${port.port}/${port.exposed}/${port.process ?? ""}`;
    if (!seen.has(key)) seen.set(key, port);
  }
  return [...seen.values()].sort((a, b) => Number(b.exposed) - Number(a.exposed) || a.port - b.port);
}

/** `ss -ltnpH` (Linux) */
export function parseSs(stdout: string): ListeningPort[] {
  const ports: ListeningPort[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const fields = line.trim().split(/\s+/);
    if (fields[0] !== "LISTEN" || fields.length < 4) continue;
    const endpoint = splitEndpoint(fields[3]!);
    if (!endpoint) continue;
    const users = /users:\(\("([^"]+)",pid=(\d+)/.exec(line);
    ports.push(makePort(endpoint.address, endpoint.port, users?.[1] ?? null, users ? Number(users[2]) : null));
  }
  return dedupe(ports);
}

/** `lsof -nP -iTCP -sTCP:LISTEN` (macOS) */
export function parseLsof(stdout: string): ListeningPort[] {
  const ports: ListeningPort[] = [];
  for (const line of stdout.split(/\r?\n/).slice(1)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 9 || !/\(LISTEN\)/.test(line)) continue;
    const endpoint = splitEndpoint(fields[fields.length - 2]!);
    if (!endpoint) continue;
    ports.push(makePort(endpoint.address, endpoint.port, fields[0]!.replace(/\\x20/g, " "), Number(fields[1]) || null));
  }
  return dedupe(ports);
}

/** `netstat -ano -p TCP` plus `tasklist /fo csv /nh` for names (Windows). */
export function parseNetstat(stdout: string, tasklist = ""): ListeningPort[] {
  const names = new Map<number, string>();
  for (const line of tasklist.split(/\r?\n/)) {
    const match = /^"([^"]+)","(\d+)"/.exec(line.trim());
    if (match) names.set(Number(match[2]), match[1]!);
  }
  const ports: ListeningPort[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const fields = line.trim().split(/\s+/);
    if (fields[0] !== "TCP" || fields[3] !== "LISTENING") continue;
    const endpoint = splitEndpoint(fields[1]!);
    if (!endpoint) continue;
    const pid = Number(fields[4]) || null;
    ports.push(makePort(endpoint.address, endpoint.port, pid ? (names.get(pid) ?? null) : null, pid));
  }
  return dedupe(ports);
}

/** IPv4 "0100007F" or IPv6 (four little-endian 32-bit words) from /proc/net/tcp*. */
export function decodeProcAddress(hex: string): string {
  if (hex.length === 8) return [3, 2, 1, 0].map((i) => Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)).join(".");
  const bytes: number[] = [];
  for (let word = 0; word < 4; word++) {
    const chunk = hex.slice(word * 8, word * 8 + 8);
    for (let i = 3; i >= 0; i--) bytes.push(Number.parseInt(chunk.slice(i * 2, i * 2 + 2), 16));
  }
  if (bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff) return bytes.slice(12).join("."); // IPv4-mapped
  if (bytes.every((b) => b === 0)) return "::";
  if (bytes.slice(0, 15).every((b) => b === 0) && bytes[15] === 1) return "::1";
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i]! << 8) | bytes[i + 1]!).toString(16));
  return groups.join(":");
}

/** `/proc/net/tcp` and `/proc/net/tcp6` (Linux; needs no tools). `owners` maps socket inode to process. */
export function parseProcNetTcp(text: string, owners: Map<string, { name: string; pid: number }> = new Map()): ListeningPort[] {
  const ports: ListeningPort[] = [];
  for (const line of text.split(/\r?\n/).slice(1)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 10 || fields[3] !== "0A") continue; // 0A = LISTEN
    const [addressHex, portHex] = fields[1]!.split(":");
    if (!addressHex || !portHex) continue;
    const owner = owners.get(fields[9]!);
    ports.push(makePort(decodeProcAddress(addressHex), Number.parseInt(portHex, 16), owner?.name ?? null, owner?.pid ?? null));
  }
  return ports;
}

/** Socket inode to process, for the processes this user can see. */
export async function socketOwners(): Promise<Map<string, { name: string; pid: number }>> {
  const owners = new Map<string, { name: string; pid: number }>();
  let pids: string[];
  try {
    pids = (await readdir("/proc")).filter((name) => /^\d+$/.test(name));
  } catch {
    return owners;
  }
  for (const pid of pids) {
    let fds: string[];
    try {
      fds = await readdir(`/proc/${pid}/fd`);
    } catch {
      continue;
    }
    let name: string | null = null;
    for (const fd of fds) {
      const target = await readlink(`/proc/${pid}/fd/${fd}`).catch(() => "");
      const inode = /^socket:\[(\d+)\]$/.exec(target)?.[1];
      if (!inode) continue;
      name ??= (await readFile(`/proc/${pid}/comm`, "utf8").catch(() => pid)).trim();
      owners.set(inode, { name, pid: Number(pid) });
    }
  }
  return owners;
}

async function linuxListeningPorts(): Promise<ListeningPort[] | null> {
  const tables = await Promise.all(["/proc/net/tcp", "/proc/net/tcp6"].map((file) => readFile(file, "utf8").catch(() => null)));
  if (tables.every((table) => table === null)) {
    try {
      return parseSs(await run("ss", ["-ltnpH"]));
    } catch {
      return null;
    }
  }
  const owners = await socketOwners();
  return dedupe(tables.flatMap((table) => (table ? parseProcNetTcp(table, owners) : [])));
}

export async function listeningPorts(platform = process.platform): Promise<ListeningPort[] | null> {
  try {
    if (platform === "win32") {
      const [netstat, tasks] = await Promise.all([run("netstat", ["-ano", "-p", "TCP"]), run("tasklist", ["/fo", "csv", "/nh"]).catch(() => "")]);
      return parseNetstat(netstat, tasks);
    }
    // A cold lsof on a busy Mac can take more than 15 seconds (seen on CI).
    if (platform === "darwin") return parseLsof(await run("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"], 30_000));
    return await linuxListeningPorts();
  } catch {
    return null;
  }
}

// --- Startup programs ----------------------------------------------------------------

export interface StartupItem {
  /** Stable id used to notice new items between checks. */
  id: string;
  name: string;
  command: string;
  location: string;
  /** Path of the program it starts, when we can tell, so it can be scanned. */
  program: string | null;
  /** Where the entry lives (file, registry key or unit), so it can be switched off. */
  source?: string;
  warnings: string[];
}

const SUSPICIOUS_COMMANDS: [RegExp, string][] = [
  [/(^|[\\/])(temp|tmp|downloads|appdata[\\/]local[\\/]temp)[\\/]/i, "Starts a program from a temporary or Downloads folder"],
  [/powershell(\.exe)?\b.*\s-(e|en|enc|encodedcommand)\s/i, "Runs a hidden, encoded PowerShell command"],
  [/powershell(\.exe)?\b.*-w(indowstyle)?\s+hidden/i, "Runs PowerShell in a hidden window"],
  [/\b(mshta|wscript|cscript|regsvr32|rundll32)(\.exe)?\b.*(https?:|\.js\b|\.vbs\b|\.hta\b|javascript:)/i, "Uses a system tool to run a script, a common malware trick"],
  [/\b(curl|wget)\b.*\|\s*(ba|z)?sh\b/i, "Downloads and runs a script at every start"],
  [/https?:\/\//i, "Contacts a web address at every start"],
  [/[\\/]users[\\/]public[\\/]/i, "Starts a program from the shared Public folder"],
];

export function startupWarnings(command: string): string[] {
  return SUSPICIOUS_COMMANDS.filter(([pattern]) => pattern.test(command)).map(([, message]) => message);
}

/** First token of a command line: a quoted path, or up to the first space. */
export function programOf(command: string): string | null {
  const trimmed = command.trim();
  const quoted = /^"([^"]+)"/.exec(trimmed);
  const first = quoted ? quoted[1]! : trimmed.split(/\s+/)[0]!;
  return /^([a-z]:)?[\\/]/i.test(first) || first.startsWith("~") ? first : null;
}

function item(name: string, command: string, location: string, source?: string): StartupItem {
  return { id: `${location}|${name}`, name, command, location, program: programOf(command), warnings: startupWarnings(command), source };
}

/**
 * `reg query ...\Explorer\StartupApproved\Run` output: entries switched off in Task
 * Manager (or by Qalaa) have an odd first byte (03...).
 */
export function parseStartupApproved(stdout: string): Set<string> {
  const off = new Set<string>();
  for (const line of stdout.split(/\r?\n/)) {
    const match = /^\s{2,}(.+?)\s{2,}REG_BINARY\s{2,}([0-9A-F]{2})/i.exec(line);
    if (match && Number.parseInt(match[2]!, 16) % 2 === 1) off.add(match[1]!);
  }
  return off;
}

/** `reg query <key>` output: lines of "    Name    REG_SZ    value". */
export function parseRegRun(stdout: string, location: string): StartupItem[] {
  const items: StartupItem[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const match = /^\s{2,}(.+?)\s{2,}REG_(?:EXPAND_)?SZ\s{2,}(.*)$/.exec(line);
    if (match) items.push(item(match[1]!.trim(), match[2]!.trim(), location, location));
  }
  return items;
}

/** A freedesktop autostart `.desktop` file. Hidden=true or X-GNOME-Autostart-enabled=false means turned off. */
export function parseDesktopEntry(text: string, file: string, location: string): StartupItem | null {
  const section = text.split(/^\[Desktop Entry\]\s*$/m)[1]?.split(/^\[/m)[0] ?? "";
  const get = (key: string) => new RegExp(`^${key}=(.*)$`, "m").exec(section)?.[1]?.trim() ?? null;
  if (get("Hidden") === "true" || get("X-GNOME-Autostart-enabled") === "false") return null;
  const exec = get("Exec");
  if (!exec) return null;
  return item(get("Name") ?? basename(file, ".desktop"), exec, location, file);
}

/** A launchd plist (XML form). */
export function parseLaunchPlist(text: string, file: string, location: string): StartupItem | null {
  const label = /<key>Label<\/key>\s*<string>([^<]*)<\/string>/.exec(text)?.[1] ?? basename(file, ".plist");
  const program = /<key>Program<\/key>\s*<string>([^<]*)<\/string>/.exec(text)?.[1];
  const args = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(text)?.[1];
  const parts = args ? [...args.matchAll(/<string>([^<]*)<\/string>/g)].map((m) => m[1]!) : [];
  const command = [program, ...parts.slice(program ? 1 : 0)].filter(Boolean).join(" ") || parts.join(" ");
  if (!command) return null;
  if (/<key>Disabled<\/key>\s*<true\/>/.test(text)) return null;
  return item(label, command, location, file);
}

async function readDirFiles(dir: string, extension: string): Promise<string[]> {
  try {
    return (await readdir(dir)).filter((name) => name.endsWith(extension)).map((name) => join(dir, name));
  } catch {
    return [];
  }
}

export async function startupItems(platform = process.platform, home = homedir()): Promise<StartupItem[]> {
  const items: StartupItem[] = [];
  if (platform === "win32") {
    const keys = [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    ];
    const approved = async (hive: "HKCU" | "HKLM", kind: string) => {
      try {
        return parseStartupApproved(await run("reg", ["query", `${hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\${kind}`]));
      } catch {
        return new Set<string>();
      }
    };
    const off = { HKCU: await approved("HKCU", "Run"), HKLM: await approved("HKLM", "Run"), folder: await approved("HKCU", "StartupFolder") };
    for (const key of keys) {
      try {
        const disabled = key.startsWith("HKCU") ? off.HKCU : off.HKLM;
        items.push(...parseRegRun(await run("reg", ["query", key]), key).filter((entry) => !disabled.has(entry.name)));
      } catch {
        // key absent
      }
    }
    const folders = [
      join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
      join(process.env.ProgramData ?? "C:\\ProgramData", "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"),
    ];
    for (const folder of folders) {
      try {
        for (const name of await readdir(folder)) {
          if (name.toLowerCase() === "desktop.ini" || off.folder.has(name)) continue;
          const path = join(folder, name);
          items.push({ ...item(name, path, "Startup folder", path), program: path });
        }
      } catch {
        // folder absent
      }
    }
  } else if (platform === "darwin") {
    for (const dir of [join(home, "Library", "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]) {
      for (const file of await readDirFiles(dir, ".plist")) {
        try {
          let text = await readFile(file, "utf8");
          // Binary plists are converted with the system's own tool.
          if (text.startsWith("bplist")) text = await run("plutil", ["-convert", "xml1", "-o", "-", file]);
          const parsed = parseLaunchPlist(text, file, dir);
          if (parsed) items.push(parsed);
        } catch {
          // unreadable
        }
      }
    }
  } else {
    // A file in the user's autostart folder replaces the system one with the same name.
    const userAutostart = join(home, ".config", "autostart");
    const overridden = new Set((await readDirFiles(userAutostart, ".desktop")).map((file) => basename(file)));
    for (const dir of [userAutostart, "/etc/xdg/autostart"]) {
      for (const file of await readDirFiles(dir, ".desktop")) {
        if (dir !== userAutostart && overridden.has(basename(file))) continue;
        try {
          const parsed = parseDesktopEntry(await readFile(file, "utf8"), file, dir);
          if (parsed) items.push(parsed);
        } catch {
          // unreadable
        }
      }
    }
    try {
      const units = await run("systemctl", ["--user", "list-unit-files", "--state=enabled", "--no-legend", "--type=service"]);
      for (const line of units.split(/\r?\n/)) {
        const unit = line.trim().split(/\s+/)[0];
        if (unit) items.push(item(unit, unit, "systemd user services", unit));
      }
    } catch {
      // no systemd user session
    }
  }
  // A user's own entry overrides the system one with the same name (Linux autostart).
  const seen = new Set<string>();
  return items.filter((entry) => {
    const key = `${entry.name}|${entry.command}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// --- Camera and microphone -----------------------------------------------------------

export interface DeviceUse {
  device: "camera" | "microphone";
  app: string;
}

/**
 * Windows records every app's camera and microphone use in
 * `HKCU\...\CapabilityAccessManager\ConsentStore\{webcam,microphone}`.
 * An app is using the device now when LastUsedTimeStop is 0.
 */
export function parseConsentStore(stdout: string, device: DeviceUse["device"]): DeviceUse[] {
  const uses: DeviceUse[] = [];
  let current: string | null = null;
  let start = 0;
  for (const line of stdout.split(/\r?\n/)) {
    if (/^HKEY_/.test(line)) {
      current = line.trim().split("\\").pop() ?? null;
      start = 0;
      continue;
    }
    const match = /^\s+(LastUsedTimeStart|LastUsedTimeStop)\s+REG_QWORD\s+0x([0-9a-f]+)/i.exec(line);
    if (!match || !current || current === "NonPackaged") continue;
    if (match[1] === "LastUsedTimeStart") start = Number.parseInt(match[2]!, 16);
    else if (start > 0 && Number.parseInt(match[2]!, 16) === 0) {
      // Packaged apps use their package name; others an escaped path like C:#Program Files#App#app.exe
      uses.push({ device, app: current.includes("#") ? basename(current.replace(/#/g, "/")) : current.split("_")[0]! });
    }
  }
  return uses;
}

/** `pactl list source-outputs`: apps recording through PulseAudio or PipeWire. */
export function parsePactlSourceOutputs(stdout: string): DeviceUse[] {
  return [...stdout.matchAll(/application\.name = "([^"]+)"/g)].map((match) => ({ device: "microphone" as const, app: match[1]! }));
}

/** Linux: which of the user's processes hold /dev/video* open (no administrator rights needed for own processes). */
async function linuxCameraUsers(): Promise<DeviceUse[]> {
  const uses: DeviceUse[] = [];
  let pids: string[];
  try {
    pids = (await readdir("/proc")).filter((name) => /^\d+$/.test(name));
  } catch {
    return uses;
  }
  for (const pid of pids) {
    let fds: string[];
    try {
      fds = await readdir(`/proc/${pid}/fd`);
    } catch {
      continue; // another user's process
    }
    for (const fd of fds) {
      const target = await readlink(`/proc/${pid}/fd/${fd}`).catch(() => "");
      if (/^\/dev\/video\d+$/.test(target)) {
        const name = (await readFile(`/proc/${pid}/comm`, "utf8").catch(() => pid)).trim();
        uses.push({ device: "camera", app: name });
        break;
      }
    }
  }
  return uses;
}

export interface DeviceUseReport {
  uses: DeviceUse[];
  /** Devices this platform does not let us see. */
  unsupported: DeviceUse["device"][];
}

export async function cameraAndMicrophoneUse(platform = process.platform): Promise<DeviceUseReport> {
  if (platform === "win32") {
    const base = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore";
    const uses: DeviceUse[] = [];
    for (const [key, device] of [["webcam", "camera"], ["microphone", "microphone"]] as const) {
      try {
        uses.push(...parseConsentStore(await run("reg", ["query", `${base}\\${key}`, "/s"]), device));
      } catch {
        // key absent
      }
    }
    return { uses: dedupeUses(uses), unsupported: [] };
  }
  if (platform === "darwin") {
    // macOS shows its own green/orange dot and does not tell other apps which app is recording.
    return { uses: [], unsupported: ["camera", "microphone"] };
  }
  const uses = await linuxCameraUsers();
  let unsupported: DeviceUse["device"][] = [];
  try {
    uses.push(...parsePactlSourceOutputs(await run("pactl", ["list", "source-outputs"], 5_000)));
  } catch {
    unsupported = ["microphone"];
  }
  return { uses: dedupeUses(uses), unsupported };
}

function dedupeUses(uses: DeviceUse[]): DeviceUse[] {
  const seen = new Set<string>();
  return uses.filter((use) => {
    const key = `${use.device}|${use.app}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Uses in `now` that were not in `before`: the moments worth a notification. */
export function newUses(before: DeviceUse[], now: DeviceUse[]): DeviceUse[] {
  const known = new Set(before.map((use) => `${use.device}|${use.app}`));
  return now.filter((use) => !known.has(`${use.device}|${use.app}`));
}
