/**
 * Maintenance and inspection tools:
 *  - startup manager: switch programs that start with the computer off and on again;
 *  - junk cleanup: temporary files, caches and the trash, measured before deleting;
 *  - file shredder: overwrite, rename and delete files so ordinary recovery tools
 *    cannot bring them back;
 *  - browser extension audit for Chrome, Edge, Brave, Chromium and Firefox;
 *  - deep check for hidden persistence and rootkit tricks (scheduled tasks, cron,
 *    WMI subscriptions, debugger hijacks, hidden processes and kernel modules);
 *  - per-program firewall blocking (Windows and macOS).
 */
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, readdir, rename, rm, rmdir, unlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir, userInfo } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import { type StartupItem, startupWarnings } from "./security";

function run(command: string, args: string[], timeout = 30_000): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout, windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error && !stdout) reject(new Error(String(stderr || error.message).trim().slice(0, 300)));
      else resolve(String(stdout));
    });
  });
}

/** Runs a command elevated on Windows (UAC prompt), the same way service control does. */
function runElevatedWindows(command: string, args: string[]): Promise<string> {
  const quoted = args.map((a) => `'${a.replace(/'/g, "''")}'`).join(",");
  return run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `Start-Process -FilePath '${command}' -ArgumentList ${quoted} -Verb RunAs -Wait -WindowStyle Hidden`], 120_000);
}

// --- Startup manager ------------------------------------------------------------------------

export interface DisabledStartup {
  id: string;
  name: string;
  command: string;
  location: string;
  method: "xdg-user" | "xdg-override" | "systemd-user" | "win-approved" | "mac-agent";
  /** What is needed to undo it (file path, registry key, value name...). */
  data: Record<string, string>;
  at: string;
}

const APPROVED_OFF = "030000000000000000000000";
const APPROVED_ON = "020000000000000000000000";
const QALAA_MARK = "# Switched off by Qalaa Desktop";

/** Adds Hidden=true to a .desktop file's main section (pure). */
export function hideDesktopEntry(text: string): string {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim() === "[Desktop Entry]");
  if (start === -1) return `[Desktop Entry]\n${QALAA_MARK}\nHidden=true\n${text}`;
  const cleaned = lines.filter((line, i) => i <= start || !/^Hidden=/.test(line));
  cleaned.splice(start + 1, 0, QALAA_MARK, "Hidden=true");
  return cleaned.join("\n");
}

/** Undoes hideDesktopEntry (pure). */
export function unhideDesktopEntry(text: string): string {
  return text
    .split(/\r?\n/)
    .filter((line, i, all) => line !== QALAA_MARK && !(line === "Hidden=true" && all[i - 1] === QALAA_MARK))
    .join("\n");
}

export function canSwitchOff(item: StartupItem, platform: NodeJS.Platform = process.platform, home = homedir()): boolean {
  if (!item.source) return false;
  if (platform === "linux") return item.location === "systemd user services" || item.source.endsWith(".desktop");
  if (platform === "win32") return /^HK(CU|LM)\\/.test(item.source) && !/RunOnce/i.test(item.source) ? true : item.location === "Startup folder" && item.source.startsWith(home);
  if (platform === "darwin") return item.source.startsWith(join(home, "Library", "LaunchAgents"));
  return false;
}

export async function switchOffStartup(item: StartupItem, platform: NodeJS.Platform = process.platform, home = homedir()): Promise<DisabledStartup> {
  if (!canSwitchOff(item, platform, home)) throw new Error("This entry can only be changed with administrator tools.");
  const base = { id: item.id, name: item.name, command: item.command, location: item.location, at: new Date().toISOString() };
  const source = item.source!;
  if (platform === "linux") {
    if (item.location === "systemd user services") {
      await run("systemctl", ["--user", "disable", "--now", source]);
      return { ...base, method: "systemd-user", data: { unit: source } };
    }
    const userDir = join(home, ".config", "autostart");
    if (dirname(source) === userDir) {
      await writeFile(source, hideDesktopEntry(await readFile(source, "utf8")));
      return { ...base, method: "xdg-user", data: { file: source } };
    }
    await mkdir(userDir, { recursive: true });
    const override = join(userDir, basename(source));
    await writeFile(override, hideDesktopEntry(await readFile(source, "utf8")));
    return { ...base, method: "xdg-override", data: { file: override } };
  }
  if (platform === "win32") {
    const machine = source.startsWith("HKLM");
    const kind = item.location === "Startup folder" ? "StartupFolder" : /WOW6432Node/i.test(source) ? "Run32" : "Run";
    const key = `${machine ? "HKLM" : "HKCU"}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\${kind}`;
    const value = item.location === "Startup folder" ? basename(source) : item.name;
    const args = ["add", key, "/v", value, "/t", "REG_BINARY", "/d", APPROVED_OFF, "/f"];
    await (machine ? runElevatedWindows("reg.exe", args) : run("reg", args));
    return { ...base, method: "win-approved", data: { key, value, machine: String(machine) } };
  }
  if (platform === "darwin") {
    const parked = join(home, "Library", "LaunchAgents", "Switched off by Qalaa");
    await mkdir(parked, { recursive: true });
    const target = join(parked, basename(source));
    await run("launchctl", ["bootout", `gui/${userInfo().uid}`, source]).catch(() => "");
    await rename(source, target);
    return { ...base, method: "mac-agent", data: { from: source, to: target } };
  }
  throw new Error("Not supported on this system.");
}

export async function switchOnStartup(entry: DisabledStartup): Promise<void> {
  switch (entry.method) {
    case "systemd-user":
      await run("systemctl", ["--user", "enable", entry.data.unit!]);
      return;
    case "xdg-user":
      await writeFile(entry.data.file!, unhideDesktopEntry(await readFile(entry.data.file!, "utf8")));
      return;
    case "xdg-override":
      await unlink(entry.data.file!).catch(() => undefined);
      return;
    case "win-approved": {
      const args = ["add", entry.data.key!, "/v", entry.data.value!, "/t", "REG_BINARY", "/d", APPROVED_ON, "/f"];
      await (entry.data.machine === "true" ? runElevatedWindows("reg.exe", args) : run("reg", args));
      return;
    }
    case "mac-agent":
      await rename(entry.data.to!, entry.data.from!);
      await run("launchctl", ["bootstrap", `gui/${userInfo().uid}`, entry.data.from!]).catch(() => "");
      return;
  }
}

// --- Junk cleanup ---------------------------------------------------------------------------

export interface JunkCategory {
  id: "temp" | "browser-cache" | "app-cache" | "thumbnails" | "trash" | "crash-reports";
  label: string;
  roots: string[];
  /** Only files untouched for this long are removed (running programs may still use newer ones). */
  minAgeMs: number;
}

const HOUR = 3_600_000;

export function junkCategories(platform: NodeJS.Platform = process.platform, home = homedir(), env: NodeJS.ProcessEnv = process.env, temp = tmpdir()): JunkCategory[] {
  const local = env.LOCALAPPDATA ?? join(home, "AppData", "Local");
  const chromium = (root: string) => ["Default", "Profile 1", "Profile 2", "Profile 3"].flatMap((p) => [join(root, p, "Cache"), join(root, p, "Code Cache"), join(root, p, "GPUCache")]);
  if (platform === "win32") {
    return [
      { id: "temp", label: "Temporary files", roots: [temp], minAgeMs: 24 * HOUR },
      {
        id: "browser-cache",
        label: "Browser caches",
        roots: [
          ...chromium(join(local, "Google", "Chrome", "User Data")),
          ...chromium(join(local, "Microsoft", "Edge", "User Data")),
          ...chromium(join(local, "BraveSoftware", "Brave-Browser", "User Data")),
          join(local, "Mozilla", "Firefox", "Profiles"),
        ],
        minAgeMs: HOUR,
      },
      { id: "thumbnails", label: "Thumbnail cache", roots: [join(local, "Microsoft", "Windows", "Explorer")], minAgeMs: 24 * HOUR },
      { id: "crash-reports", label: "Crash reports", roots: [join(local, "CrashDumps"), join(local, "Microsoft", "Windows", "WER", "ReportArchive")], minAgeMs: HOUR },
    ];
  }
  if (platform === "darwin") {
    const caches = join(home, "Library", "Caches");
    return [
      { id: "temp", label: "Temporary files", roots: [temp], minAgeMs: 24 * HOUR },
      { id: "browser-cache", label: "Browser caches", roots: [join(caches, "Google", "Chrome"), join(caches, "com.apple.Safari"), join(caches, "Firefox"), join(caches, "BraveSoftware")], minAgeMs: HOUR },
      { id: "app-cache", label: "Application caches", roots: [caches], minAgeMs: 7 * 24 * HOUR },
      { id: "crash-reports", label: "Crash reports", roots: [join(home, "Library", "Logs", "DiagnosticReports")], minAgeMs: HOUR },
      { id: "trash", label: "Trash", roots: [join(home, ".Trash")], minAgeMs: 0 },
    ];
  }
  const cache = env.XDG_CACHE_HOME ?? join(home, ".cache");
  return [
    { id: "temp", label: "Temporary files", roots: [temp], minAgeMs: 24 * HOUR },
    {
      id: "browser-cache",
      label: "Browser caches",
      roots: [join(cache, "google-chrome"), join(cache, "chromium"), join(cache, "BraveSoftware"), join(cache, "microsoft-edge"), join(cache, "mozilla", "firefox")],
      minAgeMs: HOUR,
    },
    { id: "thumbnails", label: "Thumbnail cache", roots: [join(cache, "thumbnails")], minAgeMs: 24 * HOUR },
    { id: "app-cache", label: "Application caches", roots: [join(cache, "pip"), join(cache, "yarn"), join(cache, "go-build"), join(home, ".npm", "_cacache")], minAgeMs: 7 * 24 * HOUR },
    { id: "trash", label: "Trash", roots: [join(env.XDG_DATA_HOME ?? join(home, ".local", "share"), "Trash")], minAgeMs: 0 },
  ];
}

const MAX_JUNK_FILES = 200_000;

/** Regular files under `root` (never following links), oldest-first irrelevant. */
async function* junkFiles(root: string, minAgeMs: number, now: number, budget: { left: number }): AsyncGenerator<{ path: string; size: number }> {
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (budget.left <= 0) return;
    const path = join(root, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      yield* junkFiles(path, minAgeMs, now, budget);
    } else if (entry.isFile()) {
      try {
        const info = await lstat(path);
        if (now - info.mtimeMs < minAgeMs) continue;
        budget.left -= 1;
        yield { path, size: info.size };
      } catch {
        // vanished
      }
    }
  }
}

export interface JunkSummary {
  id: JunkCategory["id"];
  label: string;
  files: number;
  bytes: number;
}

export async function measureJunk(categories: JunkCategory[], now = Date.now()): Promise<JunkSummary[]> {
  const out: JunkSummary[] = [];
  for (const category of categories) {
    let files = 0;
    let bytes = 0;
    const budget = { left: MAX_JUNK_FILES };
    for (const root of category.roots) {
      for await (const file of junkFiles(root, category.minAgeMs, now, budget)) {
        files += 1;
        bytes += file.size;
      }
    }
    out.push({ id: category.id, label: category.label, files, bytes });
  }
  return out;
}

async function pruneEmptyDirs(dir: string, root: string): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) if (entry.isDirectory() && !entry.isSymbolicLink()) await pruneEmptyDirs(join(dir, entry.name), root);
  if (dir !== root) await rmdir(dir).catch(() => undefined);
}

export async function cleanJunk(categories: JunkCategory[], ids: string[], now = Date.now()): Promise<{ files: number; bytes: number; skipped: number }> {
  const totals = { files: 0, bytes: 0, skipped: 0 };
  for (const category of categories.filter((c) => ids.includes(c.id))) {
    const budget = { left: MAX_JUNK_FILES };
    for (const root of category.roots) {
      for await (const file of junkFiles(root, category.minAgeMs, now, budget)) {
        try {
          await unlink(file.path);
          totals.files += 1;
          totals.bytes += file.size;
        } catch {
          totals.skipped += 1; // in use or protected
        }
      }
      await pruneEmptyDirs(root, root);
    }
  }
  return totals;
}

// --- File shredder --------------------------------------------------------------------------

export interface ShredGuard {
  /** Nothing inside these may be shredded (system folders, Qalaa's own data). */
  inside: string[];
  /** These folders themselves (and their parents) may not be shredded, but files in them may (the home folder). */
  exact: string[];
}

/** Why a path may not be shredded, or null when it may. */
export function shredRefusal(path: string, guard: ShredGuard, platform: NodeJS.Platform = process.platform): string | null {
  const fold = (p: string) => (platform === "win32" || platform === "darwin" ? p.toLowerCase() : p);
  const sepChar = platform === "win32" ? "\\" : "/";
  const clean = (p: string) => {
    let value = platform === "win32" ? p.replace(/\//g, "\\") : resolve(p);
    while (value.length > 1 && value.endsWith(sepChar) && !/^[a-z]:\\$/i.test(value)) value = value.slice(0, -1);
    return fold(value);
  };
  const target = clean(path);
  if (target === "/" || /^[a-z]:\\?$/i.test(target)) return "A whole drive cannot be shredded.";
  const within = (child: string, parent: string) => child === parent || child.startsWith(parent.endsWith(sepChar) ? parent : parent + sepChar);
  for (const root of guard.exact.map(clean)) {
    if (within(root, target)) return "This folder contains your whole home folder and cannot be shredded.";
  }
  for (const root of guard.inside.map(clean)) {
    if (within(target, root) || within(root, target)) return "This is a system folder, or Qalaa's own data, and cannot be shredded.";
  }
  return null;
}

export function shredGuard(platform: NodeJS.Platform = process.platform, home = homedir(), appData: string[] = []): ShredGuard {
  if (platform === "win32") {
    const env = process.env;
    return {
      inside: [env.SystemRoot ?? "C:\\Windows", env.ProgramFiles ?? "C:\\Program Files", env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)", env.ProgramData ?? "C:\\ProgramData", ...appData],
      exact: [home],
    };
  }
  return {
    inside: ["/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/opt", "/proc", "/run", "/sbin", "/snap", "/srv", "/sys", "/usr", "/var", "/System", "/Library", "/Applications", "/private", ...appData],
    exact: [home],
  };
}

async function shredFile(path: string, size: number, passes: number): Promise<void> {
  const handle = await open(path, constants.O_WRONLY);
  try {
    const chunk = 1024 * 1024;
    for (let pass = 0; pass < passes; pass++) {
      for (let offset = 0; offset < size; offset += chunk) {
        const length = Math.min(chunk, size - offset);
        const data = pass === passes - 1 || pass % 2 === 0 ? randomBytes(length) : Buffer.alloc(length, 0xff);
        await handle.write(data, 0, length, offset);
      }
      await handle.sync();
    }
    await handle.truncate(0);
  } finally {
    await handle.close();
  }
  // A random name hides the original file name from recovery tools too.
  const renamed = join(dirname(path), randomBytes(12).toString("hex"));
  await rename(path, renamed);
  await unlink(renamed);
}

export async function shred(path: string, passes = 1): Promise<{ files: number; bytes: number }> {
  const totals = { files: 0, bytes: 0 };
  const info = await lstat(path);
  if (info.isSymbolicLink()) {
    await unlink(path); // only the link: its target is not shredded
    return totals;
  }
  if (info.isDirectory()) {
    for (const name of await readdir(path)) {
      const inner = await shred(join(path, name), passes);
      totals.files += inner.files;
      totals.bytes += inner.bytes;
    }
    await rm(path, { recursive: false, force: true }).catch(() => rmdir(path));
    return totals;
  }
  if (info.isFile()) {
    await shredFile(path, info.size, Math.min(Math.max(1, passes), 7));
    totals.files += 1;
    totals.bytes += info.size;
  }
  return totals;
}

// --- Browser extensions ---------------------------------------------------------------------

export interface ExtensionInfo {
  browser: string;
  profile: string;
  id: string;
  name: string;
  version: string;
  fromStore: boolean;
  enabled: boolean;
  risk: "high" | "medium" | "low";
  reasons: string[];
}

const BROAD_HOSTS = /^(<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|\*:\/\/\*\.?[^/]*\/\*|file:\/\/\/\*)$/;
const POWERFUL: Record<string, string> = {
  debugger: "can control pages through the debugger",
  nativeMessaging: "can talk to programs installed on this computer",
  proxy: "can redirect all your browsing through another server",
  management: "can switch your other extensions on and off",
  cookies: "can read and change cookies (including sign-ins)",
  webRequest: "can watch every request your browser makes",
  webRequestBlocking: "can change requests your browser makes",
  declarativeNetRequestWithHostAccess: "can redirect requests",
  history: "can read your browsing history",
  clipboardRead: "can read the clipboard",
  downloads: "can start downloads",
  privacy: "can change privacy settings",
  scripting: "can run scripts in pages",
};

/** Plain-language risk for one extension manifest (Chrome-family or Firefox). */
export function assessExtension(manifest: Record<string, unknown>, fromStore: boolean): { risk: ExtensionInfo["risk"]; reasons: string[] } {
  const list = (value: unknown) => (Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : []);
  const permissions = [...list(manifest.permissions), ...list(manifest.optional_permissions)];
  const contentScripts = Array.isArray(manifest.content_scripts) ? (manifest.content_scripts as { matches?: unknown }[]).flatMap((c) => list(c.matches)) : [];
  const hosts = [...list(manifest.host_permissions), ...permissions.filter((p) => p.includes("://") || p === "<all_urls>"), ...contentScripts];
  const reasons: string[] = [];
  const everySite = hosts.some((h) => BROAD_HOSTS.test(h));
  if (everySite) reasons.push("can read and change every website you visit");
  for (const permission of permissions) if (POWERFUL[permission]) reasons.push(POWERFUL[permission]!);
  if (!fromStore) reasons.push("was not installed from the browser's store");
  const strong = reasons.filter((r) => /debugger|programs installed|redirect all|switch your other|cookies|watch every|change requests/.test(r)).length;
  const risk: ExtensionInfo["risk"] = (everySite && strong >= 1) || (!fromStore && everySite) ? "high" : everySite || strong >= 1 || !fromStore ? "medium" : "low";
  return { risk, reasons };
}

function chromiumRoots(platform: NodeJS.Platform, home: string, env: NodeJS.ProcessEnv): { browser: string; root: string }[] {
  if (platform === "win32") {
    const local = env.LOCALAPPDATA ?? join(home, "AppData", "Local");
    return [
      { browser: "Chrome", root: join(local, "Google", "Chrome", "User Data") },
      { browser: "Edge", root: join(local, "Microsoft", "Edge", "User Data") },
      { browser: "Brave", root: join(local, "BraveSoftware", "Brave-Browser", "User Data") },
    ];
  }
  if (platform === "darwin") {
    const support = join(home, "Library", "Application Support");
    return [
      { browser: "Chrome", root: join(support, "Google", "Chrome") },
      { browser: "Edge", root: join(support, "Microsoft Edge") },
      { browser: "Brave", root: join(support, "BraveSoftware", "Brave-Browser") },
    ];
  }
  const config = env.XDG_CONFIG_HOME ?? join(home, ".config");
  return [
    { browser: "Chrome", root: join(config, "google-chrome") },
    { browser: "Chromium", root: join(config, "chromium") },
    { browser: "Edge", root: join(config, "microsoft-edge") },
    { browser: "Brave", root: join(config, "BraveSoftware", "Brave-Browser") },
  ];
}

function firefoxRoot(platform: NodeJS.Platform, home: string, env: NodeJS.ProcessEnv): string {
  if (platform === "win32") return join(env.APPDATA ?? join(home, "AppData", "Roaming"), "Mozilla", "Firefox", "Profiles");
  if (platform === "darwin") return join(home, "Library", "Application Support", "Firefox", "Profiles");
  return join(home, ".mozilla", "firefox");
}

async function localisedName(dir: string, name: string, locale: string | undefined): Promise<string> {
  const match = /^__MSG_(.+)__$/.exec(name);
  if (!match) return name;
  for (const lang of [locale, "en", "en_US"].filter(Boolean) as string[]) {
    try {
      const messages = JSON.parse(await readFile(join(dir, "_locales", lang, "messages.json"), "utf8")) as Record<string, { message?: string }>;
      const key = Object.keys(messages).find((k) => k.toLowerCase() === match[1]!.toLowerCase());
      if (key && messages[key]?.message) return messages[key]!.message!;
    } catch {
      // try the next language
    }
  }
  return match[1]!;
}

const STORE_UPDATE = /clients2\.google\.com\/service\/update2\/crx|edge\.microsoft\.com\/extensionwebstorebase/;

export async function browserExtensions(platform: NodeJS.Platform = process.platform, home = homedir(), env: NodeJS.ProcessEnv = process.env): Promise<ExtensionInfo[]> {
  const out: ExtensionInfo[] = [];
  for (const { browser, root } of chromiumRoots(platform, home, env)) {
    const profiles = (await readdir(root).catch(() => [] as string[])).filter((p) => p === "Default" || /^Profile \d+$/.test(p));
    for (const profile of profiles) {
      let prefs: Record<string, { state?: number; disable_reasons?: number }> = {};
      try {
        const raw = JSON.parse(await readFile(join(root, profile, "Secure Preferences"), "utf8")) as { extensions?: { settings?: typeof prefs } };
        prefs = raw.extensions?.settings ?? {};
      } catch {
        // older browsers keep this in Preferences; enabled state then unknown
      }
      const extDir = join(root, profile, "Extensions");
      for (const id of await readdir(extDir).catch(() => [] as string[])) {
        if (!/^[a-p]{32}$/.test(id)) continue;
        const versions = await readdir(join(extDir, id)).catch(() => [] as string[]);
        const version = versions.sort().pop();
        if (!version) continue;
        try {
          const dir = join(extDir, id, version);
          const manifest = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")) as Record<string, unknown>;
          const fromStore = typeof manifest.update_url === "string" ? STORE_UPDATE.test(manifest.update_url) : true;
          const { risk, reasons } = assessExtension(manifest, fromStore);
          const setting = prefs[id];
          out.push({
            browser,
            profile,
            id,
            name: await localisedName(dir, String(manifest.name ?? id), typeof manifest.default_locale === "string" ? manifest.default_locale : undefined),
            version: String(manifest.version ?? version),
            fromStore,
            enabled: setting ? setting.state !== 0 && !setting.disable_reasons : true,
            risk,
            reasons,
          });
        } catch {
          // unreadable manifest
        }
      }
    }
  }
  const ff = firefoxRoot(platform, home, env);
  for (const profile of await readdir(ff).catch(() => [] as string[])) {
    try {
      const data = JSON.parse(await readFile(join(ff, profile, "extensions.json"), "utf8")) as {
        addons?: { id: string; type: string; location: string; active: boolean; version: string; defaultLocale?: { name?: string }; userPermissions?: { permissions?: string[]; origins?: string[] }; signedState?: number }[];
      };
      for (const addon of data.addons ?? []) {
        if (addon.type !== "extension" || addon.location !== "app-profile") continue;
        const fromStore = (addon.signedState ?? 2) >= 2;
        const { risk, reasons } = assessExtension({ permissions: addon.userPermissions?.permissions ?? [], host_permissions: addon.userPermissions?.origins ?? [] }, fromStore);
        out.push({ browser: "Firefox", profile, id: addon.id, name: addon.defaultLocale?.name ?? addon.id, version: addon.version, fromStore, enabled: addon.active, risk, reasons });
      }
    } catch {
      // not a profile
    }
  }
  const rank = { high: 0, medium: 1, low: 2 };
  return out.sort((a, b) => rank[a.risk] - rank[b.risk] || a.name.localeCompare(b.name));
}

// --- Deep check: hidden persistence and rootkit tricks ----------------------------------

export interface DeepFinding {
  area: string;
  item: string;
  severity: "high" | "medium" | "low";
  detail: string;
}

/** Linux: process IDs that answer to a signal but are missing from /proc's listing. */
export function hiddenPids(listed: Set<number>, alive: number[], isThread: (pid: number) => boolean): number[] {
  return alive.filter((pid) => !listed.has(pid) && !isThread(pid));
}

/** Linux: modules loaded (initstate in /sys/module) but missing from /proc/modules. */
export function hiddenModules(procModules: string, loadedInSys: string[]): string[] {
  const listed = new Set(procModules.split("\n").map((line) => line.split(" ")[0]).filter(Boolean));
  return loadedInSys.filter((name) => !listed.has(name));
}

/** crontab lines that run something (comments, variables and blank lines skipped). */
export function parseCrontab(text: string, source: string, systemFormat = false): { source: string; command: string }[] {
  const out: { source: string; command: string }[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || /^[A-Z_]+=/.test(line)) continue;
    const fields = line.split(/\s+/);
    const skip = line.startsWith("@") ? 1 : 5;
    const command = fields.slice(skip + (systemFormat ? 1 : 0)).join(" ");
    if (command) out.push({ source, command });
  }
  return out;
}

/** `schtasks /query /fo CSV /v` (header + rows). Returns task name and what it runs. */
export function parseSchtasksCsv(text: string): { name: string; command: string; author: string }[] {
  const rows = text.split(/\r?\n/).filter(Boolean).map((line) => [...line.matchAll(/"((?:[^"]|"")*)"/g)].map((m) => m[1]!.replace(/""/g, '"')));
  const header = rows[0];
  if (!header) return [];
  const col = (name: RegExp) => header.findIndex((h) => name.test(h));
  const nameAt = col(/^TaskName$/i);
  const runAt = col(/^Task To Run$/i);
  const authorAt = col(/^Author$/i);
  if (nameAt < 0 || runAt < 0) return [];
  const seen = new Set<string>();
  return rows.slice(1).filter((r) => r[nameAt] && r[nameAt] !== header[nameAt]).flatMap((r) => {
    const key = `${r[nameAt]}|${r[runAt]}`;
    if (seen.has(key)) return [];
    seen.add(key);
    return [{ name: r[nameAt]!, command: r[runAt] ?? "", author: authorAt >= 0 ? r[authorAt] ?? "" : "" }];
  });
}

/** `reg query "HKLM\...\Image File Execution Options" /s /v Debugger`. */
export function parseIfeo(text: string): { program: string; debugger: string }[] {
  const out: { program: string; debugger: string }[] = [];
  let current = "";
  for (const line of text.split(/\r?\n/)) {
    const key = /Image File Execution Options\\([^\\]+)$/i.exec(line.trim());
    if (key) current = key[1]!;
    const value = /^\s+Debugger\s+REG_(?:EXPAND_)?SZ\s+(.*)$/i.exec(line);
    if (value && current) out.push({ program: current, debugger: value[1]!.trim() });
  }
  return out;
}

/** Winlogon Shell/Userinit values that differ from Windows' defaults. */
export function parseWinlogon(text: string): { value: string; data: string }[] {
  const out: { value: string; data: string }[] = [];
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s+(Shell|Userinit)\s+REG_(?:EXPAND_)?SZ\s+(.*)$/i.exec(line);
    if (!match) continue;
    const data = match[2]!.trim();
    const normal = match[1]!.toLowerCase() === "shell" ? /^explorer\.exe,?$/i.test(data) : /^[a-z]:\\windows\\system32\\userinit\.exe,?$/i.test(data);
    if (!normal) out.push({ value: match[1]!, data });
  }
  return out;
}

const ACCESSIBILITY = /^(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe$/i;

export async function deepCheck(platform: NodeJS.Platform = process.platform, home = homedir()): Promise<{ findings: DeepFinding[]; checked: string[] }> {
  const findings: DeepFinding[] = [];
  const checked: string[] = [];
  const flagCommand = (area: string, item: string, command: string) => {
    const warnings = startupWarnings(command).filter((w) => w !== "Contacts a web address at every start");
    if (/\/dev\/shm\/|\/tmp\/\.|\bbase64\s+-d\b|\bnc(at)?\s.*-e\b|\/dev\/tcp\//i.test(command)) warnings.push("Runs something from a hidden or temporary place, or opens a network shell");
    if (warnings.length) findings.push({ area, item, severity: "high", detail: `${warnings.join("; ")}: ${command.slice(0, 300)}` });
  };

  if (platform === "linux") {
    checked.push("Scheduled jobs (cron)", "System services", "Preloaded libraries", "Hidden processes", "Hidden kernel modules");
    const cron: { source: string; command: string }[] = [];
    cron.push(...parseCrontab(await run("crontab", ["-l"]).catch(() => ""), "your crontab"));
    cron.push(...parseCrontab(await readFile("/etc/crontab", "utf8").catch(() => ""), "/etc/crontab", true));
    for (const file of await readdir("/etc/cron.d").catch(() => [] as string[])) {
      cron.push(...parseCrontab(await readFile(join("/etc/cron.d", file), "utf8").catch(() => ""), `/etc/cron.d/${file}`, true));
    }
    for (const entry of cron) flagCommand("Scheduled job", entry.source, entry.command);

    for (const dir of ["/etc/systemd/system", join(home, ".config", "systemd", "user")]) {
      for (const file of (await readdir(dir).catch(() => [] as string[])).filter((f) => f.endsWith(".service"))) {
        const text = await readFile(join(dir, file), "utf8").catch(() => "");
        for (const match of text.matchAll(/^Exec(Start|StartPre|StartPost)=(.*)$/gm)) flagCommand("Service", `${dir}/${file}`, match[2]!);
      }
    }
    const preload = (await readFile("/etc/ld.so.preload", "utf8").catch(() => "")).trim();
    if (preload) findings.push({ area: "Preloaded libraries", item: "/etc/ld.so.preload", severity: "high", detail: `Every program loads: ${preload.slice(0, 200)}. Rootkits use this to hide files and processes; legitimate systems rarely do.` });

    const listed = new Set((await readdir("/proc").catch(() => [] as string[])).filter((n) => /^\d+$/.test(n)).map(Number));
    const max = Math.min(Number((await readFile("/proc/sys/kernel/pid_max", "utf8").catch(() => "32768")).trim()) || 32768, 4_194_304, Math.max(65_536, ...listed) + 1024);
    const alive: number[] = [];
    for (let pid = 2; pid < max; pid++) {
      if (listed.has(pid)) continue;
      try {
        process.kill(pid, 0);
        alive.push(pid);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EPERM") alive.push(pid);
      }
    }
    // A process started during the sweep is not hidden: it must also be missing from a second listing.
    const relisted = new Set((await readdir("/proc").catch(() => [] as string[])).filter((n) => /^\d+$/.test(n)).map(Number));
    const stillAlive = (pid: number) => {
      try {
        process.kill(pid, 0);
        return true;
      } catch (error) {
        return (error as NodeJS.ErrnoException).code === "EPERM";
      }
    };
    const candidates = alive.filter((pid) => !relisted.has(pid) && stillAlive(pid));
    alive.length = 0;
    alive.push(...candidates);
    const tgid = async (pid: number) => Number(/^Tgid:\s+(\d+)/m.exec(await readFile(`/proc/${pid}/status`, "utf8").catch(() => ""))?.[1] ?? pid);
    const threads = new Set<number>();
    for (const pid of alive) if ((await tgid(pid)) !== pid) threads.add(pid);
    for (const pid of hiddenPids(listed, alive, (p) => threads.has(p))) {
      findings.push({ area: "Hidden process", item: `PID ${pid}`, severity: "high", detail: "This process is running but hidden from the process list, a sign of a rootkit." });
    }
    const sysModules: string[] = [];
    for (const name of await readdir("/sys/module").catch(() => [] as string[])) {
      if ((await readFile(join("/sys/module", name, "initstate"), "utf8").catch(() => "")).trim() === "live") sysModules.push(name);
    }
    const procModules = await readFile("/proc/modules", "utf8").catch(() => null);
    if (procModules !== null) {
      for (const name of hiddenModules(procModules, sysModules)) {
        findings.push({ area: "Hidden kernel module", item: name, severity: "high", detail: "This kernel module is loaded but hidden from the module list, a classic rootkit trick." });
      }
    }
  } else if (platform === "win32") {
    checked.push("Scheduled tasks", "WMI event subscriptions", "Debugger hijacks", "Sign-in shell (Winlogon)");
    for (const task of parseSchtasksCsv(await run("schtasks", ["/query", "/fo", "CSV", "/v"], 60_000).catch(() => ""))) {
      if (/^\\Microsoft\\/i.test(task.name)) continue;
      flagCommand("Scheduled task", task.name, task.command);
    }
    const wmi = await run("powershell.exe", [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.CimClass.CimClassName -in 'CommandLineEventConsumer','ActiveScriptEventConsumer' } | Select-Object Name,CommandLineTemplate,ScriptText | ConvertTo-Json -Compress",
    ]).catch(() => "");
    if (wmi.trim()) {
      try {
        const parsed = JSON.parse(wmi) as { Name?: string; CommandLineTemplate?: string; ScriptText?: string } | { Name?: string }[];
        for (const consumer of (Array.isArray(parsed) ? parsed : [parsed]) as { Name?: string; CommandLineTemplate?: string; ScriptText?: string }[]) {
          if (consumer.Name === "SCM Event Log Consumer") continue;
          findings.push({ area: "WMI subscription", item: consumer.Name ?? "unnamed", severity: "high", detail: `Runs automatically on a system event: ${(consumer.CommandLineTemplate ?? consumer.ScriptText ?? "").slice(0, 300)}` });
        }
      } catch {
        // unparseable
      }
    }
    const ifeo = await run("reg", ["query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "/s", "/v", "Debugger"]).catch(() => "");
    for (const entry of parseIfeo(ifeo)) {
      findings.push({
        area: "Debugger hijack",
        item: entry.program,
        severity: ACCESSIBILITY.test(entry.program) ? "high" : "medium",
        detail: `Starting ${entry.program} runs “${entry.debugger.slice(0, 200)}” instead${ACCESSIBILITY.test(entry.program) ? ". On an accessibility tool this is a known back door at the sign-in screen" : ""}.`,
      });
    }
    const winlogon = await run("reg", ["query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"]).catch(() => "");
    for (const entry of parseWinlogon(winlogon)) findings.push({ area: "Sign-in shell", item: entry.value, severity: "high", detail: `Windows starts “${entry.data.slice(0, 200)}” at every sign-in instead of the default.` });
  } else if (platform === "darwin") {
    checked.push("Scheduled jobs (cron)", "Login hooks", "Launch daemons");
    for (const entry of parseCrontab(await run("crontab", ["-l"]).catch(() => ""), "your crontab")) flagCommand("Scheduled job", entry.source, entry.command);
    const hook = await run("defaults", ["read", "com.apple.loginwindow", "LoginHook"]).catch(() => "");
    if (hook.trim()) findings.push({ area: "Login hook", item: "com.apple.loginwindow", severity: "medium", detail: `Runs at every login (an old mechanism malware still uses): ${hook.trim().slice(0, 200)}` });
  }
  return { findings, checked };
}

// --- Firewall: block a program --------------------------------------------------------------

export const RULE_PREFIX = "Qalaa block: ";

/** File name of a Windows or POSIX path, whatever system runs this code. */
const fileName = (path: string) => path.split(/[\\/]/).pop() ?? path;

export function netshBlockArgs(program: string, direction: "in" | "out"): string[] {
  return ["advfirewall", "firewall", "add", "rule", `name=${RULE_PREFIX}${fileName(program)}`, `dir=${direction}`, "action=block", `program=${program}`, "enable=yes"];
}

/** `netsh advfirewall firewall show rule name=all verbose` → programs blocked by Qalaa. */
export function parseNetshRules(text: string): string[] {
  const programs = new Set<string>();
  for (const block of text.split(/\r?\n\s*\r?\n/)) {
    if (!block.includes(RULE_PREFIX)) continue;
    const program = /^Program:\s+(.+)$/im.exec(block)?.[1]?.trim();
    if (program) programs.add(program);
  }
  return [...programs];
}

export function firewallBlockSupported(platform: NodeJS.Platform = process.platform): boolean {
  return platform === "win32" || platform === "darwin";
}

export async function blockProgram(program: string, platform: NodeJS.Platform = process.platform): Promise<void> {
  if (!/^([a-z]:\\|\/)/i.test(program)) throw new Error("Choose the program's full path.");
  if (platform === "win32") {
    // Both rules in one elevated step: netsh via cmd /c so a single UAC prompt covers them.
    const quote = (a: string) => (a.includes(" ") ? `"${a}"` : a);
    const both = `netsh ${netshBlockArgs(program, "out").map(quote).join(" ")} && netsh ${netshBlockArgs(program, "in").map(quote).join(" ")}`;
    await runElevatedWindows("cmd.exe", ["/c", both]);
    return;
  }
  if (platform === "darwin") {
    const fw = "/usr/libexec/ApplicationFirewall/socketfilterfw";
    const script = `do shell script "${fw} --add '${program.replace(/'/g, "")}' && ${fw} --blockapp '${program.replace(/'/g, "")}'" with administrator privileges`;
    await run("osascript", ["-e", script], 120_000);
    return;
  }
  throw new Error("Blocking a single program is not available on Linux; use your firewall's rules (ufw or firewalld) instead.");
}

export async function unblockProgram(program: string, platform: NodeJS.Platform = process.platform): Promise<void> {
  if (platform === "win32") {
    await runElevatedWindows("netsh.exe", ["advfirewall", "firewall", "delete", "rule", `name=${RULE_PREFIX}${fileName(program)}`, `program=${program}`]);
    return;
  }
  if (platform === "darwin") {
    const fw = "/usr/libexec/ApplicationFirewall/socketfilterfw";
    await run("osascript", ["-e", `do shell script "${fw} --unblockapp '${program.replace(/'/g, "")}'" with administrator privileges`], 120_000);
    return;
  }
  throw new Error("Not available on this system.");
}

export async function blockedPrograms(platform: NodeJS.Platform = process.platform): Promise<string[]> {
  if (platform === "win32") return parseNetshRules(await run("netsh", ["advfirewall", "firewall", "show", "rule", "name=all", "verbose"], 60_000).catch(() => ""));
  if (platform === "darwin") {
    const text = await run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--listapps"]).catch(() => "");
    const out: string[] = [];
    const lines = text.split("\n");
    lines.forEach((line, i) => {
      const path = /^\d+\s*:\s+(\/.+?)\s*$/.exec(line)?.[1];
      if (path && /Block incoming connections/i.test(lines[i + 1] ?? "")) out.push(path);
    });
    return out;
  }
  return [];
}
