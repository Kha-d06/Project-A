/**
 * Protection features around the scanner:
 *  - scan exclusions (files and folders the person chose to skip);
 *  - ransomware decoy files: hidden files in protected folders that nothing
 *    should ever touch, so any change to them is an early, reliable alarm;
 *  - removable drives: new USB drives and memory cards are noticed and scanned;
 *  - silent mode: no pop-ups and no scheduled work for a while (games,
 *    presentations), while protection keeps running.
 */
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { type FSWatcher, watch } from "node:fs";
import { lstat, open, readFile, readdir, realpath, rename, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join, normalize } from "node:path";

import type { Finding } from "./types";

// --- Exclusions ---------------------------------------------------------------------------

const caseInsensitive = (platform: NodeJS.Platform) => platform === "win32" || platform === "darwin";

function comparable(path: string, platform: NodeJS.Platform): string {
  const separator = platform === "win32" ? "\\" : "/";
  let value = platform === "win32" ? path.replace(/\//g, "\\") : normalize(path);
  while (value.length > 1 && value.endsWith(separator) && !/^[a-z]:\\$/i.test(value)) value = value.slice(0, -1);
  return caseInsensitive(platform) ? value.toLowerCase() : value;
}

/** True when `path` is an excluded file or lies inside an excluded folder. */
export function isExcluded(path: string, exclusions: string[], platform: NodeJS.Platform = process.platform): boolean {
  if (!exclusions.length) return false;
  const separator = platform === "win32" ? "\\" : "/";
  const target = comparable(path, platform);
  return exclusions.some((entry) => {
    const excluded = comparable(entry, platform);
    return target === excluded || target.startsWith(excluded.endsWith(separator) ? excluded : excluded + separator);
  });
}

/** Absolute paths only, without duplicates; the root of a drive cannot be excluded. */
export function sanitizeExclusions(input: unknown, platform: NodeJS.Platform = process.platform): string[] | null {
  if (!Array.isArray(input)) return null;
  const out: string[] = [];
  const seen = new Set<string>();
  for (const value of input) {
    if (typeof value !== "string" || value.length > 1024) continue;
    const path = value.trim();
    const absolute = platform === "win32" ? /^[a-z]:[\\/]|^\\\\/i.test(path) : isAbsolute(path);
    if (!absolute) continue;
    const key = comparable(path, platform);
    if (key === "/" || /^[a-z]:\\?$/i.test(key) || seen.has(key)) continue;
    seen.add(key);
    out.push(path);
    if (out.length >= 200) break;
  }
  return out;
}

// --- Ransomware decoys --------------------------------------------------------------------

/**
 * Names chosen so that ransomware, which usually walks folders in name order, reaches
 * one of them first and one last. Hidden (dot files; the hidden attribute on Windows).
 */
export function decoyNames(platform: NodeJS.Platform = process.platform): string[] {
  return platform === "win32" ? ["!qalaa-decoy.docx", "~qalaa-decoy.xlsx"] : [".qalaa-decoy.docx", ".~qalaa-decoy.xlsx"];
}

export function isDecoy(path: string, platform: NodeJS.Platform = process.platform): boolean {
  const name = path.split(/[\\/]/).pop() ?? "";
  return decoyNames(platform).includes(name);
}

/** Looks like an Office file to a quick check (zip header), but holds only random bytes. */
export function decoyContent(): Buffer {
  return Buffer.concat([Buffer.from("PK\x03\x04", "latin1"), randomBytes(24 * 1024)]);
}

const sha256 = (data: Buffer) => createHash("sha256").update(data).digest("hex");

export type DecoyRecord = Record<string, string>; // path -> sha256

function hide(path: string, platform: NodeJS.Platform): Promise<void> {
  if (platform !== "win32") return Promise.resolve();
  return new Promise((resolve) => execFile("attrib", ["+h", path], { windowsHide: true }, () => resolve()));
}

/** Writes fresh decoys into each folder. Returns where they are and their fingerprints. */
export async function plantDecoys(folders: string[], platform: NodeJS.Platform = process.platform): Promise<DecoyRecord> {
  const record: DecoyRecord = {};
  for (const folder of folders) {
    try {
      if (!(await stat(folder)).isDirectory()) continue;
    } catch {
      continue;
    }
    for (const name of decoyNames(platform)) {
      const path = join(folder, name);
      const data = decoyContent();
      try {
        // Written beside, then renamed: a half-written decoy never looks "changed".
        await writeFile(`${path}.tmp`, data, { mode: 0o600 });
        await rename(`${path}.tmp`, path);
        await hide(path, platform);
        record[path] = sha256(data);
      } catch {
        // read-only or locked folder: no decoy there
      }
    }
  }
  return record;
}

/** "changed", "missing", or null when the decoy is exactly as planted. */
export async function decoyState(path: string, expected: string): Promise<"changed" | "missing" | null> {
  try {
    return sha256(await readFile(path)) === expected ? null : "changed";
  } catch {
    return "missing";
  }
}

/** Every decoy that is no longer as planted (checked at start, before planting new ones). */
export async function tamperedDecoys(record: DecoyRecord): Promise<{ path: string; state: "changed" | "missing" }[]> {
  const out: { path: string; state: "changed" | "missing" }[] = [];
  for (const [path, hash] of Object.entries(record)) {
    const state = await decoyState(path, hash);
    if (state) out.push({ path, state });
  }
  return out;
}

// --- Removable drives ---------------------------------------------------------------------

const REMOVABLE_FS = new Set(["vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "hfsplus", "apfs", "iso9660", "udf", "ext2", "ext3", "ext4", "btrfs", "f2fs"]);

/** Linux: drives mounted under /media, /run/media or /mnt with a removable-style file system. */
export function parseProcMounts(text: string): string[] {
  const mounts: string[] = [];
  for (const line of text.split("\n")) {
    const [device, rawMount, fs] = line.split(" ");
    if (!device || !rawMount || !fs || !device.startsWith("/dev/")) continue;
    const mount = rawMount.replace(/\\040/g, " ").replace(/\\011/g, "\t");
    if (!/^\/(media|run\/media|mnt)\//.test(mount)) continue;
    if (REMOVABLE_FS.has(fs)) mounts.push(mount);
  }
  return mounts;
}

/** Windows: Get-CimInstance Win32_LogicalDisk -Filter DriveType=2 (removable) as JSON. */
export function parseWindowsRemovable(json: string): string[] {
  if (!json.trim()) return [];
  try {
    const parsed = JSON.parse(json) as { DeviceID?: string } | { DeviceID?: string }[];
    return (Array.isArray(parsed) ? parsed : [parsed]).map((d) => d.DeviceID).filter((id): id is string => typeof id === "string" && /^[A-Z]:$/i.test(id)).map((id) => `${id}\\`);
  } catch {
    return [];
  }
}

function runText(command: string, args: string[]): Promise<string> {
  return new Promise((resolve) =>
    execFile(command, args, { timeout: 15_000, windowsHide: true, maxBuffer: 1024 * 1024 }, (error, stdout) => resolve(error ? "" : stdout)),
  );
}

export async function removableMounts(platform: NodeJS.Platform = process.platform): Promise<string[]> {
  if (platform === "linux") return parseProcMounts(await readFile("/proc/mounts", "utf8").catch(() => ""));
  if (platform === "win32") {
    return parseWindowsRemovable(
      await runText("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' | Select-Object DeviceID | ConvertTo-Json -Compress"]),
    );
  }
  if (platform === "darwin") {
    const out: string[] = [];
    for (const name of await readdir("/Volumes").catch(() => [] as string[])) {
      const path = join("/Volumes", name);
      // The startup disk appears here as a link to "/".
      if ((await realpath(path).catch(() => "/")) !== "/") out.push(path);
    }
    return out;
  }
  return [];
}

/** Polls for drives; reports only ones that appear after it started. */
export class RemovableWatcher {
  private known = new Set<string>();
  private timer: NodeJS.Timeout | null = null;
  private started = false;

  constructor(
    private readonly onNew: (mount: string) => void,
    private readonly list: () => Promise<string[]> = () => removableMounts(),
  ) {}

  async poll(): Promise<string[]> {
    const now = await this.list();
    const fresh = this.started ? now.filter((mount) => !this.known.has(mount)) : [];
    this.known = new Set(now);
    this.started = true;
    for (const mount of fresh) this.onNew(mount);
    return fresh;
  }

  start(intervalMs = 5000): void {
    if (this.timer) return;
    void this.poll();
    this.timer = setInterval(() => void this.poll(), intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.started = false;
    this.known.clear();
  }
}

/** autorun.inf on a drive that tries to start a program (old USB worm technique, still seen). */
export function autorunFindings(name: string, content: Buffer): Finding[] {
  if (name.toLowerCase() !== "autorun.inf") return [];
  const text = content.subarray(0, 64 * 1024).toString("latin1");
  if (!/^\s*\[autorun\]/im.test(text)) return [];
  if (/^\s*(open|shellexecute|shell\\[^\\]+\\command)\s*=/im.test(text)) {
    return [
      {
        severity: "high",
        rule: "autorun_program",
        title: "Drive is set up to start a program by itself",
        detail: "Its autorun.inf names a program to run when the drive is opened, a technique USB worms use. Windows no longer runs it automatically, but do not open that program.",
      },
    ];
  }
  return [];
}

// --- Silent mode ------------------------------------------------------------------------

export function isSilent(silentUntil: string | null, now = Date.now()): boolean {
  if (!silentUntil) return false;
  const until = Date.parse(silentUntil);
  return Number.isFinite(until) && until > now;
}

/** Hours from now, capped at a day; 0 ends silent mode. */
export function silentUntilFrom(hours: number, now = Date.now()): string | null {
  if (!Number.isFinite(hours) || hours <= 0) return null;
  return new Date(now + Math.min(hours, 24) * 3_600_000).toISOString();
}


// --- Watching places malware drops programs and makes itself start (Linux, macOS) --------

/** Folders where downloaded tools and droppers put programs to run. */
export function executableDropFolders(platform: NodeJS.Platform = process.platform, home = homedir()): string[] {
  const common = [join(home, ".local", "bin"), join(home, "bin")];
  if (platform === "linux") return ["/tmp", "/var/tmp", "/dev/shm", ...common];
  if (platform === "darwin") return ["/tmp", "/private/var/tmp", ...common];
  return [];
}

/** Folders where programs register themselves to start automatically. */
export function persistenceFolders(platform: NodeJS.Platform = process.platform, home = homedir()): string[] {
  if (platform === "linux") return [join(home, ".config", "autostart"), join(home, ".config", "systemd", "user"), join(home, ".local", "share", "systemd", "user")];
  if (platform === "darwin") return [join(home, "Library", "LaunchAgents")];
  return [];
}

/** A program file: executable bit set, or a Linux/macOS program, or a script with #!. */
export async function looksRunnable(path: string): Promise<boolean> {
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.size === 0) return false;
    if ((info.mode & 0o111) !== 0) return true;
    const handle = await open(path, "r");
    try {
      const head = Buffer.alloc(4);
      await handle.read(head, 0, 4, 0);
      return head.readUInt32BE(0) === 0x7f454c46 || [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(head.readUInt32BE(0)) || head.subarray(0, 2).toString("latin1") === "#!";
    } finally {
      await handle.close();
    }
  } catch {
    return false;
  }
}

/** Watches folders (not recursively) and reports each new or changed file once it settles. */
export class DropWatcher {
  private watchers: FSWatcher[] = [];
  private pending = new Map<string, NodeJS.Timeout>();
  private missing: string[] = [];
  private retry: NodeJS.Timeout | null = null;

  constructor(
    private readonly onFile: (path: string) => void,
    private readonly settleMs = 800,
    private readonly retryMs = 30_000,
  ) {}

  set(folders: string[]): void {
    this.close();
    this.missing = [];
    for (const folder of folders) this.add(folder);
    // Folders such as ~/.local/bin are often created later (by an installer): watch them once they exist.
    if (this.missing.length) {
      this.retry = setInterval(() => {
        const waiting = this.missing;
        this.missing = [];
        for (const folder of waiting) this.add(folder);
        if (!this.missing.length && this.retry) {
          clearInterval(this.retry);
          this.retry = null;
        }
      }, this.retryMs);
      this.retry.unref();
    }
  }

  private add(folder: string): void {
    {
      try {
        const watcher = watch(folder, { persistent: false }, (_event, name) => {
          if (!name) return;
          const path = join(folder, String(name));
          const previous = this.pending.get(path);
          if (previous) clearTimeout(previous);
          this.pending.set(
            path,
            setTimeout(() => {
              this.pending.delete(path);
              this.onFile(path);
            }, this.settleMs),
          );
        });
        watcher.on("error", () => watcher.close());
        this.watchers.push(watcher);
      } catch {
        this.missing.push(folder); // not there (yet)
      }
    }
  }

  close(): void {
    for (const watcher of this.watchers) watcher.close();
    this.watchers = [];
    for (const timer of this.pending.values()) clearTimeout(timer);
    this.pending.clear();
    if (this.retry) clearInterval(this.retry);
    this.retry = null;
  }
}
