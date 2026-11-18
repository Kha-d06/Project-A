/**
 * File integrity monitoring: SHA-256 baselines of files attackers like to change
 * (the hosts file, SSH authorised keys, shell start-up files, sudoers rules...),
 * watched in real time and re-checked periodically. Any change raises an alert
 * until the person accepts it as expected.
 */
import { createHash } from "node:crypto";
import { type FSWatcher, createReadStream, watch } from "node:fs";
import { readFile, rename, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

export interface FileState {
  path: string;
  sha256: string | null; // null: the file does not exist (or cannot be read)
  size: number | null;
  mtime: string | null;
}

export interface Change {
  path: string;
  kind: "modified" | "deleted" | "created";
  before: FileState;
  after: FileState;
  at: string;
}

export interface IntegrityStore {
  paths: string[];
  baseline: Record<string, FileState>;
  changes: Change[];
  lastCheck: string | null;
}

export function defaultPaths(platform = process.platform, home = process.env.HOME ?? process.env.USERPROFILE ?? ""): string[] {
  if (platform === "win32") {
    const root = process.env.SystemRoot ?? "C:\\Windows";
    return [
      join(root, "System32", "drivers", "etc", "hosts"),
      join(home, ".ssh", "authorized_keys"),
      join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
      join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
    ];
  }
  const common = ["/etc/hosts", join(home, ".ssh", "authorized_keys"), join(home, ".ssh", "config"), join(home, ".profile"), join(home, ".zshrc"), join(home, ".bashrc")];
  if (platform === "darwin") return [...common, "/etc/sudoers", "/etc/pam.d/sudo"];
  return [...common, "/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/ld.so.preload", "/etc/crontab", "/etc/resolv.conf"];
}

function hash(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    createReadStream(path).on("data", (c) => h.update(c)).on("error", reject).on("end", () => resolve(h.digest("hex")));
  });
}

export async function fileState(path: string): Promise<FileState> {
  try {
    const info = await stat(path);
    if (!info.isFile()) return { path, sha256: null, size: null, mtime: null };
    return { path, sha256: await hash(path), size: info.size, mtime: info.mtime.toISOString() };
  } catch {
    return { path, sha256: null, size: null, mtime: null };
  }
}

/** Compare current states with the baseline (pure). */
export function compare(baseline: Record<string, FileState>, current: FileState[], at = new Date().toISOString()): Change[] {
  const changes: Change[] = [];
  for (const now of current) {
    const before = baseline[now.path];
    if (!before) continue;
    if (before.sha256 === now.sha256) continue;
    const kind: Change["kind"] = before.sha256 === null ? "created" : now.sha256 === null ? "deleted" : "modified";
    changes.push({ path: now.path, kind, before, after: now, at });
  }
  return changes;
}

export class IntegrityMonitor {
  private store: IntegrityStore = { paths: [], baseline: {}, changes: [], lastCheck: null };
  private watchers: FSWatcher[] = [];
  private timer: NodeJS.Timeout | null = null;
  private pending: NodeJS.Timeout | null = null;

  constructor(
    private readonly file: string,
    private readonly onChange: (changes: Change[]) => void,
  ) {}

  async load(): Promise<IntegrityStore> {
    try {
      this.store = JSON.parse(await readFile(this.file, "utf8")) as IntegrityStore;
    } catch {
      this.store = { paths: defaultPaths(), baseline: {}, changes: [], lastCheck: null };
      await this.rebaseline();
    }
    return this.store;
  }

  get state(): IntegrityStore {
    return this.store;
  }

  private async save() {
    await writeFile(`${this.file}.tmp`, JSON.stringify(this.store), { mode: 0o600 });
    await rename(`${this.file}.tmp`, this.file);
  }

  async rebaseline(paths = this.store.paths): Promise<IntegrityStore> {
    const states = await Promise.all(paths.map(fileState));
    this.store = { paths, baseline: Object.fromEntries(states.map((s) => [s.path, s])), changes: [], lastCheck: new Date().toISOString() };
    await this.save();
    this.restartWatch();
    return this.store;
  }

  /** Accept one change as expected: it becomes part of the baseline. */
  async accept(path: string): Promise<IntegrityStore> {
    this.store.baseline[path] = await fileState(path);
    this.store.changes = this.store.changes.filter((c) => c.path !== path);
    await this.save();
    return this.store;
  }

  async setPaths(paths: string[]): Promise<IntegrityStore> {
    const unique = [...new Set(paths.map((p) => p.trim()).filter(Boolean))].slice(0, 200);
    const added = unique.filter((p) => !this.store.baseline[p]);
    for (const state of await Promise.all(added.map(fileState))) this.store.baseline[state.path] = state;
    for (const p of Object.keys(this.store.baseline)) if (!unique.includes(p)) delete this.store.baseline[p];
    this.store.paths = unique;
    this.store.changes = this.store.changes.filter((c) => unique.includes(c.path));
    await this.save();
    this.restartWatch();
    return this.store;
  }

  async check(): Promise<Change[]> {
    const current = await Promise.all(this.store.paths.map(fileState));
    const fresh = compare(this.store.baseline, current).filter((c) => !this.store.changes.some((known) => known.path === c.path && known.after.sha256 === c.after.sha256));
    this.store.changes = [...this.store.changes.filter((known) => !fresh.some((c) => c.path === known.path)), ...fresh];
    this.store.lastCheck = new Date().toISOString();
    await this.save();
    if (fresh.length) this.onChange(fresh);
    return fresh;
  }

  /** Watch each file's folder (a file may be replaced, not edited), plus a 10-minute sweep. */
  start(): void {
    this.restartWatch();
    if (!this.timer) {
      this.timer = setInterval(() => void this.check(), 10 * 60 * 1000);
      this.timer.unref();
    }
  }

  stop(): void {
    for (const w of this.watchers) w.close();
    this.watchers = [];
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private restartWatch() {
    for (const w of this.watchers) w.close();
    this.watchers = [];
    const byFolder = new Map<string, Set<string>>();
    for (const path of this.store.paths) {
      const set = byFolder.get(dirname(path)) ?? new Set<string>();
      set.add(basename(path));
      byFolder.set(dirname(path), set);
    }
    for (const [folder, names] of byFolder) {
      try {
        const watcher = watch(folder, { persistent: false }, (_event, name) => {
          if (name && !names.has(String(name))) return;
          if (this.pending) clearTimeout(this.pending);
          this.pending = setTimeout(() => void this.check(), 500);
        });
        watcher.on("error", () => watcher.close());
        this.watchers.push(watcher);
      } catch {
        // folder missing or not readable: the periodic sweep still covers it
      }
    }
  }
}
