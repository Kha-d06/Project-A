/**
 * Scanning and quarantine for any interface over qalaa-ipc (the native command
 * centre today; the classic window's handlers in main.ts do the same work until
 * it is removed). The engines are unchanged: scanFile() with signatures, YARA,
 * ClamAV, qalaa-scan's native engine and model, and the encrypted Quarantine.
 *
 * One scan runs at a time; a second request is refused with "busy" rather than
 * queued, so the interface can say so. Progress is broadcast at most four times
 * a second. Results keep the last HISTORY_LIMIT files; the list sent to an
 * interface is a short summary, and one file's full findings come from
 * scan.details (the file inspector).
 */
import { readFile, stat, writeFile } from "node:fs/promises";
import { isAbsolute } from "node:path";

import { isExcluded, sanitizeExclusions } from "../engine/protection";
import type { Quarantine, QuarantineItem } from "../engine/quarantine";
import type { ScanContext } from "../engine/scanner";
import type { ScanResult } from "../engine/types";
import { IpcError } from "./protocol";

export const HISTORY_LIMIT = 500;
const LIST_LIMIT = 100;
const PROGRESS_EVERY_MS = 250;

export interface ScanTotals {
  scanned: number;
  malicious: number;
  suspicious: number;
}

export interface ScanSummary {
  path: string;
  name: string;
  size: number;
  verdict: ScanResult["verdict"];
  /** The most serious finding's title, or "". */
  title: string;
  findings: number;
  engines: string[];
  scannedAt: string;
  error: string | null;
  /** The quarantine item id when the file was moved there. */
  quarantined: string | null;
}

export interface ScanStatus {
  scanning: boolean;
  kind: "quick" | "custom" | null;
  progress: { scanned: number; found: number; current: string } | null;
  last: (ScanTotals & { kind: "quick" | "custom"; finishedAt: string }) | null;
  results: ScanSummary[];
  watchFolders: string[];
  exclusions: string[];
  /** What this computer scans with, for the interface to say so honestly. */
  engines: { clamav: boolean; native: boolean; cloud: boolean };
}

export interface DeepFinding {
  area: string;
  item: string;
  severity: "high" | "medium" | "low";
  detail: string;
}

export interface ScanServiceDeps {
  historyFile: string;
  quarantine: Quarantine;
  scanFile: (path: string, context: ScanContext) => Promise<ScanResult>;
  context: () => ScanContext;
  walk: (root: string, limit: number, skip: (path: string) => boolean) => AsyncIterable<string>;
  isDirectory: (path: string) => Promise<boolean>;
  watchFolders: () => string[];
  exclusions: () => string[];
  saveExclusions: (exclusions: string[]) => Promise<void>;
  /** Startup entries, hidden processes and the like (tools.deepCheck). */
  deepCheck?: () => Promise<{ findings: DeepFinding[]; checked: string[] }>;
  emit?: (event: "scan.started" | "scan.progress" | "scan.finished", payload: unknown) => void;
  platform?: NodeJS.Platform;
  now?: () => number;
}

function summary(result: ScanResult, quarantined: string | null): ScanSummary {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as Record<string, number>;
  const top = [...result.findings].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9))[0];
  return {
    path: result.path,
    name: result.name,
    size: result.size,
    verdict: result.verdict,
    title: top?.title ?? "",
    findings: result.findings.length,
    engines: result.engines,
    scannedAt: result.scannedAt,
    error: result.error ?? null,
    quarantined,
  };
}

function pathParam(params: unknown, key = "path"): string {
  const value = (params as Record<string, unknown> | undefined)?.[key];
  if (typeof value !== "string" || !value.trim() || value.length > 4096) throw new IpcError("bad_params", "Expected a file or folder path.");
  return value.trim();
}

export class ScanService {
  private history: (ScanResult & { quarantined?: string })[] = [];
  private scanningKind: "quick" | "custom" | null = null;
  private progress: ScanStatus["progress"] = null;
  private last: ScanStatus["last"] = null;
  private lastProgressAt = 0;
  private readonly platform: NodeJS.Platform;
  private readonly now: () => number;

  constructor(private readonly deps: ScanServiceDeps) {
    this.platform = deps.platform ?? process.platform;
    this.now = deps.now ?? Date.now;
  }

  async load(): Promise<void> {
    try {
      const saved = JSON.parse(await readFile(this.deps.historyFile, "utf8")) as unknown;
      this.history = Array.isArray(saved) ? (saved as ScanResult[]).slice(0, HISTORY_LIMIT) : [];
    } catch {
      this.history = [];
    }
  }

  /** The newest result first. Also used for Home's "last scan" and threat counts. */
  results(): readonly ScanResult[] {
    return this.history;
  }

  isScanning(): boolean {
    return this.scanningKind !== null;
  }

  status(): ScanStatus {
    const context = this.deps.context();
    return {
      scanning: this.scanningKind !== null,
      kind: this.scanningKind,
      progress: this.progress,
      last: this.last,
      results: this.history.slice(0, LIST_LIMIT).map((r) => summary(r, r.quarantined ?? null)),
      watchFolders: this.deps.watchFolders(),
      exclusions: this.deps.exclusions(),
      engines: { clamav: Boolean(context.clamBinary), native: Boolean(context.nativeScanner), cloud: Boolean(context.cloudLookup) },
    };
  }

  /** The file inspector: every finding and engine for one scanned file. */
  details(params: unknown): ScanResult & { quarantined: string | null } {
    const path = pathParam(params);
    const found = this.history.find((r) => r.path === path);
    if (!found) throw new IpcError("not_found", "That file isn't in the scan results.");
    return { ...found, quarantined: found.quarantined ?? null };
  }

  /** The watched folders (usually Downloads). */
  quick(): Promise<ScanTotals> {
    return this.exclusive("quick", this.deps.watchFolders());
  }

  /** Files or folders the person chose. */
  async custom(params: unknown): Promise<ScanTotals> {
    const raw = (params as { paths?: unknown } | undefined)?.paths;
    if (!Array.isArray(raw) || !raw.length) throw new IpcError("bad_params", "Choose at least one file or folder.");
    const paths = raw.filter((p): p is string => typeof p === "string" && p.length < 4096).map((p) => p.trim()).slice(0, 100);
    for (const p of paths) {
      if (!this.absolute(p)) throw new IpcError("bad_params", `Use a full path: ${p}`);
      await stat(p).catch(() => {
        throw new IpcError("not_found", `Nothing at ${p}`);
      });
    }
    return this.exclusive("custom", paths);
  }

  async deep(): Promise<{ findings: DeepFinding[]; checked: string[]; checkedAt: string }> {
    if (!this.deps.deepCheck) throw new IpcError("unavailable", "The deep check isn't available on this system.");
    const result = await this.deps.deepCheck();
    return { ...result, checkedAt: new Date(this.now()).toISOString() };
  }

  async addExclusion(params: unknown): Promise<ScanStatus> {
    const path = pathParam(params);
    const next = sanitizeExclusions([...this.deps.exclusions(), path], this.platform);
    if (!next || !next.some((e) => e === path)) throw new IpcError("bad_params", "Use a full path, not the root of a drive.");
    await this.deps.saveExclusions(next);
    return this.status();
  }

  async removeExclusion(params: unknown): Promise<ScanStatus> {
    const path = pathParam(params);
    await this.deps.saveExclusions(this.deps.exclusions().filter((e) => e !== path));
    return this.status();
  }

  quarantineList(): Promise<QuarantineItem[]> {
    return this.deps.quarantine.list().then((items) => items.slice().reverse());
  }

  async quarantineAdd(params: unknown): Promise<QuarantineItem> {
    const path = pathParam(params);
    const known = this.history.find((r) => r.path === path);
    if (!known) throw new IpcError("not_found", "Scan the file first; only scanned files can be quarantined from here.");
    const item = await this.deps.quarantine
      .add(path, { sha256: known.sha256, verdict: known.verdict === "no_known_threat" ? "suspicious" : known.verdict, reason: known.findings[0]?.title ?? "Quarantined by you" })
      .catch((error: unknown) => {
        throw new IpcError("failed", error instanceof Error ? error.message : String(error));
      });
    known.quarantined = item.id;
    await this.persist();
    return item;
  }

  async quarantineRestore(params: unknown): Promise<{ path: string }> {
    const id = pathParam(params, "id");
    const path = await this.deps.quarantine.restore(id).catch((error: unknown) => {
      throw new IpcError("not_found", error instanceof Error ? error.message : String(error));
    });
    for (const r of this.history) if (r.quarantined === id) delete r.quarantined;
    await this.persist();
    return { path };
  }

  async quarantineDelete(params: unknown): Promise<{ deleted: true }> {
    const id = pathParam(params, "id");
    await this.deps.quarantine.remove(id);
    return { deleted: true };
  }

  private absolute(path: string): boolean {
    return this.platform === "win32" ? /^[a-z]:[\\/]|^\\\\/i.test(path) : isAbsolute(path);
  }

  private async exclusive(kind: "quick" | "custom", paths: string[]): Promise<ScanTotals> {
    if (this.scanningKind) throw new IpcError("busy", "A scan is already running.");
    this.scanningKind = kind;
    this.progress = { scanned: 0, found: 0, current: "" };
    this.deps.emit?.("scan.started", { kind });
    const totals: ScanTotals = { scanned: 0, malicious: 0, suspicious: 0 };
    try {
      const exclusions = this.deps.exclusions();
      const skip = (path: string) => isExcluded(path, exclusions, this.platform);
      const context = this.deps.context();
      const one = async (file: string) => {
        if (skip(file)) return;
        const result = await this.deps.scanFile(file, context);
        this.history = [result, ...this.history.filter((r) => r.path !== result.path)].slice(0, HISTORY_LIMIT);
        totals.scanned += 1;
        if (result.verdict === "malicious") totals.malicious += 1;
        if (result.verdict === "suspicious") totals.suspicious += 1;
        this.progress = { scanned: totals.scanned, found: totals.malicious + totals.suspicious, current: file };
        if (this.now() - this.lastProgressAt >= PROGRESS_EVERY_MS) {
          this.lastProgressAt = this.now();
          this.deps.emit?.("scan.progress", this.progress);
        }
      };
      for (const path of paths) {
        if (await this.deps.isDirectory(path)) {
          for await (const file of this.deps.walk(path, 50_000, skip)) await one(file);
        } else {
          await one(path);
        }
      }
      await this.persist();
      this.last = { ...totals, kind, finishedAt: new Date(this.now()).toISOString() };
      this.deps.emit?.("scan.finished", this.last);
      return totals;
    } finally {
      this.scanningKind = null;
      this.progress = null;
    }
  }

  private persist(): Promise<void> {
    return writeFile(this.deps.historyFile, JSON.stringify(this.history.slice(0, HISTORY_LIMIT)));
  }
}
