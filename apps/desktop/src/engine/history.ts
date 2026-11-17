/**
 * Browser-history check: were any recently visited pages on SENTINEL's lists of
 * phishing and malware sites?
 *
 * Privacy: the app downloads the server's list (domains and exact URLs from the
 * threat feeds) and compares on this computer. No history is sent anywhere, and
 * nothing is kept: each browser's history file is copied to a temporary file,
 * read, and the copy deleted.
 *
 * Supported: Chrome, Edge, Brave, Chromium, Vivaldi, Opera (Chromium "History"
 * files) and Firefox ("places.sqlite"), on Windows, macOS and Linux.
 */
import { copyFile, mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

export interface HistoryFile {
  browser: string;
  profile: string;
  kind: "chromium" | "firefox";
  path: string;
}

export interface Visit {
  url: string;
  visitedAt: Date | null;
}

export interface HistoryMatch {
  browser: string;
  profile: string;
  url: string;
  host: string;
  visitedAt: string | null;
  /** "url" when the exact page is listed, "domain" when its domain is. */
  reason: "url" | "domain";
}

export interface ThreatList {
  hosts: string[];
  urls: string[];
}

// --- Where browsers keep history ------------------------------------------------------

const CHROMIUM_DIRS: Record<string, { name: string; dir: string }[]> = {
  win32: [
    { name: "Chrome", dir: "AppData/Local/Google/Chrome/User Data" },
    { name: "Edge", dir: "AppData/Local/Microsoft/Edge/User Data" },
    { name: "Brave", dir: "AppData/Local/BraveSoftware/Brave-Browser/User Data" },
    { name: "Vivaldi", dir: "AppData/Local/Vivaldi/User Data" },
    { name: "Opera", dir: "AppData/Roaming/Opera Software/Opera Stable" },
    { name: "Chromium", dir: "AppData/Local/Chromium/User Data" },
  ],
  darwin: [
    { name: "Chrome", dir: "Library/Application Support/Google/Chrome" },
    { name: "Edge", dir: "Library/Application Support/Microsoft Edge" },
    { name: "Brave", dir: "Library/Application Support/BraveSoftware/Brave-Browser" },
    { name: "Vivaldi", dir: "Library/Application Support/Vivaldi" },
    { name: "Opera", dir: "Library/Application Support/com.operasoftware.Opera" },
    { name: "Chromium", dir: "Library/Application Support/Chromium" },
  ],
  linux: [
    { name: "Chrome", dir: ".config/google-chrome" },
    { name: "Edge", dir: ".config/microsoft-edge" },
    { name: "Brave", dir: ".config/BraveSoftware/Brave-Browser" },
    { name: "Vivaldi", dir: ".config/vivaldi" },
    { name: "Opera", dir: ".config/opera" },
    { name: "Chromium", dir: ".config/chromium" },
    { name: "Chromium (snap)", dir: "snap/chromium/common/chromium" },
  ],
};

const FIREFOX_DIRS: Record<string, string[]> = {
  win32: ["AppData/Roaming/Mozilla/Firefox/Profiles"],
  darwin: ["Library/Application Support/Firefox/Profiles"],
  linux: [".mozilla/firefox", "snap/firefox/common/.mozilla/firefox", ".var/app/org.mozilla.firefox/.mozilla/firefox"],
};

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function subdirs(path: string): Promise<string[]> {
  try {
    return (await readdir(path, { withFileTypes: true })).filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    return [];
  }
}

export async function findHistoryFiles(platform = process.platform, home = homedir()): Promise<HistoryFile[]> {
  const found: HistoryFile[] = [];
  for (const { name, dir } of CHROMIUM_DIRS[platform] ?? []) {
    const root = join(home, dir);
    // Opera keeps History in the top folder; others in Default / "Profile N".
    const candidates = [root, ...(await subdirs(root)).filter((d) => d === "Default" || /^Profile \d+$/.test(d)).map((d) => join(root, d))];
    for (const folder of candidates) {
      const file = join(folder, "History");
      if (await exists(file)) found.push({ browser: name, profile: folder === root ? "Default" : folder.slice(root.length + 1), kind: "chromium", path: file });
    }
  }
  for (const dir of FIREFOX_DIRS[platform] ?? []) {
    const root = join(home, dir);
    for (const profile of await subdirs(root)) {
      const file = join(root, profile, "places.sqlite");
      if (await exists(file)) found.push({ browser: "Firefox", profile: profile.replace(/^[a-z0-9]+\./, ""), kind: "firefox", path: file });
    }
  }
  return found;
}

// --- Reading -------------------------------------------------------------------------

// Chromium stores microseconds since 1601-01-01; Firefox microseconds since 1970.
const CHROMIUM_EPOCH_OFFSET_US = 11_644_473_600_000_000n;

export function chromiumTime(value: number | bigint | null): Date | null {
  if (value === null || value === undefined) return null;
  const micros = BigInt(value) - CHROMIUM_EPOCH_OFFSET_US;
  return micros > 0n ? new Date(Number(micros / 1000n)) : null;
}

export function firefoxTime(value: number | bigint | null): Date | null {
  if (value === null || value === undefined) return null;
  const millis = Number(BigInt(value) / 1000n);
  return millis > 0 ? new Date(millis) : null;
}

/** Reads recent visits from a copy of the history file (browsers keep it locked). */
export async function readVisits(file: HistoryFile, since: Date, limit = 20_000): Promise<Visit[]> {
  const folder = await mkdtemp(join(tmpdir(), "sentinel-history-"));
  const copy = join(folder, "history.sqlite");
  try {
    await copyFile(file.path, copy);
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(copy, { readOnly: true });
    try {
      if (file.kind === "chromium") {
        const sinceValue = BigInt(since.getTime()) * 1000n + CHROMIUM_EPOCH_OFFSET_US;
        const query = db.prepare("SELECT url, last_visit_time AS t FROM urls WHERE last_visit_time >= ? ORDER BY last_visit_time DESC LIMIT ?");
        query.setReadBigInts(true); // Chromium times are larger than JavaScript numbers allow
        const rows = query.all(sinceValue, limit) as { url: string; t: bigint }[];
        return rows.map((row) => ({ url: row.url, visitedAt: chromiumTime(row.t) }));
      }
      const query = db.prepare("SELECT url, last_visit_date AS t FROM moz_places WHERE last_visit_date >= ? ORDER BY last_visit_date DESC LIMIT ?");
      query.setReadBigInts(true);
      const rows = query.all(BigInt(since.getTime()) * 1000n, limit) as { url: string; t: bigint }[];
      return rows.map((row) => ({ url: row.url, visitedAt: firefoxTime(row.t) }));
    } finally {
      db.close();
    }
  } finally {
    await rm(folder, { recursive: true, force: true });
  }
}

// --- Matching ------------------------------------------------------------------------

/** Same shape as the server's normalised URLs: lower-case scheme and host, default
 * ports dropped, "/" for an empty path, no fragment. */
export function normaliseUrl(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    const port = url.port ? `:${url.port}` : "";
    return `${url.protocol}//${host}${port}${url.pathname || "/"}${url.search}`;
  } catch {
    return null;
  }
}

function hostOf(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url.hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return null;
  }
}

/** The host and each parent domain: a.b.example.com → [a.b.example.com, b.example.com, example.com]. */
function hostAndParents(host: string): string[] {
  const parts = host.split(".");
  return parts.slice(0, -1).map((_, i) => parts.slice(i).join("."));
}

export function matchVisits(visits: Visit[], list: ThreatList, source: { browser: string; profile: string }): HistoryMatch[] {
  const hosts = new Set(list.hosts.map((h) => h.toLowerCase()));
  const urls = new Set(list.urls.map((u) => normaliseUrl(u)).filter((u): u is string => u !== null));
  const seen = new Set<string>();
  const matches: HistoryMatch[] = [];
  for (const visit of visits) {
    const host = hostOf(visit.url);
    if (!host) continue;
    const normalised = normaliseUrl(visit.url);
    let reason: HistoryMatch["reason"] | null = null;
    if (normalised && urls.has(normalised)) reason = "url";
    else if (hostAndParents(host).some((h) => hosts.has(h))) reason = "domain";
    if (!reason) continue;
    const key = reason === "url" ? normalised! : host;
    if (seen.has(key)) continue;
    seen.add(key);
    matches.push({ ...source, url: visit.url.slice(0, 500), host, visitedAt: visit.visitedAt?.toISOString() ?? null, reason });
  }
  return matches;
}

export interface HistoryReport {
  checkedAt: string;
  days: number;
  browsers: { browser: string; profile: string; visits: number; error: string | null }[];
  matches: HistoryMatch[];
}

export async function checkHistory(list: ThreatList, days = 30, files?: HistoryFile[]): Promise<HistoryReport> {
  const since = new Date(Date.now() - days * 86_400_000);
  const browsers: HistoryReport["browsers"] = [];
  const matches: HistoryMatch[] = [];
  for (const file of files ?? (await findHistoryFiles())) {
    try {
      const visits = await readVisits(file, since);
      browsers.push({ browser: file.browser, profile: file.profile, visits: visits.length, error: null });
      matches.push(...matchVisits(visits, list, file));
    } catch (error) {
      browsers.push({ browser: file.browser, profile: file.profile, visits: 0, error: error instanceof Error ? error.message.slice(0, 200) : String(error) });
    }
  }
  matches.sort((a, b) => (b.visitedAt ?? "").localeCompare(a.visitedAt ?? ""));
  return { checkedAt: new Date().toISOString(), days, browsers, matches };
}
