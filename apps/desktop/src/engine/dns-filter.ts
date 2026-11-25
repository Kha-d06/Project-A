/**
 * Ad and tracker blocking for Safe DNS: filter lists (EasyList, EasyPrivacy)
 * matched by qalaa-dns, the native helper built on adblock-rust.
 *
 * - The lists are downloaded on this computer from their publishers, so
 *   nothing is redistributed; their licences are shown with the feature.
 * - One `qalaa-dns serve` process answers one name per line. A name it takes
 *   longer than 250 ms to answer, or any helper failure, is allowed: DNS never
 *   waits on the filter.
 * - Only whole-host rules apply at DNS; the rest is the browser extension's job.
 */
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

export interface FilterVerdict {
  blocked: boolean;
  rule: string | null;
}

export interface FilterList {
  id: string;
  title: string;
  url: string;
  licence: string;
  homepage: string;
}

export const FILTER_LISTS: FilterList[] = [
  { id: "easylist", title: "EasyList (ads)", url: "https://easylist.to/easylist/easylist.txt", licence: "GPLv3 or CC BY-SA 3.0", homepage: "https://easylist.to/" },
  { id: "easyprivacy", title: "EasyPrivacy (trackers)", url: "https://easylist.to/easylist/easyprivacy.txt", licence: "GPLv3 or CC BY-SA 3.0", homepage: "https://easylist.to/" },
];

const MAX_LIST_BYTES = 16 * 1024 * 1024;
const LIST_MAX_AGE_MS = 4 * 24 * 60 * 60 * 1000;
const ANSWER_MS = 250;
const CACHE = 4096;

/** A list is plausible when it looks like Adblock Plus syntax or a hosts file. */
export function looksLikeFilterList(text: string): boolean {
  const head = text.slice(0, 2048);
  return /^\[Adblock Plus|^! Title:|^!|^\|\||^0\.0\.0\.0 /m.test(head) && !/^\s*<(!doctype|html)/i.test(head);
}

/** Downloads lists older than four days; a failed or odd download keeps the copy already there. */
export async function refreshLists(dir: string, fetchText: (url: string) => Promise<string> = defaultFetch, now = Date.now()): Promise<{ id: string; updated: boolean; error?: string }[]> {
  await mkdir(dir, { recursive: true });
  const out: { id: string; updated: boolean; error?: string }[] = [];
  for (const list of FILTER_LISTS) {
    const file = join(dir, `${list.id}.txt`);
    const age = await stat(file).then((s) => now - s.mtimeMs).catch(() => Infinity);
    if (age < LIST_MAX_AGE_MS) {
      out.push({ id: list.id, updated: false });
      continue;
    }
    try {
      const text = await fetchText(list.url);
      if (text.length > MAX_LIST_BYTES) throw new Error("the list is unexpectedly large");
      if (!looksLikeFilterList(text)) throw new Error("the download isn't a filter list");
      await writeFile(`${file}.tmp`, text);
      await rename(`${file}.tmp`, file);
      out.push({ id: list.id, updated: true });
    } catch (error) {
      out.push({ id: list.id, updated: false, error: error instanceof Error ? error.message : String(error) });
    }
  }
  return out;
}

async function defaultFetch(url: string): Promise<string> {
  const response = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(60_000) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.text();
}

/** The qalaa-dns helper next to the app, in its resources, or on PATH. */
export async function findDnsFilter(env: NodeJS.ProcessEnv = process.env, execPath = process.execPath): Promise<string | null> {
  const { access } = await import("node:fs/promises");
  const { delimiter, dirname } = await import("node:path");
  const exe = process.platform === "win32" ? "qalaa-dns.exe" : "qalaa-dns";
  const resources = (process as NodeJS.Process & { resourcesPath?: string }).resourcesPath;
  const candidates = [env.QALAA_DNS_BINARY, join(dirname(execPath), exe), resources ? join(resources, "bin", exe) : undefined, ...(env.PATH ?? "").split(delimiter).filter(Boolean).map((d) => join(d, exe))];
  for (const c of candidates) if (c && (await access(c).then(() => true, () => false))) return c;
  return null;
}

export async function availableLists(dir: string): Promise<string[]> {
  const found: string[] = [];
  for (const list of FILTER_LISTS) {
    const file = join(dir, `${list.id}.txt`);
    if (await readFile(file, { encoding: "utf8", flag: "r" }).then((t) => t.length > 0, () => false)) found.push(file);
  }
  return found;
}

/** Talks to one long-running `qalaa-dns serve`. */
export class DnsFilterProcess {
  private child: ChildProcessWithoutNullStreams | null = null;
  private waiting: { name: string; resolve: (v: FilterVerdict | null) => void; timer: NodeJS.Timeout }[] = [];
  private cache = new Map<string, FilterVerdict>();
  rules = 0;

  constructor(
    private readonly binary: string,
    private readonly lists: string[],
    private readonly spawnFn: typeof spawn = spawn,
  ) {}

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const child = this.spawnFn(this.binary, ["serve", ...this.lists], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true }) as ChildProcessWithoutNullStreams;
      this.child = child;
      let ready = false;
      const lines = createInterface({ input: child.stdout });
      lines.on("line", (line) => {
        let v: { ready?: boolean; rules?: number; name?: string; blocked?: boolean; rule?: string | null };
        try {
          v = JSON.parse(line) as typeof v;
        } catch {
          return;
        }
        if (v.ready) {
          ready = true;
          this.rules = Number(v.rules ?? 0);
          resolve();
          return;
        }
        const next = this.waiting.shift();
        if (!next) return;
        clearTimeout(next.timer);
        const verdict = { blocked: v.blocked === true, rule: typeof v.rule === "string" ? v.rule.slice(0, 200) : null };
        this.remember(next.name, verdict);
        next.resolve(verdict);
      });
      child.on("error", (e) => (ready ? undefined : reject(e)));
      child.on("exit", (code) => {
        this.child = null;
        for (const w of this.waiting.splice(0)) {
          clearTimeout(w.timer);
          w.resolve(null);
        }
        if (!ready) reject(new Error(`qalaa-dns exited (${String(code)})`));
      });
    });
  }

  private remember(name: string, verdict: FilterVerdict): void {
    if (this.cache.size >= CACHE) this.cache.delete(this.cache.keys().next().value!);
    this.cache.set(name, verdict);
  }

  /** null means "no opinion": the helper is down or slow, and the name is allowed. */
  check(name: string): Promise<FilterVerdict | null> {
    const key = name.toLowerCase().replace(/\.$/, "");
    const cached = this.cache.get(key);
    if (cached) return Promise.resolve(cached);
    const child = this.child;
    if (!child) return Promise.resolve(null);
    return new Promise((resolve) => {
      const entry = {
        name: key,
        resolve,
        // A late answer still arrives in order and is matched to this slot, so the queue stays aligned.
        timer: setTimeout(() => {
          entry.resolve = () => {};
          resolve(null);
        }, ANSWER_MS),
      };
      this.waiting.push(entry);
      child.stdin.write(`${key}\n`);
    });
  }

  running(): boolean {
    return this.child !== null;
  }

  stop(): void {
    this.child?.kill();
    this.child = null;
  }
}
