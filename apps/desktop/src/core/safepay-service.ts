/**
 * SafePay as a service: finds the installed browsers, starts a clean session
 * in a fresh temporary profile, and deletes that profile when the browser
 * closes. Profiles left behind by a crash or power cut are removed at start-up.
 * Events carry the site's host name only, never the full address.
 */
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { type Browser, type DnsMode, PROFILE_PREFIX, dnsMode, findBrowsers, launchPlan, safeUrl } from "../engine/safepay";
import type { Emit } from "./handlers";
import { IpcError } from "./protocol";

export interface SafePaySession {
  id: string;
  browser: string;
  host: string;
  dns: DnsMode;
  startedAt: string;
}

export interface SafePayStatus {
  available: boolean;
  browsers: { id: Browser["id"]; name: string }[];
  sessions: SafePaySession[];
  safeDnsOn: boolean;
}

export interface Child {
  pid?: number;
  once(event: "exit", listener: (code: number | null) => void): unknown;
  once(event: "error", listener: (error: Error) => void): unknown;
}

export interface SafePayDeps {
  platform: NodeJS.Platform;
  emit: Emit;
  safeDnsOn: () => boolean;
  tmp?: string;
  find?: () => Promise<Browser[]>;
  start?: (command: string, args: string[]) => Child;
  now?: () => number;
}

const realStart = (command: string, args: string[]): Child => spawn(command, args, { stdio: "ignore", windowsHide: false, detached: false });

export class SafePayService {
  private sessions = new Map<string, SafePaySession & { profile: string }>();
  private browsers: Browser[] | null = null;
  private counter = 0;
  private readonly tmp: string;

  constructor(private readonly deps: SafePayDeps) {
    this.tmp = deps.tmp ?? tmpdir();
  }

  private async installed(): Promise<Browser[]> {
    this.browsers ??= await (this.deps.find ?? (() => findBrowsers(this.deps.platform)))();
    return this.browsers;
  }

  /** Removes profiles a previous run couldn't (the browser or computer crashed). */
  async cleanup(): Promise<number> {
    const names = await readdir(this.tmp).catch(() => [] as string[]);
    const live = new Set([...this.sessions.values()].map((s) => s.profile));
    let removed = 0;
    for (const name of names.filter((n) => n.startsWith(PROFILE_PREFIX))) {
      const path = join(this.tmp, name);
      if (live.has(path)) continue;
      await rm(path, { recursive: true, force: true }).catch(() => undefined);
      removed += 1;
    }
    return removed;
  }

  async status(): Promise<SafePayStatus> {
    const browsers = await this.installed();
    return {
      available: browsers.length > 0,
      browsers: browsers.map((b) => ({ id: b.id, name: b.name })),
      sessions: [...this.sessions.values()].map(({ profile: _profile, ...s }) => s),
      safeDnsOn: this.deps.safeDnsOn(),
    };
  }

  /** Opens `url` (or a blank page) in a clean session of the chosen or first browser. */
  async launch(params: unknown): Promise<SafePaySession> {
    const { url: rawUrl, browser: wanted } = (params ?? {}) as { url?: unknown; browser?: unknown };
    const url = safeUrl(rawUrl);
    if (!url) throw new IpcError("bad_params", "SafePay opens web addresses only.");
    const browsers = await this.installed();
    if (!browsers.length) throw new IpcError("unavailable", "No supported browser was found. Install Firefox, Chrome, Edge or Brave.");
    const browser = wanted === undefined ? browsers[0]! : browsers.find((b) => b.id === wanted);
    if (!browser) throw new IpcError("not_found", "That browser isn't installed.");

    await mkdir(this.tmp, { recursive: true });
    const profile = await mkdtemp(join(this.tmp, PROFILE_PREFIX)); // created 0700
    const dns = dnsMode(browser.family, this.deps.safeDnsOn());
    const plan = launchPlan(browser, url, profile, dns);
    for (const file of plan.files) await writeFile(file.path, file.content, { mode: 0o600 });

    const host = url === "about:blank" ? "" : new URL(url).hostname;
    const now = (this.deps.now ?? Date.now)();
    const session = { id: `s${now.toString(36)}${(this.counter++).toString(36)}`, browser: browser.name, host, dns, startedAt: new Date(now).toISOString(), profile };
    let child: Child;
    try {
      child = (this.deps.start ?? realStart)(plan.command, plan.args);
    } catch (error) {
      await rm(profile, { recursive: true, force: true });
      throw new IpcError("unavailable", `Couldn't start ${browser.name}: ${error instanceof Error ? error.message : String(error)}`);
    }
    this.sessions.set(session.id, session);
    let ended = false;
    const end = () => {
      if (ended) return;
      ended = true;
      this.sessions.delete(session.id);
      void rm(profile, { recursive: true, force: true }).then(() => this.deps.emit("safepay.ended", { id: session.id, host }));
    };
    child.once("exit", end);
    child.once("error", end);
    this.deps.emit("safepay.started", { id: session.id, browser: browser.name, host, dns });
    const { profile: _profile, ...visible } = session;
    return visible;
  }
}
