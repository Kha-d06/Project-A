/**
 * The browsing check for any interface over qalaa-ipc (until now only inside the
 * Electron window). Engines unchanged:
 *
 * - Browser history (Chromium browsers and Firefox, every profile): the visits of
 *   the last few days are read on this computer and compared with the list of
 *   dangerous sites downloaded from the linked Qalaa server. The history itself
 *   never leaves the computer; only the list comes down. The matches are kept in
 *   memory only, never written to disk, since they're the person's own browsing.
 * - Browser extensions: each Chromium profile's extensions with what they're
 *   allowed to do, flagged when they can read every site, talk to programs on
 *   the computer, redirect browsing, or didn't come from the store.
 */
import type { LinkedAccount } from "../engine/account";
import type { HistoryReport, ThreatList } from "../engine/history";
import type { ExtensionInfo } from "../engine/tools";
import { IpcError } from "./protocol";

export interface BrowsingStatus {
  linked: boolean;
  history: HistoryReport | null;
  extensions: { items: ExtensionInfo[]; checkedAt: string } | null;
  checking: boolean;
}

export interface BrowsingDeps {
  account: () => Promise<LinkedAccount | null>;
  /** The server's list of dangerous hosts and pages, for the linked device. */
  blocklist: (account: LinkedAccount) => Promise<ThreatList>;
  checkHistory: (list: ThreatList, days: number) => Promise<HistoryReport>;
  extensions: () => Promise<ExtensionInfo[]>;
  emit: (event: "alert", payload: unknown) => void;
  now?: () => number;
}

export class BrowsingService {
  private history: HistoryReport | null = null;
  private extensionsReport: BrowsingStatus["extensions"] = null;
  private running: Promise<unknown> | null = null;
  private readonly now: () => number;

  constructor(private readonly deps: BrowsingDeps) {
    this.now = deps.now ?? Date.now;
  }

  async status(): Promise<BrowsingStatus> {
    return {
      linked: (await this.deps.account().catch(() => null)) !== null,
      history: this.history,
      extensions: this.extensionsReport,
      checking: this.running !== null,
    };
  }

  async checkHistory(params: unknown): Promise<BrowsingStatus> {
    const raw = (params as { days?: unknown } | undefined)?.days;
    const days = raw === undefined ? 30 : typeof raw === "number" && Number.isInteger(raw) && raw >= 1 && raw <= 90 ? raw : NaN;
    if (Number.isNaN(days)) throw new IpcError("bad_params", "Choose between 1 and 90 days.");
    const account = await this.deps.account();
    if (!account) throw new IpcError("not_linked", "Link this computer to your Qalaa account first, so it can download the list of dangerous sites.");
    await this.exclusive(async () => {
      const list = await this.deps.blocklist(account).catch((error: unknown) => {
        throw new IpcError("failed", `Couldn't download the list of dangerous sites: ${error instanceof Error ? error.message : String(error)}`.slice(0, 300));
      });
      this.history = await this.deps.checkHistory({ hosts: list.hosts ?? [], urls: list.urls ?? [] }, days);
      if (this.history.matches.length) this.deps.emit("alert", { kind: "history", matches: this.history.matches.length });
    });
    return this.status();
  }

  async checkExtensions(): Promise<BrowsingStatus> {
    await this.exclusive(async () => {
      const items = await this.deps.extensions();
      this.extensionsReport = { items, checkedAt: new Date(this.now()).toISOString() };
    });
    return this.status();
  }

  /** Forgets the history matches (they're only in memory anyway). */
  clearHistory(): Promise<BrowsingStatus> {
    this.history = null;
    return this.status();
  }

  private async exclusive(work: () => Promise<void>): Promise<void> {
    if (this.running) throw new IpcError("busy", "A browsing check is already running.");
    const run = work();
    this.running = run;
    try {
      await run;
    } finally {
      this.running = null;
    }
  }
}
