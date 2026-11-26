/**
 * Lets the owner start scans on this computer from their Qalaa account.
 *
 * - Nothing runs unless the person turned on "Allow scans from my Qalaa account"
 *   in this app. The server is told, and the app checks again before each command.
 * - Folders are offered by id and label only ("Downloads"), never by full path,
 *   and the website can only choose among them.
 * - Results sent back hold file names, verdicts and hashes, not file contents or paths.
 * - Commands run one at a time.
 * - Between heartbeats one long request stays open, so a command from the website
 *   starts within a second or two. While a scan runs, counts (files scanned,
 *   threats found) are reported every few seconds for the website's progress bar.
 */
import {
  type CommandReport,
  type LinkedAccount,
  type RemoteCommand,
  AccountLinkError,
  type ScanProgress,
  fetchCommands,
  reportProgress,
  reportResult,
  reportStarted,
  sendHeartbeat,
  waitForCommand,
} from "./account";

export interface OfferedFolder {
  id: string;
  label: string;
  path: string;
}

export interface Detection {
  name: string;
  folder: string | null;
  verdict: "malicious" | "suspicious";
  title: string;
  sha256: string | null;
  quarantined: boolean;
}

export interface ScanOutcome {
  scanned: number;
  malicious: number;
  suspicious: number;
  quarantined: number;
  detections: Detection[];
}

export interface RemoteHost {
  account(): LinkedAccount | null;
  allowRemote(): boolean;
  folders(): OfferedFolder[];
  homeFolder(): string;
  status(): Record<string, string | number | boolean | null>;
  version(): string;
  scan(paths: { path: string; label: string | null }[], onProgress?: (progress: ScanProgress) => void): Promise<ScanOutcome>;
  quarantineByHash(sha256: string[]): Promise<number>;
  updateSignatures(): Promise<void>;
  /** Called when the server says this device was removed from the account. */
  unlinked(): void;
  activity(message: string): void;
}

export const HEARTBEAT_MS = 30_000;
export const WAIT_SECONDS = 25;
export const PROGRESS_EVERY_MS = 3_000;
const MIN_WAIT_GAP_MS = 5_000;
export const MAX_REPORTED_DETECTIONS = 200;

export class RemoteAgent {
  private timer: NodeJS.Timeout | null = null;
  private busy = false;
  private waiting = false;
  private running = false;
  lastError: string | null = null;
  lastContact: string | null = null;

  constructor(
    private readonly host: RemoteHost,
    private readonly fetcher: typeof fetch = fetch,
  ) {}

  start(): void {
    if (this.timer) return;
    this.running = true;
    this.timer = setInterval(() => void this.tick(), HEARTBEAT_MS);
    this.timer.unref?.();
    void this.tick();
    void this.waitLoop();
  }

  stop(): void {
    this.running = false;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Keeps one long request open; when the server says a command is waiting, tick now. */
  private async waitLoop(): Promise<void> {
    if (this.waiting) return;
    this.waiting = true;
    try {
      while (this.running) {
        const account = this.host.account();
        if (!account || !this.host.allowRemote()) {
          await pause(MIN_WAIT_GAP_MS); // look again soon, so turning remote scans on takes effect quickly
          continue;
        }
        try {
          const began = Date.now();
          if (await this.waitOnce(account)) await this.tick();
          // A server should hold the request open; never poll faster than this.
          else if (Date.now() - began < MIN_WAIT_GAP_MS) await pause(MIN_WAIT_GAP_MS);
        } catch {
          // Server unreachable, or an older server without /devices/wait: the
          // regular heartbeat still delivers commands. Back off before retrying.
          await pause(HEARTBEAT_MS);
        }
      }
    } finally {
      this.waiting = false;
    }
  }

  /** One long poll. Exposed for tests. */
  async waitOnce(account: LinkedAccount): Promise<boolean> {
    return waitForCommand(account, WAIT_SECONDS, this.fetcher);
  }

  /** One heartbeat, then any waiting commands. Safe to call at any time. */
  async tick(): Promise<void> {
    const account = this.host.account();
    if (!account || this.busy) return;
    this.busy = true;
    try {
      const pending = await sendHeartbeat(
        account,
        {
          allow_remote: this.host.allowRemote(),
          folders: this.host.folders().map(({ id, label }) => ({ id, label })),
          status: this.host.status(),
          app_version: this.host.version(),
        },
        this.fetcher,
      );
      this.lastContact = new Date().toISOString();
      this.lastError = null;
      if (pending > 0) {
        for (const command of await fetchCommands(account, this.fetcher)) {
          await this.run(account, command);
        }
      }
    } catch (error) {
      if (error instanceof AccountLinkError && error.status === 401) {
        this.host.unlinked();
        this.lastError = "This computer was removed from your Qalaa account.";
      } else {
        this.lastError = error instanceof Error ? error.message : String(error);
      }
    } finally {
      this.busy = false;
    }
  }

  private async run(account: LinkedAccount, command: RemoteCommand): Promise<void> {
    if (!this.host.allowRemote()) {
      await reportResult(account, command.id, { ok: false, error: "Remote scans are turned off on this computer." }, this.fetcher);
      return;
    }
    await reportStarted(account, command.id, this.fetcher);
    const started = Date.now();
    let lastSent = 0;
    const onProgress = (progress: ScanProgress) => {
      const now = Date.now();
      if (now - lastSent < PROGRESS_EVERY_MS) return;
      lastSent = now;
      // Fire and forget: progress is best effort and must never slow the scan.
      void reportProgress(account, command.id, progress, this.fetcher).catch(() => undefined);
    };
    let report: CommandReport;
    try {
      report = await this.execute(command, onProgress);
    } catch (error) {
      report = { ok: false, error: (error instanceof Error ? error.message : String(error)).slice(0, 300) };
    }
    report.duration_seconds = Math.round((Date.now() - started) / 1000);
    await reportResult(account, command.id, report, this.fetcher);
  }

  private async execute(command: RemoteCommand, onProgress: (progress: ScanProgress) => void): Promise<CommandReport> {
    const folders = this.host.folders();
    switch (command.kind) {
      case "quick_scan":
        this.host.activity("Quick scan started from your Qalaa account");
        return toReport(await this.host.scan(folders.filter((f) => f.id.startsWith("watch")).map(({ path, label }) => ({ path, label })), onProgress));
      case "full_scan":
        this.host.activity("Full scan started from your Qalaa account");
        return toReport(await this.host.scan([{ path: this.host.homeFolder(), label: "Home" }], onProgress));
      case "folder_scan": {
        const folder = folders.find((f) => f.id === command.args.folder_id);
        if (!folder) return { ok: false, error: "That folder is no longer offered by this computer." };
        this.host.activity(`Scan of ${folder.label} started from your Qalaa account`);
        return toReport(await this.host.scan([{ path: folder.path, label: folder.label }], onProgress));
      }
      case "quarantine": {
        const hashes = (command.args.sha256 ?? []).filter((h) => /^[0-9a-f]{64}$/.test(h));
        const moved = await this.host.quarantineByHash(hashes);
        this.host.activity(`${moved} file(s) moved to quarantine from your Qalaa account`);
        return { ok: true, quarantined: moved };
      }
      case "update_signatures":
        await this.host.updateSignatures();
        return { ok: true };
      default:
        return { ok: false, error: "This version of the app does not support that command." };
    }
  }
}

function toReport(outcome: ScanOutcome): CommandReport {
  return {
    ok: true,
    scanned: outcome.scanned,
    malicious: outcome.malicious,
    suspicious: outcome.suspicious,
    quarantined: outcome.quarantined,
    detections: outcome.detections.slice(0, MAX_REPORTED_DETECTIONS),
  };
}

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms).unref?.());
}

/**
 * Which files a "quarantine" command from the account may move: only ones this
 * computer itself found malicious or suspicious, by the hashes the command names,
 * once each and not already in quarantine. A command (or a compromised server)
 * can't use a hash to make this computer hide an ordinary file it once scanned.
 */
export function quarantineCandidates<T extends { path: string; sha256: string | null; verdict: string }>(history: T[], hashes: string[], alreadyQuarantined: Set<string>): T[] {
  const wanted = new Set(hashes.filter((h) => /^[0-9a-f]{64}$/.test(h)));
  const seen = new Set<string>();
  const out: T[] = [];
  for (const entry of history) {
    if (!entry.sha256 || !wanted.has(entry.sha256)) continue;
    if (entry.verdict !== "malicious" && entry.verdict !== "suspicious") continue;
    if (seen.has(entry.path) || alreadyQuarantined.has(entry.path)) continue;
    seen.add(entry.path);
    out.push(entry);
  }
  return out;
}

