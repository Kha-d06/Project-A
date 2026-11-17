/**
 * Lets the owner start scans on this computer from their SENTINEL account.
 *
 * - Nothing runs unless the person turned on "Allow scans from my SENTINEL account"
 *   in this app. The server is told, and the app checks again before each command.
 * - Folders are offered by id and label only ("Downloads"), never by full path,
 *   and the website can only choose among them.
 * - Results sent back hold file names, verdicts and hashes, not file contents or paths.
 * - Commands run one at a time.
 */
import {
  type CommandReport,
  type LinkedAccount,
  type RemoteCommand,
  AccountLinkError,
  fetchCommands,
  reportResult,
  reportStarted,
  sendHeartbeat,
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
  scan(paths: { path: string; label: string | null }[]): Promise<ScanOutcome>;
  quarantineByHash(sha256: string[]): Promise<number>;
  updateSignatures(): Promise<void>;
  /** Called when the server says this device was removed from the account. */
  unlinked(): void;
  activity(message: string): void;
}

export const HEARTBEAT_MS = 30_000;
export const MAX_REPORTED_DETECTIONS = 200;

export class RemoteAgent {
  private timer: NodeJS.Timeout | null = null;
  private busy = false;
  lastError: string | null = null;
  lastContact: string | null = null;

  constructor(
    private readonly host: RemoteHost,
    private readonly fetcher: typeof fetch = fetch,
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), HEARTBEAT_MS);
    this.timer.unref?.();
    void this.tick();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
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
        this.lastError = "This computer was removed from your SENTINEL account.";
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
    let report: CommandReport;
    try {
      report = await this.execute(command);
    } catch (error) {
      report = { ok: false, error: (error instanceof Error ? error.message : String(error)).slice(0, 300) };
    }
    report.duration_seconds = Math.round((Date.now() - started) / 1000);
    await reportResult(account, command.id, report, this.fetcher);
  }

  private async execute(command: RemoteCommand): Promise<CommandReport> {
    const folders = this.host.folders();
    switch (command.kind) {
      case "quick_scan":
        this.host.activity("Quick scan started from your SENTINEL account");
        return toReport(await this.host.scan(folders.filter((f) => f.id.startsWith("watch")).map(({ path, label }) => ({ path, label }))));
      case "full_scan":
        this.host.activity("Full scan started from your SENTINEL account");
        return toReport(await this.host.scan([{ path: this.host.homeFolder(), label: "Home" }]));
      case "folder_scan": {
        const folder = folders.find((f) => f.id === command.args.folder_id);
        if (!folder) return { ok: false, error: "That folder is no longer offered by this computer." };
        this.host.activity(`Scan of ${folder.label} started from your SENTINEL account`);
        return toReport(await this.host.scan([{ path: folder.path, label: folder.label }]));
      }
      case "quarantine": {
        const hashes = (command.args.sha256 ?? []).filter((h) => /^[0-9a-f]{64}$/.test(h));
        const moved = await this.host.quarantineByHash(hashes);
        this.host.activity(`${moved} file(s) moved to quarantine from your SENTINEL account`);
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
