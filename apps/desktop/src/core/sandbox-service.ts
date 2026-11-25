/**
 * Sending a file to the person's Qalaa server to be run in its gVisor sandbox
 * (Wave 4.C), and following the result.
 *
 * Only ever on an explicit request for one chosen file: the file's contents
 * go to the server the person configured, nowhere else, and never in the
 * background. The server runs Linux programs and scripts only; for anything
 * else, or a server without a sandbox, its report says so and that is shown.
 */
import { stat } from "node:fs/promises";
import { basename } from "node:path";

import { uploadForFullScan } from "../engine/server";
import { IpcError } from "./protocol";

export interface SandboxRun {
  id: string;
  file: string;
  reportUrl: string;
  /** queued, running, completed or failed (the server's scan status). */
  status: string;
  risk: string | null;
  /** Why there was no sandbox run, when the server said so. */
  note: string | null;
  timedOut: boolean;
  seconds: number | null;
  dnsLookups: string[];
  webRequests: string[];
  directConnections: string[];
  programs: string[];
  submittedAt: string;
}

export interface SandboxDeps {
  server: () => string;
  upload?: (server: string, path: string) => Promise<string>;
  fetcher?: typeof fetch;
  now?: () => Date;
}

const MAX_RUNS = 10;
const MAX_FILE = 25 * 1024 * 1024;
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").slice(0, 20) : []);

export class SandboxService {
  private runs: SandboxRun[] = [];

  constructor(private readonly deps: SandboxDeps) {}

  async submit(path: unknown): Promise<SandboxRun> {
    if (typeof path !== "string" || !path || path.length > 4096) throw new IpcError("bad_params", "Choose a file to send.");
    const info = await stat(path).catch(() => null);
    if (!info?.isFile()) throw new IpcError("not_found", "That file doesn't exist.");
    if (info.size > MAX_FILE) throw new IpcError("too_large", "The file is larger than the server accepts (25 MB).");
    const server = this.deps.server().replace(/\/$/, "");
    const upload = this.deps.upload ?? ((s: string, p: string) => uploadForFullScan(s, p, this.deps.fetcher ?? fetch, { runInSandbox: true }));
    let reportUrl: string;
    try {
      reportUrl = await upload(server, path);
    } catch (error) {
      throw new IpcError("failed", `The file couldn't be sent: ${error instanceof Error ? error.message : String(error)}`);
    }
    const id = reportUrl.split("/").pop() ?? "";
    const run: SandboxRun = {
      id, file: basename(path), reportUrl, status: "queued", risk: null, note: null, timedOut: false, seconds: null,
      dnsLookups: [], webRequests: [], directConnections: [], programs: [],
      submittedAt: (this.deps.now ?? (() => new Date()))().toISOString(),
    };
    this.runs = [run, ...this.runs].slice(0, MAX_RUNS);
    return { ...run };
  }

  /** Refreshes unfinished runs from the server and returns them all, newest first. */
  async list(): Promise<SandboxRun[]> {
    for (const run of this.runs) {
      if (run.status === "completed" || run.status === "failed") continue;
      await this.refresh(run).catch(() => undefined); // offline: keep the last state
    }
    return this.runs.map((r) => ({ ...r }));
  }

  private async refresh(run: SandboxRun): Promise<void> {
    const response = await (this.deps.fetcher ?? fetch)(`${this.deps.server().replace(/\/$/, "")}/api/v1/scans/${encodeURIComponent(run.id)}`, { signal: AbortSignal.timeout(20_000) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const scan = (await response.json()) as { status?: string; risk?: string | null; details?: { detonation?: Record<string, unknown> }; checks?: { key?: string; status?: string; detail?: string }[] };
    run.status = typeof scan.status === "string" ? scan.status : run.status;
    run.risk = typeof scan.risk === "string" ? scan.risk : null;
    const d = scan.details?.detonation ?? {};
    run.timedOut = d.timed_out === true;
    run.seconds = typeof d.seconds === "number" ? d.seconds : null;
    run.dnsLookups = strings(d.dns_lookups);
    run.webRequests = strings(d.web_requests);
    run.directConnections = strings(d.direct_connections);
    run.programs = strings(d.programs);
    const check = scan.checks?.find((c) => c.key === "detonation");
    run.note = check && check.status !== "completed" ? String(check.detail ?? "").slice(0, 300) || null : null;
  }
}
