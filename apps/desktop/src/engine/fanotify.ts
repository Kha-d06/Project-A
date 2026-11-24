/**
 * Linux on-access scanning, built on the kernel's fanotify permission events.
 * No kernel module and no custom driver: fanotify is a user-space interface.
 * Because marking files for permission events needs CAP_SYS_ADMIN, the part
 * that talks to the kernel is a small root helper (resources/qalaa-onaccessd.py)
 * run as a systemd service. For every file open it asks this app for a verdict
 * over a local socket and then allows or denies the open.
 *
 * This module is the user-space half: it answers the helper's verdict requests
 * using the normal scanner, and it installs / starts / stops the helper. If the
 * app isn't running the helper fails open (allows), so the machine never locks
 * up — on-access protection is simply active only while Qalaa runs.
 *
 * Everything here is Linux-only and degrades cleanly elsewhere (guardrail 3).
 */
import { createServer, type Server } from "node:net";
import { mkdir, rm } from "node:fs/promises";
import { dirname } from "node:path";

import type { ScanResult } from "./types";

export interface VerdictRequest {
  id: number;
  path: string;
  /** PID that is opening the file, when the helper could resolve it. */
  pid?: number;
}

export interface VerdictResponse {
  id: number;
  verdict: "allow" | "deny";
  reason: string;
  /** When true, the helper freezes (SIGSTOP) the process behind this open. */
  halt?: boolean;
}

/** Decide what to do with a scanned file. Only known-malicious opens are blocked. */
export function decide(result: ScanResult): VerdictResponse["verdict"] {
  return result.verdict === "malicious" ? "deny" : "allow";
}

/** Parse one newline-delimited request from the helper. Returns null if malformed. */
export function parseRequest(line: string): VerdictRequest | null {
  try {
    const value = JSON.parse(line) as Partial<VerdictRequest>;
    if (typeof value.id === "number" && typeof value.path === "string" && value.path.startsWith("/")) {
      return { id: value.id, path: value.path, pid: typeof value.pid === "number" ? value.pid : undefined };
    }
  } catch {
    // malformed line
  }
  return null;
}

export function encodeResponse(response: VerdictResponse): string {
  return `${JSON.stringify(response)}\n`;
}

/** Decides a behavioural response from a per-open event, for the server to use. */
export interface BehaviourHook {
  /** Returns a halt reason when this open completes a ransomware pattern. */
  feed(pid: number, path: string): { reason: string; files: number } | null;
}

/** systemctl is-active output → a simple state. */
export function parseServiceState(output: string): "active" | "inactive" | "failed" | "absent" {
  const value = output.trim();
  if (value === "active") return "active";
  if (value === "failed") return "failed";
  if (value === "inactive" || value === "activating" || value === "deactivating") return "inactive";
  return "absent"; // "unknown", not-found, or empty
}

/** The systemd unit that runs the helper as root and restarts it with the machine. */
export function unitFile(helperPath: string, socketPath: string, markRoots: string[], user: string): string {
  const roots = markRoots.map((r) => `--mark ${r}`).join(" ");
  return [
    "[Unit]",
    "Description=Qalaa on-access file scanning (fanotify)",
    "After=network.target",
    "",
    "[Service]",
    "Type=simple",
    // The helper drops no privileges (fanotify needs them) but only ever asks the
    // user's Qalaa app for verdicts; it never scans or quarantines by itself.
    `ExecStart=/usr/bin/python3 ${helperPath} --socket ${socketPath} --user ${user} ${roots}`,
    "Restart=on-failure",
    "RestartSec=5",
    "Nice=5",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
}

export interface OnAccessOptions {
  socketPath: string;
  scan: (path: string) => Promise<ScanResult>;
  /** Paths to allow without scanning (user exclusions). */
  isExcluded?: (path: string) => boolean;
  /** Called when an open is blocked, for logging and notifications. */
  onBlocked?: (path: string, result: ScanResult) => void;
  /** Behavioural ransomware detector, fed every open; trips to freeze a process. */
  behaviour?: BehaviourHook;
  /** Called when a process is frozen for ransomware behaviour. */
  onHalt?: (pid: number, reason: string, files: number) => void;
  /** Sees every open (pid and path) before any verdict, for credential guardrails. Never blocks. */
  onOpen?: (pid: number, path: string) => void;
  /** Milliseconds to spend on one verdict before failing open. */
  timeoutMs?: number;
}

/**
 * Listens on the local socket and answers the helper's verdict requests. One
 * connection, many newline-delimited requests; replies may be out of order.
 */
export class OnAccessServer {
  private server: Server | null = null;
  private readonly options: OnAccessOptions;

  constructor(options: OnAccessOptions) {
    this.options = options;
  }

  async start(): Promise<void> {
    await mkdir(dirname(this.options.socketPath), { recursive: true }).catch(() => {});
    await rm(this.options.socketPath, { force: true }).catch(() => {});
    this.server = createServer((socket) => {
      let buffer = "";
      socket.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        let index: number;
        while ((index = buffer.indexOf("\n")) >= 0) {
          const line = buffer.slice(0, index);
          buffer = buffer.slice(index + 1);
          const request = parseRequest(line);
          if (request) void this.handle(request, socket);
        }
      });
      socket.on("error", () => {});
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.options.socketPath, resolve);
    });
  }

  private async handle(request: VerdictRequest, socket: NodeJS.WritableStream): Promise<void> {
    const reply = (verdict: VerdictResponse["verdict"], reason: string, halt = false) => {
      try {
        socket.write(encodeResponse({ id: request.id, verdict, reason, ...(halt ? { halt: true } : {}) }));
      } catch {
        // the helper went away; nothing to do
      }
    };
    if (this.options.onOpen && typeof request.pid === "number" && request.pid > 0) {
      try {
        this.options.onOpen(request.pid, request.path);
      } catch {
        // an observer must never hold up or break the open
      }
    }
    // Behavioural ransomware check runs on every open, regardless of the file verdict.
    if (this.options.behaviour && typeof request.pid === "number" && request.pid > 0) {
      const halt = this.options.behaviour.feed(request.pid, request.path);
      if (halt) {
        this.options.onHalt?.(request.pid, halt.reason, halt.files);
        reply("deny", "ransomware", true);
        return;
      }
    }
    if (this.options.isExcluded?.(request.path)) {
      reply("allow", "excluded");
      return;
    }
    const timeout = new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), this.options.timeoutMs ?? 4000));
    try {
      const outcome = await Promise.race([this.options.scan(request.path), timeout]);
      if (outcome === "timeout") {
        reply("allow", "timeout"); // never freeze the machine on a slow scan
        return;
      }
      const verdict = decide(outcome);
      if (verdict === "deny") this.options.onBlocked?.(request.path, outcome);
      reply(verdict, outcome.verdict);
    } catch {
      reply("allow", "error"); // fail open on any scan error
    }
  }

  async stop(): Promise<void> {
    const server = this.server;
    this.server = null;
    if (!server) return;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(this.options.socketPath, { force: true }).catch(() => {});
  }
}

// --- Privileged lifecycle (install / enable / disable the root helper) ------------------

export const SERVICE_NAME = "qalaa-onaccess.service";
const INSTALLED_HELPER = "/usr/local/lib/qalaa/qalaa-onaccessd.py";
const UNIT_PATH = `/etc/systemd/system/${SERVICE_NAME}`;

export interface InstallParams {
  /** Path to the helper shipped inside the app bundle. */
  bundledHelper: string;
  socketPath: string;
  markRoots: string[];
  user: string;
}

/**
 * A single root script (run once via pkexec) that installs the helper and unit
 * and enables the service. Kept to plain, auditable shell so the person can see
 * exactly what elevates.
 */
export function installScript(params: InstallParams): string {
  const unit = unitFile(INSTALLED_HELPER, params.socketPath, params.markRoots, params.user);
  return [
    "#!/bin/sh",
    "set -e",
    "install -d -m 0755 /usr/local/lib/qalaa",
    `install -m 0755 '${params.bundledHelper}' '${INSTALLED_HELPER}'`,
    // A quoted here-doc delimiter keeps the unit text literal (no shell expansion).
    `cat > '${UNIT_PATH}' <<'QALAA_UNIT'\n${unit}QALAA_UNIT`,
    "systemctl daemon-reload",
    `systemctl enable --now ${SERVICE_NAME}`,
    "",
  ].join("\n");
}

/** The root script that stops and removes the service. */
export function uninstallScript(): string {
  return [
    "#!/bin/sh",
    `systemctl disable --now ${SERVICE_NAME} 2>/dev/null || true`,
    `rm -f '${UNIT_PATH}' '${INSTALLED_HELPER}'`,
    "systemctl daemon-reload 2>/dev/null || true",
    "",
  ].join("\n");
}

type Runner = (cmd: string, args: string[]) => Promise<string>;

const execCmd: Runner = (cmd, args) =>
  new Promise((resolve, reject) => {
    import("node:child_process").then(({ execFile }) => {
      execFile(cmd, args, { timeout: 120_000, windowsHide: true, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
        if (error && !stdout) reject(new Error(String(stderr || error.message)));
        else resolve(String(stdout));
      });
    });
  });

/** Whether this system can run on-access scanning at all. */
export function onAccessSupported(platform: NodeJS.Platform = process.platform): boolean {
  return platform === "linux";
}

/** Current service state (and whether systemd/pkexec are present to manage it). */
export async function onAccessStatus(run: Runner = execCmd): Promise<{ supported: boolean; state: "active" | "inactive" | "failed" | "absent"; manageable: boolean }> {
  if (!onAccessSupported()) return { supported: false, state: "absent", manageable: false };
  const state = parseServiceState(await run("systemctl", ["is-active", SERVICE_NAME]).catch(() => "absent"));
  const manageable = await run("sh", ["-c", "command -v pkexec && command -v systemctl"]).then(() => true).catch(() => false);
  return { supported: true, state, manageable };
}

/** Run a privileged script through pkexec. The user sees a password prompt. */
async function runPrivileged(script: string, run: Runner): Promise<void> {
  await run("pkexec", ["sh", "-c", script]);
}

export async function enableOnAccess(params: InstallParams, run: Runner = execCmd): Promise<void> {
  await runPrivileged(installScript(params), run);
}

export async function disableOnAccess(run: Runner = execCmd): Promise<void> {
  await runPrivileged(uninstallScript(), run);
}
