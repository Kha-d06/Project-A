/**
 * Linking this computer to a Qalaa account, so its owner can see its status
 * and start scans on it from the website. The device token is kept in the app's
 * private data folder (owner-only permissions) and never shown in the interface.
 */
import { readFile, rename, rm, writeFile } from "node:fs/promises";

export interface LinkedAccount {
  deviceId: string;
  token: string;
  email: string;
  server: string;
}

export interface RemoteCommand {
  id: string;
  kind: "quick_scan" | "full_scan" | "folder_scan" | "quarantine" | "update_signatures";
  args: { folder_id?: string; folder_label?: string; sha256?: string[] };
}

export interface CommandReport {
  ok: boolean;
  error?: string;
  scanned?: number;
  malicious?: number;
  suspicious?: number;
  quarantined?: number;
  detections?: { name: string; folder?: string | null; verdict: "malicious" | "suspicious"; title: string; sha256?: string | null; quarantined?: boolean }[];
  duration_seconds?: number;
}

export class AccountLinkError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

const TIMEOUT_MS = 20_000;

function api(server: string, path: string): string {
  return `${server.replace(/\/$/, "")}/api/v1${path}`;
}

async function call(
  server: string,
  path: string,
  init: RequestInit & { token?: string; timeoutMs?: number } = {},
  fetcher: typeof fetch = fetch,
): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (init.body) headers["Content-Type"] = "application/json";
  if (init.token) headers.Authorization = `Bearer ${init.token}`;
  const { timeoutMs, ...rest } = init;
  const response = await fetcher(api(server, path), { ...rest, headers, signal: AbortSignal.timeout(timeoutMs ?? TIMEOUT_MS) });
  if (!response.ok && response.status !== 204) {
    let message = `The server answered ${response.status}`;
    try {
      message = ((await response.json()) as { error?: { message?: string } }).error?.message ?? message;
    } catch {
      // keep the status message
    }
    throw new AccountLinkError(message, response.status);
  }
  return response;
}

export async function loadAccount(file: string): Promise<LinkedAccount | null> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as LinkedAccount;
  } catch {
    return null;
  }
}

export async function saveAccount(file: string, account: LinkedAccount | null): Promise<void> {
  if (!account) {
    await rm(file, { force: true });
    return;
  }
  await writeFile(`${file}.tmp`, JSON.stringify(account), { mode: 0o600 });
  await rename(`${file}.tmp`, file);
}

export async function register(
  server: string,
  code: string,
  name: string,
  platform: "windows" | "macos" | "linux",
  version: string,
  fetcher: typeof fetch = fetch,
): Promise<LinkedAccount> {
  const response = await call(server, "/devices/register", {
    method: "POST",
    body: JSON.stringify({ link_code: code.trim(), name: name.slice(0, 80), platform, app_version: version }),
  }, fetcher);
  const body = (await response.json()) as { device_id: string; token: string; account_email: string };
  return { deviceId: body.device_id, token: body.token, email: body.account_email, server };
}

export async function sendHeartbeat(
  account: LinkedAccount,
  payload: { allow_remote: boolean; folders: { id: string; label: string }[]; status: Record<string, string | number | boolean | null>; app_version: string },
  fetcher: typeof fetch = fetch,
): Promise<number> {
  const response = await call(account.server, "/devices/heartbeat", { method: "POST", body: JSON.stringify(payload), token: account.token }, fetcher);
  return ((await response.json()) as { pending_commands: number }).pending_commands;
}

export async function fetchCommands(account: LinkedAccount, fetcher: typeof fetch = fetch): Promise<RemoteCommand[]> {
  const response = await call(account.server, "/devices/commands", { token: account.token }, fetcher);
  return (await response.json()) as RemoteCommand[];
}

/** Long poll: resolves true as soon as the website queues a command for this computer. */
export async function waitForCommand(account: LinkedAccount, seconds: number, fetcher: typeof fetch = fetch): Promise<boolean> {
  const response = await call(account.server, `/devices/wait?seconds=${seconds}`, { token: account.token, timeoutMs: (seconds + 15) * 1000 }, fetcher);
  return ((await response.json()) as { pending: boolean }).pending;
}

export interface ScanProgress {
  scanned: number;
  found: number;
  folder?: string | null;
}

/** Counts only: never file names or paths. */
export async function reportProgress(account: LinkedAccount, id: string, progress: ScanProgress, fetcher: typeof fetch = fetch): Promise<void> {
  const body = { scanned: progress.scanned, found: progress.found, ...(progress.folder ? { folder: progress.folder.slice(0, 80) } : {}) };
  await call(account.server, `/devices/commands/${encodeURIComponent(id)}/progress`, { method: "POST", body: JSON.stringify(body), token: account.token }, fetcher);
}

export async function reportStarted(account: LinkedAccount, id: string, fetcher: typeof fetch = fetch): Promise<void> {
  await call(account.server, `/devices/commands/${encodeURIComponent(id)}/started`, { method: "POST", token: account.token }, fetcher);
}

export async function reportResult(account: LinkedAccount, id: string, report: CommandReport, fetcher: typeof fetch = fetch): Promise<void> {
  await call(account.server, `/devices/commands/${encodeURIComponent(id)}/result`, { method: "POST", body: JSON.stringify(report), token: account.token }, fetcher);
}

export async function unlinkSelf(account: LinkedAccount, fetcher: typeof fetch = fetch): Promise<void> {
  await call(account.server, "/devices/self", { method: "DELETE", token: account.token }, fetcher).catch(() => undefined);
}
