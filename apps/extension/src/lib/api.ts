import type { ScreenTimeRule } from "./screentime";
import type { CheckResult, ServerVerdict } from "./types";

/**
 * Talks to the Qalaa API. Only the background service worker uses this.
 *
 * Credentials: the refresh token lives in chrome.storage.local (extension-private,
 * never exposed to web pages); access tokens live in chrome.storage.session and
 * expire after 15 minutes.
 */

export const REQUEST_TIMEOUT_MS = 4000;
const CREDENTIALS_KEY = "credentials";
const ACCESS_KEY = "accessToken";

declare const __EXTENSION_VERSION__: string;
const VERSION = typeof __EXTENSION_VERSION__ === "string" ? __EXTENSION_VERSION__ : "0.0.0";

export class CheckUnavailable extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

export class ApiRequestError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

interface StoredCredentials {
  installationId: string;
  refreshToken: string;
}

interface AccessToken {
  token: string;
  expiresAt: number;
}

interface ServerResult {
  verdict: ServerVerdict;
  host: string;
  reasons: { severity: string; title: string; explanation: string; source: string }[];
  sources: string[];
  limitations: string[];
  checked_at: string;
  cache_seconds: number;
}

export interface AccountLink {
  installation_id: string;
  linked: boolean;
  account_email: string | null;
  sync_events: boolean;
  family_blocklist?: string[];
  safe_search?: boolean;
  lock_protection?: boolean;
  family_groups?: string[];
  screen_time?: ScreenTimeRule | null;
}

function browserName(): string {
  const agent = typeof navigator === "undefined" ? "" : navigator.userAgent;
  if (agent.includes("Edg/")) return "edge";
  if (agent.includes("Firefox/")) return "firefox";
  return "chrome";
}

async function send(
  serverUrl: string,
  path: string,
  init: RequestInit & { token?: string } = {},
): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (init.body) headers["Content-Type"] = "application/json";
  if (init.token) headers.Authorization = `Bearer ${init.token}`;
  try {
    return await fetch(`${serverUrl.replace(/\/$/, "")}/api/v1${path}`, {
      ...init,
      headers,
      credentials: "omit",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    if (typeof navigator !== "undefined" && navigator.onLine === false) {
      throw new CheckUnavailable("You appear to be offline.");
    }
    const timedOut = error instanceof DOMException && error.name === "TimeoutError";
    throw new CheckUnavailable(
      timedOut ? "The Qalaa server took too long to answer." : "The Qalaa server could not be reached.",
    );
  }
}

async function readError(response: Response): Promise<ApiRequestError> {
  try {
    const body = (await response.json()) as { error?: { code?: string; message?: string } };
    return new ApiRequestError(response.status, body.error?.code ?? "http_error", body.error?.message ?? "Request failed.");
  } catch {
    return new ApiRequestError(response.status, "http_error", "The Qalaa server returned an unexpected answer.");
  }
}

export async function getCredentials(): Promise<StoredCredentials | null> {
  const stored = await chrome.storage.local.get(CREDENTIALS_KEY);
  return (stored[CREDENTIALS_KEY] as StoredCredentials | undefined) ?? null;
}

export async function forgetCredentials(): Promise<void> {
  await chrome.storage.local.remove(CREDENTIALS_KEY);
  await chrome.storage.session.remove(ACCESS_KEY);
}

async function storeAccess(token: string, expiresIn: number): Promise<string> {
  // Renew a minute early so a token never expires mid-request.
  const value: AccessToken = { token, expiresAt: Date.now() + (expiresIn - 60) * 1000 };
  await chrome.storage.session.set({ [ACCESS_KEY]: value });
  return token;
}

export async function enroll(serverUrl: string, linkCode?: string): Promise<void> {
  const response = await send(serverUrl, "/extension/enroll", {
    method: "POST",
    body: JSON.stringify({ browser: browserName(), version: VERSION, link_code: linkCode || null }),
  });
  if (!response.ok) throw await readError(response);
  const body = (await response.json()) as {
    installation_id: string;
    refresh_token: string;
    access_token: string;
    expires_in: number;
  };
  await chrome.storage.local.set({
    [CREDENTIALS_KEY]: { installationId: body.installation_id, refreshToken: body.refresh_token },
  });
  await storeAccess(body.access_token, body.expires_in);
}

async function accessToken(serverUrl: string, forceRefresh = false): Promise<string> {
  if (!forceRefresh) {
    const stored = await chrome.storage.session.get(ACCESS_KEY);
    const current = stored[ACCESS_KEY] as AccessToken | undefined;
    if (current && current.expiresAt > Date.now()) return current.token;
  }
  const credentials = await getCredentials();
  if (!credentials) throw new CheckUnavailable("This extension is not connected to a Qalaa server yet.");

  const response = await send(serverUrl, "/extension/token", {
    method: "POST",
    body: JSON.stringify({ refresh_token: credentials.refreshToken }),
  });
  if (response.status === 401) {
    // Revoked from the dashboard: drop the credentials so the popup offers re-enrollment.
    await forgetCredentials();
    throw new CheckUnavailable("This extension was disconnected. Connect it again from the popup.");
  }
  if (!response.ok) throw new CheckUnavailable("The Qalaa server could not issue an access token.");
  const body = (await response.json()) as { access_token: string; expires_in: number };
  return storeAccess(body.access_token, body.expires_in);
}

/** Authenticated request that refreshes the access token once if it was rejected. */
async function authorized(serverUrl: string, path: string, init: RequestInit = {}): Promise<Response> {
  let response = await send(serverUrl, path, { ...init, token: await accessToken(serverUrl) });
  if (response.status === 401) {
    response = await send(serverUrl, path, { ...init, token: await accessToken(serverUrl, true) });
  }
  return response;
}

function toResult(body: ServerResult): CheckResult {
  return {
    verdict: body.verdict,
    host: body.host,
    reasons: body.reasons.map(({ severity, title, explanation, source }) => ({ severity, title, explanation, source })),
    sources: body.sources,
    limitations: body.limitations,
    checkedAt: body.checked_at,
    cacheSeconds: body.cache_seconds,
  };
}

async function postCheck(serverUrl: string, path: string, payload: object): Promise<CheckResult> {
  const response = await authorized(serverUrl, path, { method: "POST", body: JSON.stringify(payload) });
  if (response.status === 429) throw new CheckUnavailable("Too many checks in a short time. Checks will resume shortly.");
  if (!response.ok) {
    const error = await readError(response);
    throw new CheckUnavailable(error.message);
  }
  return toResult((await response.json()) as ServerResult);
}

export function checkUrl(serverUrl: string, url: string, mode: "full" | "host"): Promise<CheckResult> {
  return postCheck(serverUrl, "/extension/check-url", { url, mode });
}

export function checkDownload(serverUrl: string, url: string, filename: string): Promise<CheckResult> {
  return postCheck(serverUrl, "/extension/check-download", { url, filename });
}

/** The day's browsing minutes, for a linked account's family. Best effort. */
export async function reportScreenTime(serverUrl: string, day: string, minutes: number): Promise<boolean> {
  try {
    const response = await authorized(serverUrl, "/extension/screen-time", { method: "POST", body: JSON.stringify({ day, minutes }) });
    return response.ok;
  } catch {
    return false;
  }
}

export async function reportEvent(
  serverUrl: string,
  event: { kind: string; url: string; verdict: string },
): Promise<void> {
  try {
    await authorized(serverUrl, "/extension/report-event", { method: "POST", body: JSON.stringify(event) });
  } catch {
    // Event sync is best effort and never affects protection.
  }
}

export async function accountLink(serverUrl: string): Promise<AccountLink> {
  const response = await authorized(serverUrl, "/extension/settings");
  if (!response.ok) throw await readError(response);
  return (await response.json()) as AccountLink;
}

export async function link(serverUrl: string, code: string): Promise<AccountLink> {
  const response = await authorized(serverUrl, "/extension/link", {
    method: "POST",
    body: JSON.stringify({ link_code: code }),
  });
  if (!response.ok) throw await readError(response);
  return (await response.json()) as AccountLink;
}

export async function unlink(serverUrl: string): Promise<AccountLink> {
  const response = await authorized(serverUrl, "/extension/unlink", { method: "POST" });
  if (!response.ok) throw await readError(response);
  return (await response.json()) as AccountLink;
}

export interface BlocklistResponse {
  version: string;
  generated_at: string;
  hosts: string[];
  sources: string[];
}

export async function fetchBlocklist(serverUrl: string): Promise<BlocklistResponse> {
  const response = await authorized(serverUrl, "/extension/blocklist");
  if (!response.ok) throw await readError(response);
  return (await response.json()) as BlocklistResponse;
}

export interface AssistantContext {
  host: string;
  verdict: string;
  warning_signs: string[];
  cookies: { name: string; domain: string; third_party: boolean; session: boolean; days: number | null }[];
  trackers: string[];
  has_password_field: boolean;
}

/** Only the summary above is sent: never page text, form values or cookie values. */
export async function askAssistant(
  serverUrl: string,
  question: string,
  language: "en" | "ar",
  context: AssistantContext,
): Promise<{ answer: string; model: string }> {
  const response = await authorized(serverUrl, "/extension/assistant", {
    method: "POST",
    body: JSON.stringify({ question, language, context }),
  });
  if (!response.ok) throw await readError(response);
  return (await response.json()) as { answer: string; model: string };
}

export interface StoredVaultResponse {
  user_id: string;
  kdf: { name: "PBKDF2-SHA256"; iterations: number; salt: string };
  wrapped_key: string;
  data: string;
  version: number;
}

/** The account's encrypted vault (ciphertext only). Null when none exists. */
export async function fetchVault(serverUrl: string): Promise<StoredVaultResponse | null> {
  const response = await authorized(serverUrl, "/extension/vault");
  if (response.status === 404) return null;
  if (!response.ok) throw await readError(response);
  return (await response.json()) as StoredVaultResponse;
}

