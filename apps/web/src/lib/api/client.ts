import type {
  Activity,
  Explanation,
  ExtensionEvent,
  Installation,
  Overview,
  Profile,
  ProviderStatus,
  RiskLevel,
  Scan,
  ScanPage,
  ScanStatus,
  ScanType,
  SessionInfo,
  SessionStatus,
} from "./types";

const BASE = "/api/v1";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details: unknown = null,
  ) {
    super(message);
    this.name = "ApiError";
  }

  /** Field-level messages from a validation error, keyed by field name. */
  fieldErrors(): Record<string, string> {
    if (this.code !== "validation_error" || !Array.isArray(this.details)) return {};
    const errors: Record<string, string> = {};
    for (const item of this.details) {
      if (item && typeof item === "object" && "field" in item && "message" in item) {
        errors[String(item.field)] = String(item.message);
      }
    }
    return errors;
  }
}

// The CSRF token comes from the session endpoint and lives in memory only. It is
// sent as a header, which a cross-site form or image cannot do.
let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

function describeNetworkFailure(): ApiError {
  return new ApiError(
    0,
    "network_error",
    "We could not reach SENTINEL. Check your connection and try again.",
  );
}

async function readError(response: Response): Promise<ApiError> {
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "error" in body) {
      const error = (body as { error: { code?: string; message?: string; details?: unknown } })
        .error;
      return new ApiError(
        response.status,
        error.code ?? "http_error",
        error.message ?? "The request failed.",
        error.details ?? null,
      );
    }
  } catch {
    // Not JSON: typically a proxy error page while the API is down.
  }
  if (response.status >= 500) {
    return new ApiError(
      response.status,
      "service_unavailable",
      "The SENTINEL service is unavailable right now. Please try again shortly.",
    );
  }
  return new ApiError(response.status, "http_error", "The request failed.");
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  json?: unknown;
  form?: FormData;
  query?: Record<string, string | number | undefined | null>;
  signal?: AbortSignal;
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.json !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const url = `${BASE}${path}${params.size ? `?${params}` : ""}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body: options.form ?? (options.json !== undefined ? JSON.stringify(options.json) : undefined),
      credentials: "same-origin",
      signal: options.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw describeNetworkFailure();
  }

  if (!response.ok) throw await readError(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function uploadScan(path: string, file: File): Promise<Scan> {
  const form = new FormData();
  form.append("file", file);
  return request<Scan>(path, { method: "POST", form });
}

export interface HistoryFilters {
  type?: ScanType | "";
  risk?: RiskLevel | "";
  status?: ScanStatus | "";
  since?: string;
  until?: string;
  page?: number;
  pageSize?: number;
}

export const api = {
  auth: {
    session: () => request<SessionStatus>("/auth/session"),
    register: (body: { email: string; password: string; display_name?: string }) =>
      request<SessionInfo>("/auth/register", { method: "POST", json: body }),
    login: (body: { email: string; password: string }) =>
      request<SessionInfo>("/auth/login", { method: "POST", json: body }),
    logout: () => request<void>("/auth/logout", { method: "POST" }),
  },
  scans: {
    url: (url: string) => request<Scan>("/scans/url", { method: "POST", json: { url } }),
    message: (content: string) =>
      request<Scan>("/scans/message", { method: "POST", json: { content } }),
    file: (file: File) => uploadScan("/scans/file", file),
    qr: (image: File) => uploadScan("/scans/qr", image),
    apk: (file: File) => uploadScan("/scans/apk", file),
    website: (url: string) => request<Scan>("/scans/website", { method: "POST", json: { url } }),
    explain: (id: string) =>
      request<Explanation>(`/scans/${encodeURIComponent(id)}/explanation`, { method: "POST" }),
    get: (id: string, signal?: AbortSignal) =>
      request<Scan>(`/scans/${encodeURIComponent(id)}`, { signal }),
    remove: (id: string) =>
      request<void>(`/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),
    history: (filters: HistoryFilters = {}) =>
      request<ScanPage>("/scans/history", {
        query: {
          type: filters.type,
          risk: filters.risk,
          status: filters.status,
          since: filters.since,
          until: filters.until,
          page: filters.page,
          page_size: filters.pageSize,
        },
      }),
    clearHistory: () => request<void>("/scans/history", { method: "DELETE" }),
  },
  user: {
    profile: () => request<Profile>("/user/profile"),
    updateSettings: (body: {
      display_name?: string | null;
      save_scan_history?: boolean;
      sync_extension_events?: boolean;
    }) =>
      request<Profile>("/user/settings", { method: "PATCH", json: body }),
    changePassword: (body: { current_password: string; new_password: string }) =>
      request<void>("/user/password", { method: "POST", json: body }),
    overview: () => request<Overview>("/user/overview"),
    activity: () => request<Activity[]>("/user/activity"),
    exportData: () => request<Record<string, unknown>>("/user/export"),
    deleteAccount: (password: string) =>
      request<void>("/user/account", { method: "DELETE", json: { password } }),
  },
  extension: {
    createLinkCode: () =>
      request<{ code: string; expires_at: string }>("/extension/link-codes", { method: "POST" }),
    installations: () => request<Installation[]>("/extension/installations"),
    revoke: (id: string) =>
      request<void>(`/extension/installations/${encodeURIComponent(id)}`, { method: "DELETE" }),
    events: () => request<ExtensionEvent[]>("/extension/events"),
    clearEvents: () => request<void>("/extension/events", { method: "DELETE" }),
  },
  system: {
    providers: () => request<ProviderStatus[]>("/system/providers"),
  },
};
