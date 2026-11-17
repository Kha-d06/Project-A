import type {
  Activity,
  ApiKey,
  AdminOverview,
  AdminScan,
  AdminUser,
  AuditEntry,
  CommunityReport,
  LookupResult,
  ModerationItem,
  PublicReport,
  ReportCategory,
  ReportCreated,
  ReportStatus,
  SourceFreshness,
  Explanation,
  LoginChallenge,
  SecurityStatus,
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
  AdminStats,
  BreachResult,
  Device,
  DeviceCommand,
  DeviceCommandKind,
  VpnPeerConfig,
  VpnStatus,
  Trends,
  Group,
  GroupSharedScan,
  InviteCreated,
  Share,
  SharedScan,
  Webhook,
  WebhookEvent,
} from "./types";
import type { StoredVault } from "@/lib/vault";

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

// The API writes verdict summaries and advice in the language the page is using.
let requestLocale = "en";

export function setRequestLocale(locale: string) {
  requestLocale = locale;
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
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  json?: unknown;
  form?: FormData;
  query?: Record<string, string | number | undefined | null>;
  signal?: AbortSignal;
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json", "Accept-Language": requestLocale };
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

function uploadScan(path: string, file: File, fields: Record<string, string> = {}): Promise<Scan> {
  const form = new FormData();
  form.append("file", file);
  for (const [key, value] of Object.entries(fields)) form.append(key, value);
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
  sharing: {
    create: (scanId: string, body: { include_target?: boolean; note?: string; expires_in_days?: number; group_id?: string }) =>
      request<Share>(`/scans/${encodeURIComponent(scanId)}/shares`, { method: "POST", json: body }),
    list: (scanId: string) => request<Share[]>(`/scans/${encodeURIComponent(scanId)}/shares`),
    revoke: (shareId: string) => request<void>(`/shares/${encodeURIComponent(shareId)}`, { method: "DELETE" }),
    view: (token: string) => request<SharedScan>(`/shared/${encodeURIComponent(token)}`),
  },
  groups: {
    list: () => request<Group[]>("/groups"),
    create: (name: string, kind: Group["kind"]) => request<Group>("/groups", { method: "POST", json: { name, kind } }),
    invite: (groupId: string, email: string, role: "admin" | "member") =>
      request<InviteCreated>(`/groups/${encodeURIComponent(groupId)}/invites`, { method: "POST", json: { email, role } }),
    accept: (token: string) => request<Group>("/groups/invites/accept", { method: "POST", json: { token } }),
    setBlocklist: (groupId: string, domains: string[]) =>
      request<Group>(`/groups/${encodeURIComponent(groupId)}/blocklist`, { method: "PUT", json: { domains } }),
    updateMember: (groupId: string, userId: string, changes: { role?: "admin" | "member"; share_activity?: boolean; apply_blocklist?: boolean }) =>
      request<Group>(`/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`, { method: "PATCH", json: changes }),
    removeMember: (groupId: string, userId: string) =>
      request<void>(`/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`, { method: "DELETE" }),
    remove: (groupId: string) => request<void>(`/groups/${encodeURIComponent(groupId)}`, { method: "DELETE" }),
    shares: (groupId: string) => request<GroupSharedScan[]>(`/groups/${encodeURIComponent(groupId)}/shares`),
  },
  webhooks: {
    list: () => request<Webhook[]>("/user/webhooks"),
    create: (url: string, events: WebhookEvent[]) => request<Webhook>("/user/webhooks", { method: "POST", json: { url, events } }),
    setActive: (id: string, active: boolean) =>
      request<Webhook>(`/user/webhooks/${encodeURIComponent(id)}`, { method: "PATCH", query: { active: String(active) } }),
    remove: (id: string) => request<void>(`/user/webhooks/${encodeURIComponent(id)}`, { method: "DELETE" }),
  },
  push: {
    key: () => request<{ public_key: string | null }>("/push/key"),
    subscribe: (subscription: PushSubscriptionJSON) =>
      request<{ subscribed: boolean }>("/push/subscriptions", { method: "POST", json: subscription }),
    unsubscribe: (endpoint: string) => request<void>("/push/subscriptions", { method: "DELETE", json: { endpoint } }),
    test: () => request<{ delivered: number }>("/push/test", { method: "POST" }),
  },
  trends: (days = 30) => request<Trends>("/trends", { query: { days } }),
  breach: {
    email: () => request<BreachResult>("/breach/email"),
  },
  vpn: {
    status: () => request<VpnStatus>("/vpn"),
    add: (name: string, publicKey: string) =>
      request<VpnPeerConfig>("/vpn/devices", { method: "POST", json: { name, public_key: publicKey } }),
    remove: (id: string) => request<void>(`/vpn/devices/${encodeURIComponent(id)}`, { method: "DELETE" }),
  },
  vault: {
    get: () => request<StoredVault & { updated_at: string }>("/vault"),
    save: (body: Omit<StoredVault, "version"> & { expected_version: number | null }) =>
      request<{ version: number; updated_at: string }>("/vault", { method: "PUT", json: body }),
    remove: (password: string) => request<void>("/vault/delete", { method: "POST", json: { password } }),
  },
  devices: {
    list: () => request<Device[]>("/user/devices"),
    command: (deviceId: string, body: { kind: DeviceCommandKind; folder_id?: string; sha256?: string[] }) =>
      request<DeviceCommand>(`/user/devices/${encodeURIComponent(deviceId)}/commands`, { method: "POST", json: body }),
    rename: (deviceId: string, name: string) =>
      request<Device>(`/user/devices/${encodeURIComponent(deviceId)}`, { method: "PATCH", json: { name } }),
    remove: (deviceId: string) => request<void>(`/user/devices/${encodeURIComponent(deviceId)}`, { method: "DELETE" }),
  },
  auth: {
    session: () => request<SessionStatus>("/auth/session"),
    register: (body: { email: string; password: string; display_name?: string }) =>
      request<SessionInfo>("/auth/register", { method: "POST", json: body }),
    login: (body: { email: string; password: string }) =>
      request<SessionInfo | LoginChallenge>("/auth/login", { method: "POST", json: body }),
    completeTwoFactor: (challenge: string, code: string) =>
      request<SessionInfo>("/auth/login/two-factor", { method: "POST", json: { challenge, code } }),
    requestReset: (email: string) =>
      request<{ status: string }>("/auth/password-reset", { method: "POST", json: { email } }),
    confirmReset: (token: string, newPassword: string) =>
      request<void>("/auth/password-reset/confirm", { method: "POST", json: { token, new_password: newPassword } }),
    verifyEmail: (token: string) => request<void>("/auth/verify-email", { method: "POST", json: { token } }),
    resendVerification: () => request<{ status: string }>("/auth/verify-email/send", { method: "POST" }),
    logout: () => request<void>("/auth/logout", { method: "POST" }),
  },
  scans: {
    url: (url: string) => request<Scan>("/scans/url", { method: "POST", json: { url } }),
    message: (content: string, options: { aiConsent?: boolean; sender?: string } = {}) =>
      request<Scan>("/scans/message", {
        method: "POST",
        json: { content, ai_consent: options.aiConsent ?? false, sender: options.sender?.trim() || undefined },
      }),
    file: (file: File, options: { virustotalConsent?: boolean } = {}) =>
      uploadScan("/scans/file", file, options.virustotalConsent ? { virustotal_consent: "true" } : {}),
    qr: (image: File) => uploadScan("/scans/qr", image),
    apk: (file: File) => uploadScan("/scans/apk", file),
    screenshot: (image: File, options: { aiConsent?: boolean } = {}) =>
      uploadScan("/scans/screenshot", image, options.aiConsent ? { ai_consent: "true" } : {}),
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
      weekly_summary?: boolean;
      breach_monitoring?: boolean;
    }) =>
      request<Profile>("/user/settings", { method: "PATCH", json: body }),
    changePassword: (body: { current_password: string; new_password: string }) =>
      request<void>("/user/password", { method: "POST", json: body }),
    overview: () => request<Overview>("/user/overview"),
    activity: () => request<Activity[]>("/user/activity"),
    exportData: () => request<Record<string, unknown>>("/user/export"),
    security: () => request<SecurityStatus>("/user/security"),
    setupTwoFactor: () =>
      request<{ secret: string; otpauth_uri: string; qr_code: string }>("/user/2fa/setup", { method: "POST" }),
    enableTwoFactor: (code: string) =>
      request<{ backup_codes: string[] }>("/user/2fa/enable", { method: "POST", json: { code } }),
    disableTwoFactor: (password: string, code: string) =>
      request<void>("/user/2fa/disable", { method: "POST", json: { password, code } }),
    apiKeys: () => request<ApiKey[]>("/user/api-keys"),
    createApiKey: (name: string) =>
      request<ApiKey & { key: string }>("/user/api-keys", { method: "POST", json: { name } }),
    revokeApiKey: (id: string) =>
      request<void>(`/user/api-keys/${encodeURIComponent(id)}`, { method: "DELETE" }),
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
  intelligence: {
    lookup: (kind: "domain" | "ip" | "hash" | "phone", value: string) =>
      request<LookupResult>(`/intelligence/${kind}/${encodeURIComponent(value)}`),
    sources: () => request<SourceFreshness[]>("/intelligence/sources"),
  },
  reports: {
    create: (body: {
      category: ReportCategory;
      subject: string;
      description: string;
      evidence?: string;
      anonymous?: boolean;
    }) => request<ReportCreated>("/reports", { method: "POST", json: body }),
    publicList: (category?: ReportCategory) =>
      request<PublicReport[]>("/reports", { query: { category } }),
    mine: () => request<CommunityReport[]>("/reports/mine"),
    get: (id: string, token?: string | null) =>
      request<CommunityReport>(`/reports/${encodeURIComponent(id)}`, { query: { token } }),
  },
  moderation: {
    queue: (status: ReportStatus = "pending", sort: "oldest" | "reputation" = "oldest") =>
      request<ModerationItem[]>("/admin/reports", { query: { status, sort } }),
    review: (id: string, body: { status: "verified" | "rejected" | "duplicate"; note?: string; duplicate_of?: string }) =>
      request<CommunityReport>(`/admin/reports/${encodeURIComponent(id)}/review`, { method: "POST", json: body }),
  },
  adminStats: (days = 30) => request<AdminStats>("/admin/stats", { query: { days } }),
  admin: {
    overview: () => request<AdminOverview>("/admin/overview"),
    users: (query?: string, page = 1) =>
      request<{ items: AdminUser[]; total: number }>("/admin/users", { query: { query, page } }),
    updateUser: (id: string, body: { role?: AdminUser["role"]; disabled?: boolean }) =>
      request<AdminUser>(`/admin/users/${encodeURIComponent(id)}`, { method: "PATCH", json: body }),
    scans: (status?: string) => request<AdminScan[]>("/admin/scans", { query: { status } }),
    audit: (page = 1) =>
      request<{ items: AuditEntry[]; total: number; page: number }>("/admin/audit", { query: { page } }),
    syncFeeds: () => request<{ status: string }>("/admin/feeds/sync", { method: "POST" }),
  },
  system: {
    providers: () => request<ProviderStatus[]>("/system/providers"),
  },
};
