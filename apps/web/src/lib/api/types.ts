/**
 * Response shapes of the SENTINEL API (services/api/app/schemas). Keep in sync
 * with the Pydantic models; the OpenAPI document at /api/v1/openapi.json is the
 * source of truth.
 */

export type ScanType = "url" | "message" | "file" | "qr" | "website" | "apk";
export type ScanStatus = "queued" | "processing" | "completed" | "failed" | "inconclusive";
export type RiskLevel = "known_malicious" | "suspicious" | "no_known_threat" | "inconclusive";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type CheckStatus = "completed" | "unavailable" | "failed" | "skipped";
export type Confidence = "high" | "medium" | "low";

export interface User {
  id: string;
  email: string;
  display_name: string | null;
  role: string;
  created_at: string;
}

export interface SessionInfo {
  user: User;
  csrf_token: string;
}

/** GET /auth/session: both fields are null when signed out. */
export interface SessionStatus {
  user: User | null;
  csrf_token: string | null;
}

export interface Profile {
  user: User;
  settings: { save_scan_history: boolean; sync_extension_events: boolean };
}

export interface Finding {
  severity: Severity;
  category: string;
  title: string;
  explanation: string;
  evidence: Record<string, unknown>;
  source: string;
}

export interface Check {
  key: string;
  label: string;
  provider: string;
  status: CheckStatus;
  detail: string;
  core: boolean;
  finished_at: string;
}

export interface ScanSummary {
  id: string;
  scan_type: ScanType;
  status: ScanStatus;
  target: string;
  risk: RiskLevel | null;
  created_at: string;
  completed_at: string | null;
}

export interface Scan extends ScanSummary {
  confidence: Confidence | null;
  summary: string | null;
  findings: Finding[];
  checks: Check[];
  details: Record<string, unknown>;
  recommendations: string[];
  limitations: string[];
  error: string | null;
  started_at: string | null;
  saved_to_history: boolean;
  ai_explanation: string | null;
  ai_model: string | null;
  ai_generated_at: string | null;
}

export interface Explanation {
  explanation: string;
  model: string;
  generated_at: string;
  label: string;
}

export interface ScanPage {
  items: ScanSummary[];
  total: number;
  page: number;
  page_size: number;
}

export interface Overview {
  total_scans: number;
  by_risk: Partial<Record<RiskLevel, number>>;
  by_type: Partial<Record<ScanType, number>>;
  recent_scans: ScanSummary[];
  recent_threats: ScanSummary[];
  daily_activity: { date: string; total: number; flagged: number }[];
}

export interface Activity {
  action: string;
  created_at: string;
}

export interface ProviderStatus {
  key: string;
  name: string;
  purpose: string;
  status: "active" | "not_configured" | "degraded" | "awaiting_first_sync";
  detail: string;
  shares_data: string;
}

export interface Installation {
  id: string;
  browser: string;
  version: string;
  created_at: string;
  last_seen_at: string;
}

export interface ExtensionEvent {
  kind: "warning_shown" | "went_back" | "proceeded" | "download_warning" | "link_checked";
  host: string;
  verdict: "dangerous" | "suspicious" | "caution" | "no_known_threat" | "unavailable";
  created_at: string;
}

export type ReportCategory =
  | "website"
  | "scam_message"
  | "job_offer"
  | "fraudulent_app"
  | "phone_number"
  | "social_account";
export type ReportStatus = "pending" | "verified" | "rejected" | "duplicate";

export interface CommunityReport {
  id: string;
  category: ReportCategory;
  subject: string;
  description: string;
  evidence: string | null;
  status: ReportStatus;
  moderator_note: string | null;
  created_at: string;
  reviewed_at: string | null;
}

export interface ReportCreated {
  report: CommunityReport;
  tracking_token: string | null;
  similar_reports: number;
}

export interface PublicReport {
  category: ReportCategory;
  subject: string;
  reports: number;
  verified_at: string;
}

export interface ModerationItem extends CommunityReport {
  similar_reports: number;
  anonymous: boolean;
}

export interface IntelIndicator {
  source: string;
  kind: string;
  value: string;
  threat: string | null;
  tags: string | null;
  first_seen: string | null;
  last_seen: string;
  reference: string | null;
}

export interface SourceFreshness {
  name: string;
  indicators: number;
  last_updated: string | null;
  fresh: boolean;
}

export interface LookupResult {
  query: string;
  kind: "domain" | "ip" | "hash";
  verdict: "listed" | "community_verified" | "not_listed" | "unavailable";
  indicators: IntelIndicator[];
  sources: SourceFreshness[];
  notes: string[];
}

export interface AdminOverview {
  users_total: number;
  users_new_7d: number;
  scans_24h: Partial<Record<ScanStatus, number>>;
  failed_24h: number;
  stuck: number;
  reports_pending: number;
  workers: { reachable: boolean; workers: string[]; queued_tasks: number | null; detail: string };
  feeds: {
    name: string;
    indicators: number;
    last_success_at: string | null;
    last_attempt_at: string | null;
    last_error: string | null;
    fresh: boolean;
  }[];
  rate_limit_rejections_24h: Record<string, number>;
}

export interface AdminUser {
  id: string;
  email: string;
  display_name: string | null;
  role: "user" | "moderator" | "admin";
  created_at: string;
  disabled: boolean;
  scans: number;
}

export interface AdminScan {
  id: string;
  scan_type: ScanType;
  status: ScanStatus;
  error: string | null;
  created_at: string;
  completed_at: string | null;
  duration_seconds: number | null;
}

export interface AuditEntry {
  action: string;
  detail: string | null;
  user_email: string | null;
  ip_address: string | null;
  created_at: string;
}

export interface FieldError {
  field: string;
  message: string;
}
