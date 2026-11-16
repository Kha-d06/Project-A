/**
 * Response shapes of the SENTINEL API (services/api/app/schemas). Keep in sync
 * with the Pydantic models; the OpenAPI document at /api/v1/openapi.json is the
 * source of truth.
 */

export type ScanType = "url" | "message" | "file";
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
  settings: { save_scan_history: boolean };
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

export interface FieldError {
  field: string;
  message: string;
}
