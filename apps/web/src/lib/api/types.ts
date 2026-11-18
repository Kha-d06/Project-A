/**
 * Response shapes of the SENTINEL API (services/api/app/schemas). Keep in sync
 * with the Pydantic models; the OpenAPI document at /api/v1/openapi.json is the
 * source of truth.
 */

export type ScanType = "url" | "message" | "file" | "qr" | "website" | "apk" | "screenshot";
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
  email_verified_at?: string | null;
  assessment_enabled?: boolean;
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
  settings: { save_scan_history: boolean; sync_extension_events: boolean; weekly_summary?: boolean; breach_monitoring?: boolean };
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
  reporter_reputation: { level: "trusted" | "new" | "unreliable" | "anonymous"; verified: number; rejected: number };
  verification_expires_at?: string | null;
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
  kind: "domain" | "ip" | "hash" | "phone";
  verdict: "listed" | "community_verified" | "not_listed" | "unavailable";
  indicators: IntelIndicator[];
  sources: SourceFreshness[];
  notes: string[];
  country?: string | null;
  reports_awaiting_review?: number | null;
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
  assessment_enabled: boolean;
  assessment_domain_limit: number;
  assessment_monthly_limit: number;
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

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
}

export interface LoginChallenge {
  two_factor_required: true;
  challenge: string;
}

export interface SecurityStatus {
  email_enabled: boolean;
  email_verified: boolean;
  two_factor_enabled: boolean;
  backup_codes_remaining: number;
}

export interface FieldError {
  field: string;
  message: string;
}

// --- Sharing, groups, webhooks, breach check -----------------------------------------

export interface Share {
  id: string;
  scan_id: string;
  group_id: string | null;
  include_target: boolean;
  note: string | null;
  views: number;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  url?: string | null;
}

export interface SharedScan {
  scan_type: ScanType;
  status: ScanStatus;
  risk: RiskLevel | null;
  confidence: Confidence | null;
  summary: string | null;
  target: string | null;
  findings: (Omit<Finding, "evidence"> & { evidence: Record<string, unknown> | null })[];
  checks: Check[];
  recommendations: string[];
  limitations: string[];
  details: Record<string, unknown> | null;
  completed_at: string | null;
  note: string | null;
  shared_at: string;
  expires_at: string | null;
}

export type GroupKind = "family" | "organisation";
export type GroupRole = "owner" | "admin" | "member";

export interface GroupMember {
  user_id: string;
  email: string;
  display_name: string | null;
  role: GroupRole;
  share_activity: boolean;
  joined_at: string;
  warnings_last_30_days: number | null;
}

export interface Group {
  id: string;
  name: string;
  kind: GroupKind;
  created_at: string;
  my_role: GroupRole;
  my_share_activity: boolean;
  my_apply_blocklist?: boolean;
  blocklist?: string[];
  policies?: GroupPolicies;
  members: GroupMember[];
  pending_invites: { email: string; role: GroupRole; expires_at: string }[];
}

export interface GroupPolicies {
  safe_search?: boolean;
  lock_protection?: boolean;
  require_2fa?: boolean;
  require_extension?: boolean;
  max_days_since_scan?: number;
}

export interface MemberCompliance {
  user_id: string;
  email: string;
  display_name: string | null;
  role: GroupRole;
  follows_rules: boolean;
  shared: boolean;
  two_factor: boolean | null;
  extension_linked: boolean | null;
  devices: number | null;
  last_device_scan: string | null;
  device_threats: number | null;
  problems: string[];
}

export interface GroupCompliance {
  group_id: string;
  policies: GroupPolicies;
  members: MemberCompliance[];
  sharing: number;
  compliant: number;
}

export interface SecurityScore {
  score: number;
  grade: "strong" | "good" | "fair" | "weak";
  steps: { key: string; done: boolean; points: number }[];
}

export interface MonitoredIdentity {
  id: string;
  email: string;
  verified: boolean;
  created_at: string;
  last_checked_at: string | null;
  breaches: { name: string; title: string; breach_date: string | null; data_classes: string[] }[];
}

export interface IdentityStatus {
  available: boolean;
  email_available: boolean;
  max_identities: number;
  identities: MonitoredIdentity[];
}

export interface GroupSharedScan {
  share_id: string;
  shared_by: string;
  note: string | null;
  shared_at: string;
  scan: SharedScan;
}

export interface InviteCreated {
  email: string;
  expires_at: string;
  emailed: boolean;
  url: string;
}

export type WebhookEvent = "scan.completed" | "scan.dangerous";

export interface Webhook {
  id: string;
  url: string;
  events: WebhookEvent[];
  active: boolean;
  created_at: string;
  last_delivery_at: string | null;
  last_status: string | null;
  consecutive_failures: number;
  secret?: string;
}

export interface BreachResult {
  email: string;
  breaches: { name: string; title: string; domain: string | null; breach_date: string | null; data_classes: string[]; verified: boolean }[];
  checked_at: string;
}

export interface Trends {
  days: number;
  generated_at: string;
  techniques: Record<string, number>;
  verdicts: Partial<Record<RiskLevel, number>>;
  verified_reports_by_category: Record<string, number>;
  verified_reports_by_country: Record<string, number>;
  minimum_count: number;
}

export interface AdminStats {
  days: number;
  series: { date: string; scans: number; flagged: number; failed: number; signups: number; reports: number }[];
  pending_by_age: { under_1_day: number; "1_to_3_days": number; over_3_days: number };
  reviews_by_moderator: { moderator: string; reviews: number }[];
}

export type DevicePlatform = "windows" | "macos" | "linux" | "android";
export type DeviceCommandKind = "quick_scan" | "full_scan" | "folder_scan" | "quarantine" | "update_signatures";
export type DeviceCommandStatus = "queued" | "sent" | "running" | "done" | "failed" | "expired";

export interface DeviceDetection {
  name: string;
  folder: string | null;
  verdict: "malicious" | "suspicious";
  title: string;
  sha256: string | null;
  quarantined: boolean;
}

export interface DeviceCommand {
  id: string;
  kind: DeviceCommandKind;
  args: { folder_id?: string; folder_label?: string; sha256?: string[] };
  status: DeviceCommandStatus;
  result: {
    ok?: boolean;
    scanned?: number;
    malicious?: number;
    suspicious?: number;
    quarantined?: number;
    detections?: DeviceDetection[];
    duration_seconds?: number;
  } | null;
  error: string | null;
  progress?: { scanned: number; found?: number; total?: number; folder?: string; at?: string } | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface Device {
  id: string;
  name: string;
  platform: DevicePlatform;
  app_version: string;
  online: boolean;
  allow_remote: boolean;
  status: Record<string, string | number | boolean | null>;
  folders: { id: string; label: string }[];
  last_seen_at: string | null;
  created_at: string;
  recent_commands: DeviceCommand[];
}

export interface VpnDevice {
  id: string;
  name: string;
  address: string;
  created_at: string;
  last_handshake_at: string | null;
  connected: boolean;
  received_bytes: number;
  sent_bytes: number;
  month_bytes: number;
  monthly_limit_bytes: number | null;
  paused: boolean;
  state: "active" | "paused" | "limit_reached";
}

export interface VpnStatus {
  enabled: boolean;
  server_online: boolean;
  max_devices: number;
  devices: VpnDevice[];
}

export interface VpnPeerConfig {
  peer: VpnDevice;
  address: string;
  dns: string;
  server_public_key: string;
  endpoint: string;
  allowed_ips: string;
}

export interface AssessedDomain {
  id: string;
  domain: string;
  verified: boolean;
  verified_method: "dns" | "file" | null;
  verified_at: string | null;
  created_at: string;
  schedule: AssessmentSchedule;
  next_run_at: string | null;
}

export type AssessmentSchedule = "off" | "weekly" | "monthly";

export interface VerificationInstructions {
  domain: AssessedDomain;
  token: string;
  dns_name: string;
  dns_type: string;
  dns_value: string;
  file_url: string;
  file_content: string;
}

export type AssessmentResult = "critical" | "high" | "medium" | "low" | "no_issues" | "inconclusive";

export interface AssessmentFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  explanation: string;
  recommendation: string;
  evidence: Record<string, unknown>;
}

export interface AssessmentCheck {
  key: string;
  label: string;
  status: string;
  detail: string;
}

export interface AssessmentSummary {
  id: string;
  domain: string;
  status: "queued" | "running" | "completed" | "failed";
  result: AssessmentResult | null;
  summary: string | null;
  finding_count: number;
  pages_checked: number;
  active_probes: boolean;
  scheduled: boolean;
  created_at: string;
  finished_at: string | null;
}

export interface AssessmentDetail extends AssessmentSummary {
  findings: AssessmentFinding[];
  checks: AssessmentCheck[];
  error: string | null;
}

export interface AssessmentStatus {
  enabled: boolean;
  domain_limit: number;
  monthly_limit: number;
  used_this_month: number;
  domains: AssessedDomain[];
  recent: AssessmentSummary[];
}
