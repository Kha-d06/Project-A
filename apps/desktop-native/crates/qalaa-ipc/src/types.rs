use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureState {
    Protected,
    Attention,
    AtRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Attention,
    Off,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HomeCheck {
    pub id: String,
    pub status: CheckStatus,
    /// ISO 8601, or `None` when never checked.
    pub checked_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Command {
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HomeAction {
    pub id: String,
    pub priority: u8,
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HomeToggle {
    pub key: String,
    pub on: bool,
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HomeModel {
    pub score: u8,
    pub state: PostureState,
    pub checks: Vec<HomeCheck>,
    pub actions: Vec<HomeAction>,
    pub toggles: Vec<HomeToggle>,
    pub silent_until: Option<String>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol: u32,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanTotals {
    pub scanned: u64,
    pub malicious: u64,
    pub suspicious: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Listener {
    pub key: String,
    pub port: u16,
    pub address: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub exposed: bool,
    pub risk: Option<String>,
    pub fresh: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenerStatus {
    pub listeners: Vec<Listener>,
    pub blocked_ports: Vec<u16>,
    pub can_block: bool,
    pub checked_at: Option<String>,
    /// Present after a block or unblock: what was changed.
    #[serde(default)]
    pub change: Option<String>,
}

/// A program that isn't expected to opened a credential file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialIncident {
    pub id: String,
    pub pid: u32,
    pub program: String,
    pub exe: String,
    /// "ssh_key", "env_file", "cloud_credentials" or "browser_secrets".
    pub credential: String,
    /// Shortened path, "~/.ssh/id_ed25519".
    pub file: String,
    pub at: String,
    /// "open", "suspended" or "terminated".
    pub state: String,
    /// "warning" or "high" (stealer pattern, wallets, keychains, system secrets).
    #[serde(default = "default_severity")]
    pub severity: String,
    /// "browser_key_and_secrets" when one program read a browser's key and its passwords or cookies.
    #[serde(default)]
    pub pattern: Option<String>,
}

fn default_severity() -> String {
    "warning".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub supported: bool,
    pub enabled: bool,
    /// "every_open", "polling" or "unavailable".
    pub mode: String,
    pub incidents: Vec<CredentialIncident>,
    pub trusted: Vec<String>,
}

/// One company in the data-broker opt-out checklist, with this person's progress.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerRow {
    pub id: String,
    pub name: String,
    pub site: String,
    pub opt_out_url: String,
    pub verification: String,
    pub removal_days: u32,
    pub steps: Vec<String>,
    /// "todo", "requested", "removed" or "not_listed".
    pub state: String,
    pub at: Option<String>,
    pub recheck_due: bool,
    pub expected_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerStatus {
    pub catalog_version: String,
    pub reviewed: Option<String>,
    pub note: String,
    pub brokers: Vec<BrokerRow>,
    pub done: u32,
    pub recheck_due: u32,
}

/// A newly started program matched a behaviour rule (Sigma-derived).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BehaviourIncident {
    pub id: String,
    pub rule: String,
    /// English title from the rule; the interface uses its own translation where it has one.
    pub title: String,
    pub description: String,
    pub technique: String,
    /// "low", "medium", "high" or "critical".
    pub level: String,
    pub pid: u32,
    pub program: String,
    pub parent: String,
    /// Shortened, with passwords and tokens masked by the service.
    pub command_line: String,
    pub at: String,
    /// "open", "stopped" or "dismissed".
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BehaviourCapability {
    /// "proc_poll", "ps_poll" or "unavailable".
    pub source: String,
    pub interval_ms: u64,
    pub sees_short_lived: bool,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BehaviourStatus {
    pub enabled: bool,
    pub capability: BehaviourCapability,
    pub rules: u32,
    pub rules_version: String,
    pub incidents: Vec<BehaviourIncident>,
}

/// A file sent to the server's gVisor sandbox, and what it tried to do there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxRun {
    pub id: String,
    pub file: String,
    pub report_url: String,
    /// "queued", "running", "completed" or "failed".
    pub status: String,
    pub risk: Option<String>,
    /// Why there was no sandbox run (no sandbox on the server, a Windows program…).
    pub note: Option<String>,
    pub timed_out: bool,
    pub seconds: Option<f64>,
    pub dns_lookups: Vec<String>,
    pub web_requests: Vec<String>,
    pub direct_connections: Vec<String>,
    pub programs: Vec<String>,
    pub submitted_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxList {
    pub runs: Vec<SandboxRun>,
}

/// One scanned file, as listed (`scan.get`). Mirrors `ScanSummary` in core/scan-service.ts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub path: String,
    pub name: String,
    pub size: u64,
    /// "malicious", "suspicious", "no_known_threat" or "not_scanned".
    pub verdict: String,
    /// The most serious finding's title, or "".
    pub title: String,
    pub findings: u32,
    pub engines: Vec<String>,
    pub scanned_at: String,
    pub error: Option<String>,
    /// The quarantine item id when the file was moved there.
    pub quarantined: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scanned: u32,
    pub found: u32,
    pub current: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanLast {
    pub scanned: u32,
    pub malicious: u32,
    pub suspicious: u32,
    /// "quick" or "custom".
    pub kind: String,
    pub finished_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanEngines {
    pub clamav: bool,
    pub native: bool,
    pub cloud: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStatus {
    pub scanning: bool,
    pub kind: Option<String>,
    pub progress: Option<ScanProgress>,
    pub last: Option<ScanLast>,
    pub results: Vec<ScanSummary>,
    pub watch_folders: Vec<String>,
    pub exclusions: Vec<String>,
    pub engines: ScanEngines,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// "critical", "high", "medium", "low" or "info".
    pub severity: String,
    pub rule: String,
    pub title: String,
    pub detail: String,
    /// For findings inside an archive: the member's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
}

/// One file's full result, for the file inspector (`scan.details`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanDetails {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub verdict: String,
    pub findings: Vec<Finding>,
    pub engines: Vec<String>,
    pub scanned_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub quarantined: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeepFinding {
    pub area: String,
    pub item: String,
    /// "high", "medium" or "low".
    pub severity: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeepCheck {
    pub findings: Vec<DeepFinding>,
    pub checked: Vec<String>,
    pub checked_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub name: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub verdict: String,
    pub reason: String,
    pub quarantined_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineList {
    pub items: Vec<QuarantineItem>,
}
