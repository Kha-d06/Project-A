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

/// Real-time protection (`protection.get`). Mirrors core/protection-service.ts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RealtimeStatus {
    pub on: bool,
    pub folders: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RansomwareAlert {
    pub reasons: Vec<String>,
    pub examples: Vec<String>,
    pub at: String,
}

/// A process frozen for ransomware behaviour, waiting for the person to decide.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HaltedProcess {
    pub pid: u32,
    pub reason: String,
    pub files: u32,
    pub at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RansomwareStatus {
    pub on: bool,
    pub decoys: bool,
    pub decoy_count: u32,
    pub folders: Vec<String>,
    pub last_alert: Option<RansomwareAlert>,
    pub halted: Vec<HaltedProcess>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnAccessStatus {
    pub supported: bool,
    pub on: bool,
    /// "active", "inactive", "failed" or "absent" (the root helper's service).
    pub state: String,
    /// pkexec and systemd are there to install it.
    pub manageable: bool,
    /// This service is answering the helper.
    pub responder: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CfaStatus {
    pub supported: bool,
    /// "on", "off", "audit" or "unknown".
    pub state: String,
    pub folders: Vec<String>,
    pub allowed_apps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShellHook {
    pub shell: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalStatus {
    pub supported: bool,
    pub command: Option<String>,
    pub shells: Vec<ShellHook>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionStatus {
    pub platform: String,
    pub realtime: RealtimeStatus,
    pub ransomware: RansomwareStatus,
    pub on_access: OnAccessStatus,
    pub cfa: Option<CfaStatus>,
    pub terminal: TerminalStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WifiStatus {
    pub ssid: Option<String>,
    pub security: Option<String>,
    /// "open", "weak", "ok", "none" or "unknown".
    pub risk: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingUpdate {
    pub name: String,
    pub current: Option<String>,
    pub available: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdatesStatus {
    pub count: u32,
    pub source: String,
    pub items: Vec<PendingUpdate>,
}

/// The slower checks (`protection.system`): `None` means the check couldn't run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemChecks {
    pub wifi: Option<WifiStatus>,
    pub updates: Option<UpdatesStatus>,
    pub checked_at: String,
}

/// A service found listening on a device. Mirrors engine/network/types.ts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetService {
    pub port: u16,
    pub name: String,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetDevice {
    /// Inventory key, for marking the device as known.
    pub key: String,
    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    /// "router", "self" or "device".
    pub role: String,
    pub services: Vec<NetService>,
    pub trusted: bool,
    pub first_seen: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetFinding {
    /// "critical", "high", "medium", "low" or "info".
    pub severity: String,
    pub rule: String,
    pub title: String,
    pub detail: String,
    /// The device (IP) it's about, or `None` for the whole network.
    pub device: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortForward {
    pub external: u16,
    pub internal: String,
    pub protocol: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsServer {
    pub address: String,
    pub known: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterInfo {
    pub ip: Option<String>,
    pub admin_http: bool,
    pub hint: Option<String>,
    pub port_forwards: Vec<PortForward>,
    pub upnp: bool,
    pub dns: Vec<DnsServer>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetWifi {
    pub ssid: Option<String>,
    pub risk: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkScan {
    pub started_at: String,
    pub finished_at: String,
    pub cidr: Option<String>,
    pub gateway: Option<String>,
    pub interface: Option<String>,
    pub wifi: Option<NetWifi>,
    pub devices: Vec<NetDevice>,
    pub router: Option<RouterInfo>,
    pub findings: Vec<NetFinding>,
    /// Which steps could run: "ok", "unsupported" or "unavailable" per step.
    pub capabilities: std::collections::BTreeMap<String, String>,
    pub new_devices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoneDevice {
    pub key: String,
    pub ip: String,
    pub name: Option<String>,
}

/// What changed since the previous scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkChanges {
    pub compared_with: Option<String>,
    pub new_devices: Vec<String>,
    pub gone: Vec<GoneDevice>,
    pub new_risks: Vec<NetFinding>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkWatch {
    pub on: bool,
    pub every_hours: u32,
    pub next_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkProgress {
    pub done: u32,
    pub total: u32,
    pub phase: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub scanning: bool,
    pub progress: Option<NetworkProgress>,
    pub scan: Option<NetworkScan>,
    pub changes: Option<NetworkChanges>,
    pub watch: NetworkWatch,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialCheck {
    pub device: String,
    /// "http", "telnet" or "ftp" (with the port, as the service reports it).
    pub service: String,
    /// A factory default login was accepted.
    pub default_accepted: bool,
    pub user: Option<String>,
    pub tried: u32,
    pub stopped: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialChecks {
    pub ip: String,
    pub results: Vec<CredentialCheck>,
}

/// The WireGuard VPN (`vpn.get`). Mirrors core/vpn-service.ts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnStatus {
    pub platform: String,
    /// Linked to a Qalaa account (needed to set up a tunnel).
    pub linked: bool,
    /// A tunnel file is saved on this computer.
    pub saved: bool,
    /// "connected", "disconnected", "not_imported" or "unsupported".
    pub state: String,
    /// The kill switch and auto-connect can run here (Linux).
    pub guard_capable: bool,
    pub kill_switch: bool,
    pub allow_lan: bool,
    /// "full", "exclude" or "only".
    pub split_mode: String,
    pub split_cidrs: Vec<String>,
    pub auto_connect: bool,
    pub trusted: Vec<String>,
    pub auto_connected_on: Option<String>,
}

/// One posture check (`posture.get`). Mirrors engine/posture.ts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureCheck {
    pub id: String,
    pub title: String,
    /// "pass", "fail", "warn" or "unknown" (couldn't run; not counted in the score).
    pub status: String,
    pub detail: Option<String>,
    pub fix: Option<String>,
    /// Whole numbers in every engine check.
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureReport {
    /// `None` when no check could run.
    pub score: Option<u32>,
    pub checks: Vec<PostureCheck>,
    pub checked_at: String,
}

/// Firewall or disk encryption: "on", "off", "partial" or "unknown".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateDetail {
    pub state: String,
    pub detail: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupEntry {
    pub id: String,
    pub name: String,
    pub command: String,
    pub location: String,
    pub program: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub warnings: Vec<String>,
    pub is_new: bool,
    pub can_switch_off: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisabledStartup {
    pub id: String,
    pub name: String,
    pub command: String,
    pub location: String,
    pub method: String,
    pub data: std::collections::BTreeMap<String, String>,
    pub at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileState {
    pub path: String,
    /// `None`: the file doesn't exist or can't be read.
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub mtime: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntegrityChange {
    pub path: String,
    /// "modified", "deleted" or "created".
    pub kind: String,
    pub before: FileState,
    pub after: FileState,
    pub at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityState {
    pub paths: Vec<String>,
    pub baseline: std::collections::BTreeMap<String, FileState>,
    pub changes: Vec<IntegrityChange>,
    pub last_check: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsbSummary {
    pub new_keyboards: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureStatus {
    pub posture: Option<PostureReport>,
    pub firewall: Option<StateDetail>,
    pub encryption: Option<StateDetail>,
    pub startup: Vec<StartupEntry>,
    pub disabled_startup: Vec<DisabledStartup>,
    pub startup_baseline_set: bool,
    pub integrity: IntegrityState,
    pub usb: UsbSummary,
    pub checking: bool,
}
