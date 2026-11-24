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
