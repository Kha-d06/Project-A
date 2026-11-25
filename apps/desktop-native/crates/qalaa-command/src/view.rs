//! Turns the service's Home model into rows for the interface. Plain Rust with
//! no window, so it is tested directly.

use qalaa_ipc::{
    BehaviourStatus, BrokerStatus, CheckStatus, CredentialChecks, CredentialStatus, DeepCheck, HomeModel, ListenerStatus, NetworkStatus,
    PostureState, ProtectionStatus, QuarantineItem, SandboxRun, ScanDetails, ScanStatus, SystemChecks, VpnStatus,
};

use crate::strings::{t, Lang};

#[derive(Debug, Clone, PartialEq)]
pub struct CheckView {
    pub id: String,
    pub label: String,
    pub status: &'static str,
    pub status_text: String,
    pub freshness: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionView {
    pub id: String,
    pub title: String,
    pub detail: String,
    /// The button's words: the action's own answer where it has one.
    pub button: String,
    pub priority: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToggleView {
    pub key: String,
    pub label: String,
    pub hint: String,
    pub on: bool,
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HomeView {
    pub state: &'static str,
    pub state_text: String,
    pub score: u8,
    pub checks: Vec<CheckView>,
    pub actions: Vec<ActionView>,
    pub toggles: Vec<ToggleView>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PaletteEntry {
    pub id: String,
    pub title: String,
}

/// Seconds since 1970 for an ISO 8601 UTC time like `2026-11-24T12:00:00.000Z`.
pub fn parse_iso(iso: &str) -> Option<i64> {
    let b = iso.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b' ') {
        return None;
    }
    let num = |s: &str| s.parse::<i64>().ok();
    let (y, m, d) = (num(&iso[0..4])?, num(&iso[5..7])?, num(&iso[8..10])?);
    let (hh, mm, ss) = (num(&iso[11..13])?, num(&iso[14..16])?, num(&iso[17..19])?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// "3 hours ago", in either language. Future times read as "just now".
pub fn relative(iso: Option<&str>, now: i64, lang: Lang) -> String {
    let Some(then) = iso.and_then(parse_iso) else {
        return t(lang, "fresh.never").to_owned();
    };
    let secs = (now - then).max(0);
    let (n, unit_en, unit_ar) = match secs {
        s if s < 60 => return t(lang, "fresh.just_now").to_owned(),
        s if s < 3600 => (s / 60, "minute", "دقيقة"),
        s if s < 86_400 => (s / 3600, "hour", "ساعة"),
        s => (s / 86_400, "day", "يوم"),
    };
    match lang {
        Lang::En => format!("{n} {unit_en}{} ago", if n == 1 { "" } else { "s" }),
        Lang::Ar => format!("منذ {n} {unit_ar}"),
    }
}

fn status_key(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Ok => "ok",
        CheckStatus::Attention => "attention",
        CheckStatus::Off => "off",
        CheckStatus::Unknown => "unknown",
    }
}

pub fn state_key(state: PostureState) -> &'static str {
    match state {
        PostureState::Protected => "protected",
        PostureState::Attention => "attention",
        PostureState::AtRisk => "at_risk",
    }
}

pub fn home_view(model: &HomeModel, now: i64, lang: Lang) -> HomeView {
    let state = state_key(model.state);
    HomeView {
        state,
        state_text: t(lang, &format!("state.{state}")).to_owned(),
        score: model.score.min(100),
        checks: model
            .checks
            .iter()
            .map(|check| {
                let status = status_key(check.status);
                CheckView {
                    id: check.id.clone(),
                    label: t(lang, &format!("check.{}", check.id)).to_owned(),
                    status,
                    status_text: t(lang, &format!("status.{status}")).to_owned(),
                    freshness: relative(check.checked_at.as_deref(), now, lang),
                }
            })
            .collect(),
        actions: model
            .actions
            .iter()
            .map(|action| ActionView {
                id: action.id.clone(),
                title: t(lang, &format!("action.{}", action.id)).to_owned(),
                detail: t(lang, &format!("action.{}.detail", action.id)).to_owned(),
                button: match t(lang, &format!("action.{}.button", action.id)) {
                    "?" => t(lang, "action.go").to_owned(),
                    own => own.to_owned(),
                },
                priority: action.priority,
            })
            .collect(),
        toggles: model
            .toggles
            .iter()
            .map(|toggle| ToggleView {
                key: toggle.key.clone(),
                label: t(lang, &format!("toggle.{}", toggle.key)).to_owned(),
                hint: if toggle.available {
                    String::new()
                } else {
                    t(lang, "toggle.unavailable").to_owned()
                },
                on: toggle.on,
                available: toggle.available,
            })
            .collect(),
    }
}

/// Everything the command palette can do right now.
pub fn palette_entries(view: Option<&HomeView>, lang: Lang) -> Vec<PaletteEntry> {
    let mut entries = vec![
        PaletteEntry {
            id: "scan.quick".into(),
            title: t(lang, "palette.quick_scan").into(),
        },
        PaletteEntry {
            id: "signatures.update".into(),
            title: t(lang, "palette.update_signatures").into(),
        },
        PaletteEntry {
            id: "safepay".into(),
            title: t(lang, "safepay.open").into(),
        },
        PaletteEntry {
            id: "alias.new".into(),
            title: t(lang, "alias.new").into(),
        },
        PaletteEntry {
            id: "page.home".into(),
            title: t(lang, "palette.home").into(),
        },
        PaletteEntry {
            id: "page.scan".into(),
            title: t(lang, "nav.scan").into(),
        },
        PaletteEntry {
            id: "page.quarantine".into(),
            title: t(lang, "nav.quarantine").into(),
        },
        PaletteEntry {
            id: "page.protection".into(),
            title: t(lang, "nav.protection").into(),
        },
        PaletteEntry {
            id: "page.network".into(),
            title: t(lang, "nav.network").into(),
        },
        PaletteEntry {
            id: "page.vpn".into(),
            title: t(lang, "nav.vpn").into(),
        },
        PaletteEntry {
            id: "page.ports".into(),
            title: t(lang, "nav.ports").into(),
        },
        PaletteEntry {
            id: "page.credentials".into(),
            title: t(lang, "nav.credentials").into(),
        },
        PaletteEntry {
            id: "page.brokers".into(),
            title: t(lang, "nav.brokers").into(),
        },
        PaletteEntry {
            id: "page.about".into(),
            title: t(lang, "palette.about").into(),
        },
    ];
    if let Some(view) = view {
        for toggle in view.toggles.iter().filter(|t| t.available) {
            entries.push(PaletteEntry {
                id: format!("toggle.{}", toggle.key),
                title: format!("{}: {}", t(lang, "palette.toggle"), toggle.label),
            });
        }
    }
    entries
}

/// Case-insensitive match on every word typed, in any order.
pub fn filter_palette(entries: &[PaletteEntry], query: &str) -> Vec<PaletteEntry> {
    let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    entries
        .iter()
        .filter(|e| words.iter().all(|w| e.title.to_lowercase().contains(w)))
        .cloned()
        .collect()
}

/// "An API token is on the clipboard: clearing in 23 s".
pub fn clipboard_text(kind: &str, remaining_ms: u64, lang: Lang) -> String {
    let what = match t(lang, &format!("clip.kind.{kind}")) {
        "?" => t(lang, "clip.kind.high_entropy"),
        known => known,
    };
    let secs = remaining_ms.div_ceil(1000);
    match lang {
        Lang::En => format!("{what} is on the clipboard: clearing in {secs} s"),
        Lang::Ar => format!("{what} في الحافظة: تُمسح خلال {secs} ث"),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PortView {
    pub key: String,
    pub port: u16,
    pub title: String,
    pub detail: String,
    pub fresh: bool,
    pub blocked: bool,
    pub exposed: bool,
}

/// New listeners first, then those reachable from other machines, then by port.
pub fn ports_view(status: &ListenerStatus, lang: Lang) -> Vec<PortView> {
    let mut rows: Vec<PortView> = status
        .listeners
        .iter()
        .map(|l| {
            let program = l.process.clone().unwrap_or_else(|| t(lang, "ports.unknown_program").to_owned());
            let reach = t(lang, if l.exposed { "ports.reachable" } else { "ports.local" });
            PortView {
                key: l.key.clone(),
                port: l.port,
                title: match lang {
                    Lang::En => format!("{program} on port {}", l.port),
                    Lang::Ar => format!("{program} على المنفذ {}", l.port),
                },
                detail: l.risk.as_ref().map_or_else(|| reach.to_owned(), |risk| format!("{reach}. {risk}")),
                fresh: l.fresh,
                blocked: status.blocked_ports.contains(&l.port),
                exposed: l.exposed,
            }
        })
        .collect();
    rows.sort_by_key(|r| (!r.fresh, !r.exposed, r.port));
    rows.dedup_by(|a, b| a.key == b.key);
    rows
}

/// "k7x2…@relay.example.org copied. Mail to it reaches your inbox; …"
pub fn alias_notice(address: &str, copied: bool, lang: Lang) -> String {
    format!("{address} {}", t(lang, if copied { "alias.copied" } else { "alias.made" }))
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrokerView {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub state: String,
    pub url: String,
    pub recheck: bool,
}

/// Re-checks first, then not started, then the rest, each in catalog order; plus "3 of 13 done".
pub fn brokers_view(status: &BrokerStatus, lang: Lang) -> (Vec<BrokerView>, String) {
    let mut rows: Vec<(u8, BrokerView)> = status
        .brokers
        .iter()
        .map(|b| {
            let state = t(lang, &format!("brokers.state.{}", b.state));
            let mut detail = vec![b.site.clone(), state.to_owned()];
            if b.recheck_due {
                detail.push(t(lang, "brokers.recheck").to_owned());
            } else if let Some(by) = b.expected_by.as_deref().and_then(|d| d.get(..10)) {
                detail.push(format!("{} {by}", t(lang, "brokers.expected")));
            } else if b.state == "todo" {
                detail.push(format!("{} {}", b.removal_days, t(lang, "brokers.days")));
            }
            let order = if b.recheck_due {
                0
            } else if b.state == "todo" {
                1
            } else {
                2
            };
            let view = BrokerView {
                id: b.id.clone(),
                title: b.name.clone(),
                detail: detail.join(" · "),
                state: b.state.clone(),
                url: b.opt_out_url.clone(),
                recheck: b.recheck_due,
            };
            (order, view)
        })
        .collect();
    rows.sort_by_key(|(order, _)| *order);
    let summary = format!("{} / {} {}", status.done, status.brokers.len(), t(lang, "brokers.progress"));
    (rows.into_iter().map(|(_, v)| v).collect(), summary)
}

/// Only an https page is handed to the system browser.
pub fn safe_to_open(url: &str) -> bool {
    url.starts_with("https://") && !url.contains(char::is_whitespace) && url.len() < 2048
}

/// Pages that show what programs read your secrets are hidden from screenshots
/// and screen sharing (Windows and macOS; Linux has no way to ask).
pub fn content_protected(page: &str) -> bool {
    matches!(page, "credentials")
}

#[derive(Debug, Clone, PartialEq)]
pub struct CredentialView {
    pub id: String,
    pub title: String,
    pub detail: String,
    /// "open", "suspended" or "terminated".
    pub state: String,
}

/// Rows for the Credentials page, newest first (as the service sends them), and
/// the sentence saying how complete the watching is.
pub fn credentials_view(status: &CredentialStatus, now: i64, lang: Lang) -> (Vec<CredentialView>, String) {
    let rows = status
        .incidents
        .iter()
        .map(|i| {
            let kind = match t(lang, &format!("cred.kind.{}", i.credential)) {
                "?" => i.credential.as_str(),
                known => known,
            };
            let mut state = match i.state.as_str() {
                "suspended" | "terminated" => format!("  · {}", t(lang, &format!("cred.state.{}", i.state))),
                _ => String::new(),
            };
            if i.severity == "high" {
                state.push_str(&format!("  · {}", t(lang, "cred.high")));
            }
            let pattern = i
                .pattern
                .as_deref()
                .map(|p| match t(lang, &format!("cred.pattern.{p}")) {
                    "?" => String::new(),
                    text => format!(" · {text}"),
                })
                .unwrap_or_default();
            CredentialView {
                id: i.id.clone(),
                title: match lang {
                    Lang::En => format!("{} opened {}{state}", i.program, i.file),
                    Lang::Ar => format!("فتح {} الملف {}{state}", i.program, i.file),
                },
                detail: format!("{kind}{pattern} · {} · {}", relative(Some(&i.at), now, lang), i.exe),
                state: i.state.clone(),
            }
        })
        .collect();
    let mode = match status.mode.as_str() {
        "every_open" | "polling" => status.mode.as_str(),
        _ => "unavailable",
    };
    (rows, t(lang, &format!("cred.mode.{mode}")).to_owned())
}

#[derive(Debug, Clone, PartialEq)]
pub struct BehaviourView {
    pub id: String,
    pub title: String,
    pub detail: String,
    /// "open", "stopped" or "dismissed".
    pub state: String,
}

/// Rows for the Behaviour page and the sentence saying how complete the watching is.
pub fn behaviour_view(status: &BehaviourStatus, now: i64, lang: Lang) -> (Vec<BehaviourView>, String) {
    let rows = status
        .incidents
        .iter()
        .map(|i| {
            let rule = match t(lang, &format!("beh.rule.{}", i.rule)) {
                "?" => i.title.as_str(),
                known => known,
            };
            let mut tags = String::new();
            if matches!(i.level.as_str(), "high" | "critical") {
                tags.push_str(&format!("  · {}", t(lang, &format!("beh.level.{}", i.level))));
            }
            if matches!(i.state.as_str(), "stopped" | "dismissed") {
                tags.push_str(&format!("  · {}", t(lang, &format!("beh.state.{}", i.state))));
            }
            let parent = if i.parent.is_empty() {
                String::new()
            } else {
                format!(" ({} {})", t(lang, "beh.started_by"), i.parent)
            };
            BehaviourView {
                id: i.id.clone(),
                title: format!("{rule}: {}{tags}", i.program),
                detail: format!(
                    "{}{parent} · {} · {} · {}",
                    i.command_line,
                    i.technique,
                    relative(Some(&i.at), now, lang),
                    i.pid
                ),
                state: i.state.clone(),
            }
        })
        .collect();
    let source = match status.capability.source.as_str() {
        "proc_connector" | "proc_poll" | "ps_poll" => status.capability.source.as_str(),
        _ => "unavailable",
    };
    (rows, t(lang, &format!("beh.source.{source}")).to_owned())
}

/// Linux without the root helper: offer to install it, so every start is seen.
pub fn behaviour_can_install_helper(status: &BehaviourStatus) -> bool {
    status.capability.source == "proc_poll"
}

#[derive(Debug, Clone, PartialEq)]
pub struct SandboxView {
    pub title: String,
    pub detail: String,
    pub url: String,
}

/// Rows for sandbox runs: file and status, then what it tried to reach, or why there was no run.
pub fn sandbox_view(runs: &[SandboxRun], lang: Lang) -> Vec<SandboxView> {
    runs.iter()
        .map(|r| {
            let status = match t(lang, &format!("sbx.status.{}", r.status)) {
                "?" => r.status.as_str(),
                s => s,
            };
            let mut parts: Vec<String> = Vec::new();
            if let Some(note) = &r.note {
                parts.push(note.clone());
            } else if r.status == "completed" {
                if r.timed_out {
                    parts.push(t(lang, "sbx.stopped").to_owned());
                } else if let Some(s) = r.seconds {
                    parts.push(format!("{} {s} s", t(lang, "sbx.ran")));
                }
                for (key, items) in [
                    ("sbx.lookups", &r.dns_lookups),
                    ("sbx.requests", &r.web_requests),
                    ("sbx.direct", &r.direct_connections),
                    ("sbx.programs", &r.programs),
                ] {
                    if !items.is_empty() {
                        parts.push(format!("{}: {}", t(lang, key), items.join(", ")));
                    }
                }
                if r.dns_lookups.is_empty() && r.web_requests.is_empty() && r.direct_connections.is_empty() && r.programs.is_empty() {
                    parts.push(t(lang, "sbx.quiet").to_owned());
                }
            }
            SandboxView {
                title: format!("{}  · {status}", r.file),
                detail: parts.join(" · "),
                url: r.report_url.clone(),
            }
        })
        .collect()
}

/// "1.2 MB", for file sizes.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A verdict in words. Never "safe": a clean result is "no known threat".
pub fn verdict_text(verdict: &str, lang: Lang) -> String {
    match t(lang, &format!("verdict.{verdict}")) {
        "?" => verdict.to_owned(),
        s => s.to_owned(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanRowView {
    pub path: String,
    pub title: String,
    pub detail: String,
    /// "malicious", "suspicious", "no_known_threat" or "not_scanned".
    pub verdict: String,
    pub can_quarantine: bool,
    pub quarantined: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanPageView {
    pub rows: Vec<ScanRowView>,
    /// The running scan's progress, or the last scan's totals.
    pub summary: String,
    pub engines: String,
    pub watched: String,
    pub exclusions: Vec<String>,
    pub scanning: bool,
}

pub fn scan_view(status: &ScanStatus, now: i64, lang: Lang) -> ScanPageView {
    let rows = status
        .results
        .iter()
        .map(|r| {
            let serious = r.verdict == "malicious" || r.verdict == "suspicious";
            let mut parts = vec![verdict_text(&r.verdict, lang), bytes(r.size)];
            if !r.title.is_empty() {
                parts.push(r.title.clone());
            }
            if let Some(error) = &r.error {
                parts.push(error.clone());
            }
            if r.quarantined.is_some() {
                parts.push(t(lang, "scan.quarantined").to_owned());
            }
            parts.push(relative(Some(&r.scanned_at), now, lang));
            ScanRowView {
                path: r.path.clone(),
                title: r.name.clone(),
                detail: parts.join(" · "),
                verdict: r.verdict.clone(),
                can_quarantine: serious && r.quarantined.is_none(),
                quarantined: r.quarantined.is_some(),
            }
        })
        .collect();
    let summary = if let Some(p) = &status.progress {
        progress_text(p.scanned, p.found, lang)
    } else if let Some(last) = &status.last {
        t(lang, "scan.last")
            .replace("{scanned}", &last.scanned.to_string())
            .replace("{found}", &(last.malicious + last.suspicious).to_string())
            .replace("{when}", &relative(Some(&last.finished_at), now, lang))
    } else {
        t(lang, "scan.none").to_owned()
    };
    let mut engines = vec![t(lang, "engine.signatures")];
    if status.engines.native {
        engines.push(t(lang, "engine.native"));
    }
    if status.engines.clamav {
        engines.push(t(lang, "engine.clamav"));
    }
    if status.engines.cloud {
        engines.push(t(lang, "engine.cloud"));
    }
    let mut engines_text = format!("{} {}", t(lang, "scan.engines"), engines.join(", "));
    if !status.engines.native {
        engines_text.push_str(" · ");
        engines_text.push_str(t(lang, "engine.native_missing"));
    }
    ScanPageView {
        rows,
        summary,
        engines: engines_text,
        watched: format!("{} {}", t(lang, "scan.watched"), status.watch_folders.join(", ")),
        exclusions: status.exclusions.clone(),
        scanning: status.scanning,
    }
}

/// "Scanning… 120 files checked, 1 found".
pub fn progress_text(scanned: u32, found: u32, lang: Lang) -> String {
    t(lang, "scan.running")
        .replace("{scanned}", &scanned.to_string())
        .replace("{found}", &found.to_string())
}

/// The file inspector's text: every finding, the engines, the fingerprint.
pub fn inspector_text(d: &ScanDetails, now: i64, lang: Lang) -> String {
    let mut lines = vec![
        format!("{} · {} · {}", d.name, verdict_text(&d.verdict, lang), bytes(d.size)),
        d.path.clone(),
    ];
    if d.findings.is_empty() {
        lines.push(t(lang, "scan.no_findings").to_owned());
    }
    for f in &d.findings {
        let severity = match t(lang, &format!("sev.{}", f.severity)) {
            "?" => f.severity.clone(),
            s => s.to_owned(),
        };
        let member = f.member.as_ref().map(|m| format!(" ({m})")).unwrap_or_default();
        let detail = if f.detail.is_empty() {
            String::new()
        } else {
            format!(": {}", f.detail)
        };
        lines.push(format!("• [{severity}] {}{member}{detail}", f.title));
    }
    lines.push(format!("{} {}", t(lang, "scan.engines"), d.engines.join(", ")));
    if let Some(sha) = &d.sha256 {
        lines.push(format!("SHA-256 {sha}"));
    }
    if let Some(error) = &d.error {
        lines.push(error.clone());
    }
    lines.push(format!("{} {}", t(lang, "scan.scanned"), relative(Some(&d.scanned_at), now, lang)));
    lines.join("\n")
}

/// The deep check's findings as (title, detail), or one line saying nothing unusual was found.
pub fn deep_view(deep: &DeepCheck, lang: Lang) -> Vec<(String, String)> {
    if deep.findings.is_empty() {
        return vec![(
            t(lang, "scan.deep_none").to_owned(),
            format!("{} {}", t(lang, "scan.deep_checked"), deep.checked.join(", ")),
        )];
    }
    deep.findings
        .iter()
        .map(|f| {
            let severity = match t(lang, &format!("sev.{}", f.severity)) {
                "?" => f.severity.clone(),
                s => s.to_owned(),
            };
            (format!("[{severity}] {}: {}", f.area, f.item), f.detail.clone())
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct QuarantineView {
    pub id: String,
    pub title: String,
    pub detail: String,
}

pub fn quarantine_view(items: &[QuarantineItem], now: i64, lang: Lang) -> Vec<QuarantineView> {
    items
        .iter()
        .map(|i| QuarantineView {
            id: i.id.clone(),
            title: format!("{} · {}", i.name, verdict_text(&i.verdict, lang)),
            detail: format!(
                "{} {} · {} · {} · {}",
                t(lang, "quar.from"),
                i.original_path,
                i.reason,
                bytes(i.size),
                relative(Some(&i.quarantined_at), now, lang)
            ),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProtectionPageView {
    /// realtime, onaccess, ransomware, decoys, terminal (in that order; terminal only off Windows).
    pub toggles: Vec<ToggleView>,
    pub folders: Vec<String>,
    /// Frozen processes: id is the pid.
    pub halted: Vec<QuarantineView>,
    /// Ransomware alert and Controlled Folder Access state, as (title, detail).
    pub notes: Vec<(String, String)>,
    pub show_cfa: bool,
}

fn fill(lang: Lang, key: &str, pairs: &[(&str, String)]) -> String {
    let mut text = t(lang, key).to_owned();
    for (name, value) in pairs {
        text = text.replace(&format!("{{{name}}}"), value);
    }
    text
}

pub fn protection_view(status: &ProtectionStatus, now: i64, lang: Lang) -> ProtectionPageView {
    let mut toggles = vec![ToggleView {
        key: "realtime".into(),
        label: t(lang, "prot.realtime").into(),
        hint: fill(lang, "prot.realtime_hint", &[("folders", status.realtime.folders.join(", "))]),
        on: status.realtime.on,
        available: true,
    }];
    let oa = &status.on_access;
    let onaccess_hint = if !oa.supported {
        t(lang, "prot.onaccess_linux").to_owned()
    } else if oa.on && oa.state != "active" {
        fill(lang, "prot.onaccess_state", &[("state", oa.state.clone())])
    } else if !oa.manageable && !oa.on {
        t(lang, "prot.onaccess_unmanageable").to_owned()
    } else {
        t(lang, "prot.onaccess_hint").to_owned()
    };
    toggles.push(ToggleView {
        key: "onaccess".into(),
        label: t(lang, "prot.onaccess").into(),
        hint: onaccess_hint,
        on: oa.on,
        available: oa.supported && (oa.manageable || oa.on),
    });
    let rw = &status.ransomware;
    toggles.push(ToggleView {
        key: "ransomware".into(),
        label: t(lang, "prot.ransomware").into(),
        hint: if rw.folders.is_empty() {
            t(lang, "prot.no_folders").to_owned()
        } else {
            t(lang, "prot.ransomware_hint").to_owned()
        },
        on: rw.on,
        available: true,
    });
    toggles.push(ToggleView {
        key: "decoys".into(),
        label: t(lang, "prot.decoys").into(),
        hint: fill(lang, "prot.decoys_hint", &[("n", rw.decoy_count.to_string())]),
        on: rw.decoys,
        available: rw.on,
    });
    if status.terminal.supported {
        let shells: Vec<String> = status
            .terminal
            .shells
            .iter()
            .map(|s| format!("{} {}", s.shell, if s.enabled { t(lang, "prot.on") } else { t(lang, "prot.off") }))
            .collect();
        toggles.push(ToggleView {
            key: "terminal".into(),
            label: t(lang, "prot.terminal").into(),
            hint: format!("{} {}", t(lang, "prot.terminal_hint"), shells.join(", ")),
            on: status.terminal.shells.iter().any(|s| s.enabled),
            available: true,
        });
    }
    let halted = rw
        .halted
        .iter()
        .map(|h| QuarantineView {
            id: h.pid.to_string(),
            title: fill(lang, "prot.halted_title", &[("pid", h.pid.to_string())]),
            detail: format!("{} · {}", h.reason, relative(Some(&h.at), now, lang)),
        })
        .collect();
    let mut notes = Vec::new();
    if let Some(alert) = &rw.last_alert {
        notes.push((
            fill(lang, "prot.alert", &[("when", relative(Some(&alert.at), now, lang))]),
            format!("{} · {}", alert.reasons.join("; "), alert.examples.join(", ")),
        ));
    }
    if let Some(cfa) = &status.cfa {
        let state = match t(lang, &format!("prot.cfa.{}", cfa.state)) {
            "?" => cfa.state.clone(),
            s => s.to_owned(),
        };
        let mut detail = Vec::new();
        if !cfa.folders.is_empty() {
            detail.push(format!("{} {}", t(lang, "prot.cfa_folders"), cfa.folders.join(", ")));
        }
        if !cfa.allowed_apps.is_empty() {
            detail.push(format!("{} {}", t(lang, "prot.cfa_apps"), cfa.allowed_apps.join(", ")));
        }
        notes.push((format!("{} {state}", t(lang, "prot.cfa")), detail.join(" · ")));
    }
    ProtectionPageView {
        toggles,
        folders: rw.folders.clone(),
        halted,
        notes,
        show_cfa: status.cfa.as_ref().is_some_and(|c| c.supported),
    }
}

/// The Wi-Fi and updates checks as (title, detail). A check that couldn't run says so.
pub fn system_view(checks: &SystemChecks, lang: Lang) -> Vec<(String, String)> {
    let wifi = match &checks.wifi {
        None => (t(lang, "prot.wifi_unknown").to_owned(), String::new()),
        Some(w) if w.risk == "none" || w.ssid.is_none() => (t(lang, "prot.wifi_none").to_owned(), String::new()),
        Some(w) => {
            let name = w.ssid.clone().unwrap_or_default();
            let key = match w.risk.as_str() {
                "open" => "prot.wifi_open",
                "weak" => "prot.wifi_weak",
                "ok" => "prot.wifi_ok",
                _ => "prot.wifi_unclear",
            };
            (fill(lang, key, &[("ssid", name)]), w.security.clone().unwrap_or_default())
        }
    };
    let updates = match &checks.updates {
        None => (t(lang, "prot.updates_unknown").to_owned(), String::new()),
        Some(u) if u.count == 0 => (t(lang, "prot.updates_none").to_owned(), u.source.clone()),
        Some(u) => (
            fill(lang, "prot.updates", &[("n", u.count.to_string()), ("source", u.source.clone())]),
            u.items.iter().take(8).map(|i| i.name.clone()).collect::<Vec<_>>().join(", "),
        ),
    };
    vec![wifi, updates]
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceCardView {
    pub key: String,
    pub ip: String,
    pub title: String,
    pub detail: String,
    /// "new", "known", "router", "self" or "" (seen before, not marked).
    pub badge: String,
    pub trusted: bool,
    /// Has a login service (web page, Telnet, FTP) the default-password check can try.
    pub can_check: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkPageView {
    pub summary: String,
    /// What changed since the previous scan, as (title, detail).
    pub changes: Vec<(String, String)>,
    pub devices: Vec<DeviceCardView>,
    /// (title, detail, severity), most serious first.
    pub findings: Vec<(String, String, String)>,
    pub scanning: bool,
}

/// "Scanning the network… 120/254".
pub fn network_progress_text(done: u32, total: u32, phase: &str, lang: Lang) -> String {
    let key = if phase == "sweep" { "net.finding" } else { "net.checking" };
    format!("{} {done}/{total}", t(lang, key))
}

pub fn network_view(status: &NetworkStatus, now: i64, lang: Lang) -> NetworkPageView {
    let Some(scan) = &status.scan else {
        return NetworkPageView {
            summary: if let Some(p) = &status.progress {
                network_progress_text(p.done, p.total, &p.phase, lang)
            } else {
                t(lang, "net.never").to_owned()
            },
            changes: vec![],
            devices: vec![],
            findings: vec![],
            scanning: status.scanning,
        };
    };
    let fresh: Vec<&str> = status
        .changes
        .as_ref()
        .map(|c| c.new_devices.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let devices = scan
        .devices
        .iter()
        .map(|d| {
            let badge = if d.role == "router" {
                "router"
            } else if d.role == "self" {
                "self"
            } else if d.trusted {
                "known"
            } else if fresh.contains(&d.key.as_str()) {
                "new"
            } else {
                ""
            };
            let mut parts = vec![d.ip.clone()];
            if let Some(v) = &d.vendor {
                parts.push(v.clone());
            }
            if !d.services.is_empty() {
                parts.push(
                    d.services
                        .iter()
                        .map(|s| format!("{} {}", s.name, s.port))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            if !badge.is_empty() {
                parts.push(t(lang, &format!("net.badge.{badge}")).to_owned());
            }
            if let Some(first) = &d.first_seen {
                parts.push(format!("{} {}", t(lang, "net.first_seen"), relative(Some(first), now, lang)));
            }
            DeviceCardView {
                key: d.key.clone(),
                ip: d.ip.clone(),
                title: d
                    .hostname
                    .clone()
                    .or_else(|| d.vendor.clone())
                    .unwrap_or_else(|| t(lang, "net.unnamed").to_owned()),
                detail: parts.join(" · "),
                badge: badge.into(),
                trusted: d.trusted,
                can_check: d.services.iter().any(|s| matches!(s.port, 80 | 8080 | 23 | 2323 | 21)),
            }
        })
        .collect();
    let rank = |s: &str| match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    };
    let mut findings: Vec<(String, String, String)> = scan
        .findings
        .iter()
        .map(|f| {
            let severity = match t(lang, &format!("sev.{}", f.severity)) {
                "?" => f.severity.clone(),
                s => s.to_owned(),
            };
            (format!("[{severity}] {}", f.title), f.detail.clone(), f.severity.clone())
        })
        .collect();
    findings.sort_by_key(|f| rank(&f.2));
    let mut changes = Vec::new();
    if let Some(c) = &status.changes {
        if c.compared_with.is_some() {
            let names = |keys: &[String]| -> String {
                keys.iter()
                    .filter_map(|k| scan.devices.iter().find(|d| &d.key == k))
                    .map(|d| d.hostname.clone().or_else(|| d.vendor.clone()).unwrap_or_else(|| d.ip.clone()))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            if !c.new_devices.is_empty() {
                changes.push((
                    fill(lang, "net.changes_new", &[("n", c.new_devices.len().to_string())]),
                    names(&c.new_devices),
                ));
            }
            if !c.gone.is_empty() {
                changes.push((
                    fill(lang, "net.changes_gone", &[("n", c.gone.len().to_string())]),
                    c.gone
                        .iter()
                        .map(|g| g.name.clone().unwrap_or_else(|| g.ip.clone()))
                        .collect::<Vec<_>>()
                        .join(", "),
                ));
            }
            if !c.new_risks.is_empty() {
                changes.push((
                    fill(lang, "net.changes_risks", &[("n", c.new_risks.len().to_string())]),
                    c.new_risks.iter().map(|r| r.title.clone()).collect::<Vec<_>>().join("; "),
                ));
            }
            if changes.is_empty() {
                changes.push((t(lang, "net.no_changes").to_owned(), String::new()));
            }
        }
    }
    let mut summary = if let Some(p) = &status.progress {
        network_progress_text(p.done, p.total, &p.phase, lang)
    } else {
        fill(
            lang,
            "net.summary",
            &[
                ("n", scan.devices.len().to_string()),
                ("cidr", scan.cidr.clone().unwrap_or_default()),
                ("when", relative(Some(&scan.finished_at), now, lang)),
            ],
        )
    };
    if status.watch.on {
        if let Some(next) = &status.watch.next_at {
            summary.push_str(" · ");
            summary.push_str(&fill(
                lang,
                "net.next",
                &[("when", next.get(11..16).unwrap_or_default().to_owned())],
            ));
        }
    }
    NetworkPageView {
        summary,
        changes,
        devices,
        findings,
        scanning: status.scanning,
    }
}

/// The default-password check's result. Never "secure": a refused login means only that.
pub fn credential_text(checks: &CredentialChecks, lang: Lang) -> String {
    checks
        .results
        .iter()
        .map(|r| {
            if r.default_accepted {
                fill(
                    lang,
                    "net.cred_accepted",
                    &[("service", r.service.clone()), ("user", r.user.clone().unwrap_or_default())],
                )
            } else if let Some(why) = &r.stopped {
                fill(lang, "net.cred_stopped", &[("service", r.service.clone()), ("why", why.clone())])
            } else {
                fill(
                    lang,
                    "net.cred_refused",
                    &[("service", r.service.clone()), ("n", r.tried.to_string())],
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Clone, PartialEq)]
pub struct VpnPageView {
    pub state_text: String,
    /// What to do next, or why something isn't available here.
    pub hint: String,
    pub can_setup: bool,
    pub setup_label: String,
    pub can_connect: bool,
    pub connected: bool,
    /// killswitch, allowlan, autoconnect.
    pub toggles: Vec<ToggleView>,
    pub split_mode: String,
    pub split_hint: String,
    pub ranges: Vec<String>,
    pub trusted: Vec<String>,
}

pub fn vpn_view(status: &VpnStatus, lang: Lang) -> VpnPageView {
    let state_text = match t(lang, &format!("vpn.state.{}", status.state)) {
        "?" => status.state.clone(),
        s => s.to_owned(),
    };
    let hint = if !status.linked && !status.saved {
        t(lang, "vpn.hint_link").to_owned()
    } else if !status.saved {
        t(lang, "vpn.hint_setup").to_owned()
    } else if status.state == "unsupported" {
        t(lang, "vpn.hint_unsupported").to_owned()
    } else if let Some(network) = &status.auto_connected_on {
        fill(lang, "vpn.hint_auto", &[("network", network.clone())])
    } else {
        String::new()
    };
    let guard_hint = |key: &str| {
        if status.guard_capable {
            t(lang, key).to_owned()
        } else {
            t(lang, "vpn.linux_only").to_owned()
        }
    };
    let toggles = vec![
        ToggleView {
            key: "killswitch".into(),
            label: t(lang, "vpn.killswitch").into(),
            hint: guard_hint("vpn.killswitch_hint"),
            on: status.kill_switch,
            available: status.guard_capable,
        },
        ToggleView {
            key: "allowlan".into(),
            label: t(lang, "vpn.allowlan").into(),
            hint: t(lang, "vpn.allowlan_hint").into(),
            on: status.allow_lan,
            available: status.guard_capable,
        },
        ToggleView {
            key: "autoconnect".into(),
            label: t(lang, "vpn.autoconnect").into(),
            hint: guard_hint("vpn.autoconnect_hint"),
            on: status.auto_connect,
            available: status.guard_capable,
        },
    ];
    VpnPageView {
        state_text: format!("{} {state_text}", t(lang, "vpn.state")),
        hint,
        can_setup: status.linked,
        setup_label: t(lang, if status.saved { "vpn.setup_again" } else { "vpn.setup" }).to_owned(),
        can_connect: status.saved && matches!(status.state.as_str(), "connected" | "disconnected"),
        connected: status.state == "connected",
        toggles,
        split_mode: status.split_mode.clone(),
        split_hint: t(lang, &format!("vpn.split.{}_hint", status.split_mode)).to_owned(),
        ranges: status.split_cidrs.clone(),
        trusted: status.trusted.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_page_follows_the_tunnel_state_and_platform() {
        let json: serde_json::Value = serde_json::from_str(include_str!("../../qalaa-ipc/tests/fixtures/vpn.json")).expect("fixture");
        let status: qalaa_ipc::VpnStatus = serde_json::from_value(json["status"].clone()).expect("status");
        let view = vpn_view(&status, Lang::En);
        assert_eq!(view.state_text, "Tunnel: connected");
        assert_eq!(view.hint, "Turned on automatically on \"Cafe\".");
        assert!(view.connected && view.can_connect && view.can_setup);
        assert_eq!(view.setup_label, "Set up again (new key)");
        assert_eq!(view.ranges, ["192.168.50.0/24"]);
        assert!(view.toggles.iter().all(|t| t.available));

        let mut mac = status.clone();
        mac.platform = "darwin".into();
        mac.guard_capable = false;
        let view = vpn_view(&mac, Lang::Ar);
        assert!(view
            .toggles
            .iter()
            .filter(|t| t.key != "allowlan")
            .all(|t| !t.available && t.hint.contains("لينكس")));

        let mut fresh = status;
        fresh.linked = false;
        fresh.saved = false;
        fresh.state = "not_imported".into();
        let view = vpn_view(&fresh, Lang::En);
        assert!(!view.can_setup && !view.can_connect);
        assert!(view.hint.starts_with("Link this computer"));
    }

    fn network_fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../../qalaa-ipc/tests/fixtures/network.json")).expect("fixture")
    }

    #[test]
    fn network_page_shows_devices_changes_and_findings() {
        let json = network_fixture();
        let status: qalaa_ipc::NetworkStatus = serde_json::from_value(json["status"].clone()).expect("status");
        let now = parse_iso("2026-11-25T19:00:00Z").expect("time");
        let view = network_view(&status, now, Lang::En);
        assert_eq!(
            view.summary,
            "3 devices on 192.168.1.0/24, scanned 1 hour ago · next scan at 00:00 UTC"
        );
        let badges: Vec<&str> = view.devices.iter().map(|d| d.badge.as_str()).collect();
        assert_eq!(badges, ["router", "self", "new"]);
        assert_eq!(view.devices[2].title, "living-room-tv");
        assert!(view.devices[0].can_check, "the router has a web admin page");
        assert!(!view.devices[2].can_check);
        assert_eq!(view.changes[0], ("1 new device(s)".to_owned(), "living-room-tv".to_owned()));
        assert_eq!(view.changes[1], ("1 device(s) not seen this time".to_owned(), "ipcam".to_owned()));
        assert_eq!(view.changes[2].0, "1 new risk(s)");
        assert!(view.findings[0].0.starts_with("[critical]"));
        // Arabic falls back to the engine's English finding text, with an Arabic severity.
        let ar = network_view(&status, now, Lang::Ar);
        assert!(ar.findings[0].0.starts_with("[حرج]"));
        for text in [&view.summary, &ar.summary] {
            assert!(!text.to_lowercase().contains("safe"));
        }
    }

    #[test]
    fn never_scanned_and_first_scan_say_so() {
        let empty = qalaa_ipc::NetworkStatus {
            scanning: false,
            progress: None,
            scan: None,
            changes: None,
            watch: qalaa_ipc::NetworkWatch {
                on: false,
                every_hours: 6,
                next_at: None,
            },
        };
        assert_eq!(network_view(&empty, 0, Lang::En).summary, "Not scanned yet.");
        let running = qalaa_ipc::NetworkStatus {
            scanning: true,
            progress: Some(qalaa_ipc::NetworkProgress {
                done: 40,
                total: 254,
                phase: "sweep".into(),
            }),
            ..empty
        };
        assert_eq!(network_view(&running, 0, Lang::En).summary, "Finding devices… 40/254");
    }

    #[test]
    fn default_password_results_never_say_secure() {
        let checks = qalaa_ipc::CredentialChecks {
            ip: "192.168.1.30".into(),
            results: vec![
                qalaa_ipc::CredentialCheck {
                    device: "192.168.1.30".into(),
                    service: "telnet".into(),
                    default_accepted: true,
                    user: Some("admin".into()),
                    tried: 2,
                    stopped: None,
                },
                qalaa_ipc::CredentialCheck {
                    device: "192.168.1.30".into(),
                    service: "http".into(),
                    default_accepted: false,
                    user: None,
                    tried: 5,
                    stopped: None,
                },
                qalaa_ipc::CredentialCheck {
                    device: "192.168.1.30".into(),
                    service: "ftp".into(),
                    default_accepted: false,
                    user: None,
                    tried: 1,
                    stopped: Some("locked out".into()),
                },
            ],
        };
        let text = credential_text(&checks, Lang::En);
        assert_eq!(
            text,
            "telnet: a factory default login works (user \"admin\"). Change that password now.\nhttp: none of the 5 common default logins worked.\nftp: the check stopped (locked out)."
        );
        assert!(!text.to_lowercase().contains("secure"));
    }

    fn protection_fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../../qalaa-ipc/tests/fixtures/protection.json")).expect("fixture")
    }

    #[test]
    fn protection_page_lists_switches_frozen_programs_and_alerts() {
        let json = protection_fixture();
        let linux: qalaa_ipc::ProtectionStatus = serde_json::from_value(json["linux"].clone()).expect("linux");
        let now = parse_iso("2026-11-25T12:30:00Z").expect("time");
        let view = protection_view(&linux, now, Lang::En);
        let keys: Vec<&str> = view.toggles.iter().map(|t| t.key.as_str()).collect();
        assert_eq!(keys, ["realtime", "onaccess", "ransomware", "decoys", "terminal"]);
        assert!(view.toggles.iter().all(|t| t.available));
        assert_eq!(view.toggles[0].hint, "Checks each new file in: /home/me/Downloads");
        assert_eq!(view.halted[0].id, "4242");
        assert_eq!(view.halted[0].title, "Program 4242 was frozen");
        assert!(view.notes[0].0.starts_with("Possible ransomware activity, 30 minutes ago"));
        assert!(!view.show_cfa);

        let windows: qalaa_ipc::ProtectionStatus = serde_json::from_value(json["windows"].clone()).expect("windows");
        let view = protection_view(&windows, now, Lang::En);
        // No terminal protection on Windows; on-access is Linux only and says so.
        assert!(!view.toggles.iter().any(|t| t.key == "terminal"));
        let onaccess = view.toggles.iter().find(|t| t.key == "onaccess").expect("onaccess");
        assert!(onaccess.available, "the fixture's fake says supported");
        assert!(view.show_cfa);
        assert_eq!(
            view.notes[0].0,
            "Windows Controlled Folder Access: audit only (logs, doesn't block)"
        );
        assert!(view.notes[0].1.contains("D:\\Work"));

        let mut unsupported = windows.clone();
        unsupported.on_access.supported = false;
        let view = protection_view(&unsupported, now, Lang::Ar);
        let onaccess = view.toggles.iter().find(|t| t.key == "onaccess").expect("onaccess");
        assert!(!onaccess.available);
        assert!(onaccess.hint.contains("لينكس"));
    }

    #[test]
    fn system_checks_that_could_not_run_say_so() {
        let json = protection_fixture();
        let checks: qalaa_ipc::SystemChecks = serde_json::from_value(json["system"].clone()).expect("system");
        let rows = system_view(&checks, Lang::En);
        assert!(rows[0].0.starts_with("Wi-Fi \"Cafe\" is open"));
        assert_eq!(rows[1], ("1 system update(s) waiting (apt)".to_owned(), "openssl".to_owned()));
        let unknown = qalaa_ipc::SystemChecks {
            wifi: None,
            updates: None,
            checked_at: checks.checked_at.clone(),
        };
        let rows = system_view(&unknown, Lang::En);
        assert_eq!(rows[0].0, "Couldn't check the Wi-Fi on this system.");
        assert_eq!(rows[1].0, "Couldn't check for system updates on this system.");
    }

    #[test]
    fn scan_results_say_no_known_threat_never_safe() {
        let json: serde_json::Value = serde_json::from_str(include_str!("../../qalaa-ipc/tests/fixtures/scan.json")).expect("fixture");
        let status: qalaa_ipc::ScanStatus = serde_json::from_value(json["status"].clone()).expect("status");
        let now = parse_iso("2026-11-25T13:00:00Z").expect("time");
        for lang in [Lang::En, Lang::Ar] {
            let view = scan_view(&status, now, lang);
            assert_eq!(view.rows.len(), 3);
            for row in &view.rows {
                assert!(!row.detail.to_lowercase().contains("safe"), "{}", row.detail);
            }
        }
        let view = scan_view(&status, now, Lang::En);
        assert!(view.rows[1].detail.starts_with("No known threat"));
        assert!(view.rows[2].quarantined && !view.rows[2].can_quarantine);
        assert!(view.rows[0].can_quarantine);
        assert_eq!(view.summary, "Last scan: 3 files, 2 found, 59 minutes ago");
        // No native engine on the fixture's computer: said plainly.
        assert!(view.engines.contains("ClamAV") && view.engines.contains("isn't installed"));
        let mut running = status.clone();
        running.progress = Some(qalaa_ipc::ScanProgress {
            scanned: 120,
            found: 1,
            current: "/x".into(),
        });
        assert_eq!(scan_view(&running, now, Lang::En).summary, "Scanning… 120 files checked, 1 found");
    }

    #[test]
    fn inspector_lists_every_finding_and_the_fingerprint() {
        let json: serde_json::Value = serde_json::from_str(include_str!("../../qalaa-ipc/tests/fixtures/scan.json")).expect("fixture");
        let details: qalaa_ipc::ScanDetails = serde_json::from_value(json["details"].clone()).expect("details");
        let text = inspector_text(&details, parse_iso("2026-11-25T13:00:00Z").expect("time"), Lang::En);
        assert!(text.contains("• [medium] Script downloads and runs a file: Matched in the first 4 KB."));
        assert!(text.contains(&format!("SHA-256 {}", "b".repeat(64))));
        assert!(text.contains("Engines: signatures, heuristics"));
    }

    #[test]
    fn deep_check_and_sizes() {
        let empty = qalaa_ipc::DeepCheck {
            findings: vec![],
            checked: vec!["Startup".into(), "Cron".into()],
            checked_at: "2026-11-25T12:00:00Z".into(),
        };
        assert_eq!(
            deep_view(&empty, Lang::En),
            vec![(
                "Nothing unusual in the places checked.".to_owned(),
                "Checked: Startup, Cron".to_owned()
            )]
        );
        let found = qalaa_ipc::DeepCheck {
            findings: vec![qalaa_ipc::DeepFinding {
                area: "Cron".into(),
                item: "@reboot curl x | sh".into(),
                severity: "high".into(),
                detail: "Runs a download".into(),
            }],
            ..empty
        };
        assert_eq!(deep_view(&found, Lang::Ar)[0].0, "[عالٍ] Cron: @reboot curl x | sh");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MB");
    }

    const NOW: &str = "2026-11-24T12:00:00Z";

    fn fixture() -> HomeModel {
        serde_json::from_str(include_str!("../../qalaa-ipc/tests/fixtures/home.json")).expect("fixture")
    }

    #[test]
    fn behaviour_rows_in_both_languages() {
        let status: BehaviourStatus = serde_json::from_value(serde_json::json!({
            "enabled": true, "rules": 8, "rulesVersion": "2026.11.25.1",
            "capability": {"source": "ps_poll", "intervalMs": 2000, "seesShortLived": false, "note": "x"},
            "incidents": [
                {"id": "b1", "rule": "firewall_disabled", "title": "The firewall is being switched off or emptied", "description": "", "technique": "T1562.004", "level": "high", "pid": 87, "program": "sh", "parent": "bash", "commandLine": "sh -c ufw disable", "at": "2026-11-24T11:59:30Z", "state": "open"},
                {"id": "b2", "rule": "brand_new_rule", "title": "Something new", "description": "", "technique": "T1000", "level": "low", "pid": 9, "program": "x", "parent": "", "commandLine": "x", "at": "2026-11-24T11:00:00Z", "state": "stopped"}
            ]
        }))
        .expect("status");
        let now = parse_iso(NOW).expect("now");
        let (rows, note) = behaviour_view(&status, now, Lang::En);
        assert_eq!(rows[0].title, "The firewall is being switched off or emptied: sh  · High risk");
        assert_eq!(rows[0].detail, "sh -c ufw disable (started by bash) · T1562.004 · just now · 87");
        assert_eq!(
            rows[1].title, "Something new: x  · Stopped",
            "unknown rules fall back to the service's title"
        );
        assert!(note.contains("macOS"));
        assert!(!behaviour_can_install_helper(&status));
        let mut linux = status.clone();
        linux.capability.source = "proc_poll".into();
        assert!(behaviour_can_install_helper(&linux));
        linux.capability.source = "proc_connector".into();
        assert!(behaviour_view(&linux, now, Lang::En).1.contains("Every program start"));
        assert!(!behaviour_can_install_helper(&linux));
        let (ar, note_ar) = behaviour_view(&status, now, Lang::Ar);
        assert!(ar[0].title.starts_with("يُوقَف جدار الحماية"));
        assert!(ar[0].title.contains("خطورة عالية"));
        assert!(note_ar.contains("macOS"));
    }

    #[test]
    fn safe_dns_ad_blocking_switch_in_both_languages() {
        let mut model = fixture();
        model
            .toggles
            .push(serde_json::from_value(serde_json::json!({"key": "dnsAdBlocking", "on": false, "available": true})).expect("toggle"));
        let now = parse_iso(NOW).expect("now");
        let en = home_view(&model, now, Lang::En);
        let row = en.toggles.iter().find(|t| t.key == "dnsAdBlocking").expect("toggle row");
        assert_eq!(row.label, "Also block ads and trackers (EasyList, EasyPrivacy)");
        let ar = home_view(&model, now, Lang::Ar);
        assert!(ar.toggles.iter().any(|t| t.label.starts_with("احجب أيضًا الإعلانات")));
    }

    #[test]
    fn sandbox_rows_show_indicators_or_the_reason() {
        let runs: Vec<SandboxRun> = serde_json::from_value(serde_json::json!([
            {"id": "a", "file": "install.sh", "reportUrl": "https://q.example/scans/a", "status": "completed", "risk": "suspicious", "note": null, "timedOut": false, "seconds": 2.5, "dnsLookups": ["c2.bad.test"], "webRequests": [], "directConnections": ["203.0.113.7:4444"], "programs": ["curl"], "submittedAt": "2026-11-25T10:00:00Z"},
            {"id": "b", "file": "setup.exe", "reportUrl": "https://q.example/scans/b", "status": "completed", "risk": null, "note": "Only Linux programs and scripts can be run in the sandbox.", "timedOut": false, "seconds": null, "dnsLookups": [], "webRequests": [], "directConnections": [], "programs": [], "submittedAt": "2026-11-25T10:00:00Z"},
            {"id": "c", "file": "quiet.sh", "reportUrl": "https://q.example/scans/c", "status": "running", "risk": null, "note": null, "timedOut": false, "seconds": null, "dnsLookups": [], "webRequests": [], "directConnections": [], "programs": [], "submittedAt": "2026-11-25T10:00:00Z"}
        ]))
        .expect("runs");
        let rows = sandbox_view(&runs, Lang::En);
        assert_eq!(rows[0].title, "install.sh  · Done");
        assert_eq!(
            rows[0].detail,
            "ran for 2.5 s · looked up: c2.bad.test · connected to: 203.0.113.7:4444 · started: curl"
        );
        assert!(rows[1].detail.contains("Only Linux"));
        assert_eq!(rows[2].title, "quiet.sh  · Running");
        assert!(sandbox_view(&runs, Lang::Ar)[0].title.contains("انتهى"));
    }

    #[test]
    fn parses_iso_times() {
        assert_eq!(parse_iso("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso("2026-11-24T12:00:00.000Z"), Some(1_795_521_600));
        assert_eq!(parse_iso("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(parse_iso("nonsense"), None);
        assert_eq!(parse_iso("2026-13-01T00:00:00Z"), None);
    }

    #[test]
    fn freshness_in_both_languages() {
        let now = parse_iso(NOW).expect("now");
        assert_eq!(relative(Some("2026-11-24T11:59:30Z"), now, Lang::En), "just now");
        assert_eq!(relative(Some("2026-11-24T11:00:00Z"), now, Lang::En), "1 hour ago");
        assert_eq!(relative(Some("2026-11-21T08:00:00Z"), now, Lang::En), "3 days ago");
        assert_eq!(relative(Some("2026-11-24T11:15:00Z"), now, Lang::Ar), "منذ 45 دقيقة");
        assert_eq!(relative(None, now, Lang::En), "never");
        assert_eq!(relative(Some("2027-01-01T00:00:00Z"), now, Lang::En), "just now");
    }

    #[test]
    fn home_view_from_the_shared_fixture() {
        let view = home_view(&fixture(), parse_iso(NOW).expect("now"), Lang::En);
        assert_eq!(view.state, "at_risk");
        assert_eq!(view.state_text, "At risk");
        assert_eq!(view.checks[0].label, "Malware fingerprints");
        assert_eq!(view.checks[0].freshness, "3 days ago");
        assert_eq!(view.checks[1].status_text, "Off");
        assert_eq!(view.actions[0].title, "Review recent threats");
        assert!(view.actions.windows(2).all(|w| w[0].priority <= w[1].priority));
        let arabic = home_view(&fixture(), parse_iso(NOW).expect("now"), Lang::Ar);
        assert_eq!(arabic.state_text, "في خطر");
        assert!(arabic.actions.iter().all(|a| !a.title.contains('?')));
    }

    #[test]
    fn clipboard_countdown_text() {
        assert_eq!(
            clipboard_text("api_token", 23_400, Lang::En),
            "An API token is on the clipboard: clearing in 24 s"
        );
        assert_eq!(
            clipboard_text("mystery", 1, Lang::En),
            "Something that looks like a password is on the clipboard: clearing in 1 s"
        );
        assert_eq!(clipboard_text("private_key", 5_000, Lang::Ar), "مفتاح خاص في الحافظة: تُمسح خلال 5 ث");
    }

    #[test]
    fn keyboard_action_has_its_own_answer() {
        let mut model = fixture();
        model.actions.insert(
            0,
            serde_json::from_value(
                serde_json::json!({"id": "review_keyboard", "priority": 1, "command": {"method": "keyboards.trust_all"}}),
            )
            .expect("action"),
        );
        let view = home_view(&model, 0, Lang::En);
        assert_eq!(view.actions[0].title, "A new keyboard was connected");
        assert_eq!(view.actions[0].button, "I plugged it in");
        assert_eq!(view.actions[1].button, "Do it");
        assert_eq!(home_view(&model, 0, Lang::Ar).actions[0].button, "أنا وصلتها");
    }

    #[test]
    fn credentials_view_names_the_program_and_file() {
        let status: CredentialStatus = serde_json::from_value(serde_json::json!({
            "supported": true, "enabled": true, "mode": "polling", "trusted": [],
            "incidents": [
                {"id": "c2", "pid": 901, "program": "node", "exe": "/usr/bin/node", "credential": "browser_secrets", "file": "~/.config/google-chrome/Default/Cookies", "at": "2026-11-24T10:00:00Z", "state": "suspended"},
                {"id": "c1", "pid": 900, "program": "python3", "exe": "/usr/bin/python3", "credential": "ssh_key", "file": "~/.ssh/id_rsa", "at": "2026-11-24T09:59:00Z", "state": "open"},
                {"id": "c3", "pid": 902, "program": "upd", "exe": "/tmp/upd", "credential": "browser_secrets", "file": "~/.config/google-chrome/Default/Login Data", "at": "2026-11-24T09:59:00Z", "state": "open", "severity": "high", "pattern": "browser_key_and_secrets"}
            ]
        }))
        .expect("status");
        let now = parse_iso("2026-11-24T10:00:30Z").expect("time");
        let (high, _) = credentials_view(&status, now, Lang::En);
        assert!(high[2].title.ends_with("  · High risk"), "{}", high[2].title);
        assert!(high[2].detail.contains("as information stealers do"));
        assert_eq!(status.incidents[0].severity, "warning", "older daemons send no severity");
        let (rows, mode) = credentials_view(&status, now, Lang::En);
        assert_eq!(rows[0].title, "node opened ~/.config/google-chrome/Default/Cookies  · Paused");
        assert!(rows[0].detail.starts_with("Browser passwords and cookies · "));
        assert_eq!(rows[1].title, "python3 opened ~/.ssh/id_rsa");
        assert!(mode.starts_with("Checking open files"));
        let (ar, _) = credentials_view(&status, now, Lang::Ar);
        assert_eq!(ar[1].title, "فتح python3 الملف ~/.ssh/id_rsa");
        let unknown = CredentialStatus {
            mode: "unavailable".into(),
            supported: false,
            ..status
        };
        assert!(credentials_view(&unknown, now, Lang::En).1.contains("Windows"));
    }

    #[test]
    fn alias_notice_in_both_languages() {
        assert_eq!(
            alias_notice("k7x2mq9p4h@relay.example.org", true, Lang::En),
            "k7x2mq9p4h@relay.example.org copied. Mail to it reaches your inbox; pause or delete it from your account."
        );
        assert!(alias_notice("a@b.org", false, Lang::Ar).starts_with("a@b.org جاهز"));
        assert!(palette_entries(None, Lang::En).iter().any(|e| e.id == "alias.new"));
    }

    #[test]
    fn brokers_view_puts_rechecks_first() {
        let status: BrokerStatus = serde_json::from_value(serde_json::json!({
            "catalogVersion": "2026-11-25", "reviewed": null, "note": "", "done": 2, "recheckDue": 1,
            "brokers": [
                {"id": "a", "name": "Alpha", "site": "a.example", "optOutUrl": "https://a.example/out", "verification": "email_link", "removalDays": 3, "steps": [], "state": "removed", "at": "2026-01-01T00:00:00Z", "recheckDue": false, "expectedBy": null},
                {"id": "b", "name": "Beta", "site": "b.example", "optOutUrl": "https://b.example/out", "verification": "email_link", "removalDays": 7, "steps": [], "state": "todo", "at": null, "recheckDue": false, "expectedBy": null},
                {"id": "c", "name": "Gamma", "site": "c.example", "optOutUrl": "https://c.example/out", "verification": "form", "removalDays": 30, "steps": [], "state": "requested", "at": "2026-01-01T00:00:00Z", "recheckDue": true, "expectedBy": "2026-01-31T00:00:00Z"}
            ]
        }))
        .expect("status");
        let (rows, summary) = brokers_view(&status, Lang::En);
        assert_eq!(rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["c", "b", "a"]);
        assert_eq!(rows[0].detail, "c.example · Requested · Look again: 90 days have passed");
        assert_eq!(rows[1].detail, "b.example · Not started · 7 days to remove");
        assert_eq!(summary, "2 / 3 done");
        assert!(safe_to_open("https://a.example/out"));
        assert!(!safe_to_open("file:///etc/passwd") && !safe_to_open("https://a.example/x y"));
        assert!(brokers_view(&status, Lang::Ar).0[1].detail.contains("لم يبدأ"));
    }

    #[test]
    fn sensitive_pages_are_hidden_from_capture() {
        assert!(content_protected("credentials"));
        assert!(!content_protected("home"));
        assert!(palette_entries(None, Lang::En)
            .iter()
            .any(|e| e.id == "safepay" && e.title == "Open SafePay"));
    }

    #[test]
    fn ports_view_puts_new_listeners_first() {
        let status: ListenerStatus = serde_json::from_value(serde_json::json!({
            "listeners": [
                {"key": "cupsd|631|local", "port": 631, "address": "127.0.0.1", "process": "cupsd", "pid": 1, "exposed": false, "risk": null, "fresh": false},
                {"key": "sshd|22|net", "port": 22, "address": "0.0.0.0", "process": "sshd", "pid": 2, "exposed": true, "risk": null, "fresh": false},
                {"key": "telnetd|23|net", "port": 23, "address": "0.0.0.0", "process": "telnetd", "pid": 3, "exposed": true, "risk": "Telnet sends everything unencrypted", "fresh": true},
                {"key": "unknown|9|net", "port": 9, "address": "0.0.0.0", "process": null, "pid": null, "exposed": true, "risk": null, "fresh": false}
            ],
            "blockedPorts": [9], "canBlock": true, "checkedAt": null
        }))
        .expect("status");
        let rows = ports_view(&status, Lang::En);
        assert_eq!(rows.iter().map(|r| r.port).collect::<Vec<_>>(), [23, 9, 22, 631]);
        assert_eq!(rows[0].title, "telnetd on port 23");
        assert_eq!(rows[0].detail, "Reachable from other machines. Telnet sends everything unencrypted");
        assert!(rows[1].blocked && rows[1].title.starts_with("Unknown program"));
        assert_eq!(ports_view(&status, Lang::Ar)[0].title, "telnetd على المنفذ 23");
    }

    #[test]
    fn palette_lists_available_toggles_and_filters_by_words() {
        let view = home_view(&fixture(), 0, Lang::En);
        let entries = palette_entries(Some(&view), Lang::En);
        assert!(entries.iter().any(|e| e.id == "toggle.onAccessScan"));
        assert_eq!(
            filter_palette(&entries, "ports").iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            ["page.ports"]
        );
        let found = filter_palette(&entries, "SCAN quick");
        assert_eq!(found.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), ["scan.quick"]);
        assert_eq!(filter_palette(&entries, "").len(), entries.len());
        assert!(filter_palette(&entries, "zzz").is_empty());
    }
}
