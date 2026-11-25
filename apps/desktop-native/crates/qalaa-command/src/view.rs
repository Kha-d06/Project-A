//! Turns the service's Home model into rows for the interface. Plain Rust with
//! no window, so it is tested directly.

use qalaa_ipc::{BehaviourStatus, BrokerStatus, CheckStatus, CredentialStatus, HomeModel, ListenerStatus, PostureState, SandboxRun};

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

#[cfg(test)]
mod tests {
    use super::*;

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
