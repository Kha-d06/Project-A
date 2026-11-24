//! Turns the service's Home model into rows for the interface. Plain Rust with
//! no window, so it is tested directly.

use qalaa_ipc::{CheckStatus, HomeModel, ListenerStatus, PostureState};

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
            id: "page.home".into(),
            title: t(lang, "palette.home").into(),
        },
        PaletteEntry {
            id: "page.ports".into(),
            title: t(lang, "nav.ports").into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-11-24T12:00:00Z";

    fn fixture() -> HomeModel {
        serde_json::from_str(include_str!("../../qalaa-ipc/tests/fixtures/home.json")).expect("fixture")
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
