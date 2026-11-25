//! Filter-list matching for Safe DNS.
//!
//! Lists in Adblock Plus / uBlock syntax (EasyList, EasyPrivacy, a threat
//! list, the person's own rules) are compiled by adblock-rust. DNS only sees a
//! host name, so a name is blocked only by rules that block the whole host:
//! `||ads.example^`, hosts-file lines, `0.0.0.0 tracker.example`. Rules that
//! need more than the name (a path, a resource type, the page it's on, or
//! `$third-party`) can't apply here and are left to the browser extension.
//! Exceptions (`@@||cdn.example^`), `$important` and `$badfilter` behave as in
//! the browser.

use adblock::lists::{FilterSet, ParseOptions};
use adblock::request::Request;
use adblock::Engine;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    pub name: String,
    pub blocked: bool,
    /// The rule that decided, when adblock-rust reports it.
    pub rule: Option<String>,
    /// An exception rule allowed a name another rule would block.
    pub excepted: bool,
}

pub struct DnsFilter {
    engine: Engine,
    pub rules: usize,
}

/// Plain hosts-file lines ("0.0.0.0 tracker.example") as `||tracker.example^`.
pub fn normalise_line(line: &str) -> Option<String> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') || t.starts_with('!') {
        return None;
    }
    let mut parts = t.split_whitespace();
    let first = parts.next()?;
    if matches!(first, "0.0.0.0" | "127.0.0.1" | "::" | "::1") {
        let host = parts.next()?;
        if host == "localhost" || host.contains('/') || !host.contains('.') {
            return None;
        }
        return Some(format!("||{}^", host.to_ascii_lowercase()));
    }
    Some(t.to_owned())
}

/// A valid DNS name, lower-cased, without the trailing dot.
pub fn clean_name(name: &str) -> Option<String> {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !n.is_empty()
        && n.len() <= 253
        && n.split('.')
            .all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    ok.then_some(n)
}

impl DnsFilter {
    pub fn from_lists<'a>(lists: impl IntoIterator<Item = &'a str>) -> DnsFilter {
        let mut set = FilterSet::new(true);
        let mut rules = 0;
        for list in lists {
            let lines: Vec<String> = list.lines().filter_map(normalise_line).collect();
            rules += lines.len();
            set.add_filter_list(lines.join("\n"), ParseOptions::default());
        }
        DnsFilter {
            engine: Engine::new_with_filter_set(set),
            rules,
        }
    }

    pub fn check(&self, name: &str) -> Verdict {
        let Some(name) = clean_name(name) else {
            return Verdict {
                name: name.to_owned(),
                blocked: false,
                rule: None,
                excepted: false,
            };
        };
        let url = format!("https://{name}/");
        // First-party "document" request: rules that only apply to third-party or
        // sub-resource loads don't fire, so only whole-host rules decide.
        let Ok(request) = Request::new(&url, &url, "document", "GET") else {
            return Verdict {
                name,
                blocked: false,
                rule: None,
                excepted: false,
            };
        };
        let result = self.engine.check_network_request(&request);
        let blocked = result.should_block();
        let rule = if blocked {
            result.filter.as_ref()
        } else {
            result.exception.as_ref()
        }
        .and_then(|f| f.raw_line.clone());
        Verdict {
            name,
            blocked,
            rule,
            excepted: !blocked && result.filter.is_some() && result.exception.is_some(),
        }
    }
}
