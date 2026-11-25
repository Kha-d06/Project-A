//! One file in, one report out.

use serde::Serialize;

use crate::bundle::Bundle;
use crate::features::{self, RawFeatures};
use crate::model::Model;

pub const REPORT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Indicator {
    pub id: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Signature {
    pub rule: String,
    pub namespace: String,
    /// "malicious", "suspicious" or "info", from the rule's name prefix or meta.
    pub level: &'static str,
    pub description: Option<String>,
    pub author: Option<String>,
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ModelResult {
    pub name: String,
    pub score: f64,
    pub threshold: f64,
    pub suspicious: bool,
    pub fpr: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub version: u32,
    pub size: u64,
    pub sha256: String,
    pub format: String,
    pub bundle_version: Option<String>,
    pub signatures: Vec<Signature>,
    pub model: Option<ModelResult>,
    pub indicators: Vec<Indicator>,
    /// What this scan could not do, in plain words.
    pub limitations: Vec<String>,
    /// "known_malicious" (signatures only), "suspicious" or "no_findings".
    pub verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<RawFeatures>,
}

/// What a loaded, verified bundle gives the scanner.
pub struct Engine {
    pub bundle_version: Option<String>,
    #[cfg(feature = "yara")]
    pub rules: Option<yara_x::Rules>,
    pub model: Option<Model>,
    pub limitations: Vec<String>,
}

impl Engine {
    pub fn empty(reason: impl Into<String>) -> Engine {
        Engine {
            bundle_version: None,
            #[cfg(feature = "yara")]
            rules: None,
            model: None,
            limitations: vec![reason.into()],
        }
    }

    pub fn from_bundle(bundle: &Bundle) -> Engine {
        let mut engine = Engine::empty("");
        engine.limitations.clear();
        engine.bundle_version = Some(bundle.manifest.version.clone());
        #[cfg(feature = "yara")]
        {
            let files = bundle.rule_files();
            if files.is_empty() {
                engine.limitations.push("The rule bundle has no YARA rules.".into());
            } else {
                match compile(bundle, &files) {
                    Ok(rules) => engine.rules = Some(rules),
                    Err(e) => engine.limitations.push(format!("The YARA rules could not be compiled: {e}")),
                }
            }
        }
        #[cfg(not(feature = "yara"))]
        engine.limitations.push("This build has no YARA engine.".into());
        match bundle
            .manifest
            .files
            .contains_key("model.json")
            .then(|| bundle.read("model.json").and_then(|b| Model::parse(&b)))
        {
            Some(Ok(m)) => engine.model = Some(m),
            Some(Err(e)) => engine.limitations.push(format!("The model could not be loaded: {e}")),
            None => engine
                .limitations
                .push("The bundle has no model, so there is no machine-learning opinion.".into()),
        }
        engine
    }
}

#[cfg(feature = "yara")]
fn compile(bundle: &Bundle, files: &[String]) -> Result<yara_x::Rules, String> {
    let mut compiler = yara_x::Compiler::new();
    for name in files {
        let bytes = bundle.read(name)?;
        let src = String::from_utf8(bytes).map_err(|_| format!("{name} is not UTF-8"))?;
        let ns = name
            .trim_start_matches("rules/")
            .trim_end_matches(".yara")
            .trim_end_matches(".yar")
            .replace(['/', '.', '-'], "_");
        compiler.new_namespace(&ns);
        compiler.add_source(src.as_str()).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(compiler.build())
}

pub fn level_for(rule: &str, score: Option<i64>) -> &'static str {
    let upper = rule.to_ascii_uppercase();
    if upper.starts_with("MAL_") || upper.starts_with("APT_") || score.is_some_and(|s| s >= 80) {
        "malicious"
    } else if upper.starts_with("INFO_") || upper.starts_with("GEN_INFO") {
        "info"
    } else {
        "suspicious"
    }
}

#[cfg(feature = "yara")]
fn signatures(rules: &yara_x::Rules, bytes: &[u8], limitations: &mut Vec<String>) -> Vec<Signature> {
    use yara_x::MetaValue;
    let mut scanner = yara_x::Scanner::new(rules);
    scanner.set_timeout(std::time::Duration::from_secs(20));
    let results = match scanner.scan(bytes) {
        Ok(r) => r,
        Err(e) => {
            limitations.push(format!("The YARA scan stopped early: {e}"));
            return vec![];
        }
    };
    results
        .matching_rules()
        .map(|r| {
            let meta_str = |key: &str| {
                r.metadata().find(|(k, _)| *k == key).and_then(|(_, v)| match v {
                    MetaValue::String(s) => Some(s.chars().take(300).collect::<String>()),
                    _ => None,
                })
            };
            let score = r.metadata().find(|(k, _)| *k == "score").and_then(|(_, v)| match v {
                MetaValue::Integer(i) => Some(i),
                _ => None,
            });
            Signature {
                rule: r.identifier().to_string(),
                namespace: r.namespace().to_string(),
                level: level_for(r.identifier(), score),
                description: meta_str("description"),
                author: meta_str("author"),
                reference: meta_str("reference"),
            }
        })
        .collect()
}

pub fn indicators(raw: &RawFeatures) -> Vec<Indicator> {
    let mut out = vec![];
    if let Some(e) = &raw.parse_error {
        out.push(Indicator {
            id: "malformed_header",
            detail: format!("The file claims to be a program but its headers don't parse ({e})."),
        });
    }
    for s in &raw.sections {
        if s.executable && s.writable {
            out.push(Indicator {
                id: "writable_code",
                detail: format!(
                    "Section {:?} is both writable and executable, common in packed or self-modifying code.",
                    s.name
                ),
            });
        }
        if s.executable && s.entropy > 7.2 && s.size >= 4096 {
            out.push(Indicator {
                id: "packed_code",
                detail: format!(
                    "Code section {:?} looks compressed or encrypted (entropy {:.2} of 8).",
                    s.name, s.entropy
                ),
            });
        }
    }
    if raw.format == "pe" && raw.imports.is_empty() && !raw.sections.is_empty() {
        out.push(Indicator {
            id: "no_imports",
            detail: "The program imports no functions, so it resolves them itself at run time, as packers do.".into(),
        });
    }
    if raw.format == "pe" && !raw.entry_section.is_empty() && !matches!(raw.entry_section.as_str(), ".text" | "CODE" | ".code" | "text") {
        out.push(Indicator {
            id: "unusual_entry",
            detail: format!("The program starts in section {:?}, not its code section.", raw.entry_section),
        });
    }
    if raw.format == "pe" && raw.has_tls {
        out.push(Indicator {
            id: "tls_callbacks",
            detail: "The program has TLS callbacks, which can run before its main code.".into(),
        });
    }
    out
}

pub fn scan(bytes: &[u8], engine: &Engine, with_features: bool) -> Report {
    let raw = features::extract(bytes);
    let mut limitations = engine.limitations.clone();
    #[cfg(feature = "yara")]
    let signatures = engine
        .rules
        .as_ref()
        .map(|r| signatures(r, bytes, &mut limitations))
        .unwrap_or_default();
    #[cfg(not(feature = "yara"))]
    let signatures: Vec<Signature> = vec![];
    let model = match &engine.model {
        Some(m) if m.applies_to(&raw.format) => {
            let score = m.score(&features::vectorize(&raw));
            Some(ModelResult {
                name: m.name.clone(),
                score,
                threshold: m.threshold,
                suspicious: score >= m.threshold,
                fpr: m.fpr,
            })
        }
        Some(m) => {
            limitations.push(format!(
                "The model was trained on {} files only, so it gave no opinion on this {} file.",
                m.formats.join(", "),
                raw.format
            ));
            None
        }
        None => None,
    };
    let indicators = indicators(&raw);
    let verdict = if signatures.iter().any(|s| s.level == "malicious") {
        "known_malicious"
    } else if signatures.iter().any(|s| s.level == "suspicious") || model.as_ref().is_some_and(|m| m.suspicious) {
        "suspicious"
    } else {
        "no_findings"
    };
    Report {
        version: REPORT_VERSION,
        size: bytes.len() as u64,
        sha256: crate::bundle::sha256_hex(bytes),
        format: raw.format.clone(),
        bundle_version: engine.bundle_version.clone(),
        signatures,
        model,
        indicators,
        limitations,
        verdict,
        features: with_features.then_some(raw),
    }
}
