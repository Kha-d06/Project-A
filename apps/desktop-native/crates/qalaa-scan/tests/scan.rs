use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use qalaa_scan::bundle::{parse_keys, safe_relative, sha256_hex, to_hex, Bundle, FileEntry, Manifest};
use qalaa_scan::features::{self, VECTOR_LEN};
use qalaa_scan::model::Model;
use qalaa_scan::scan::{level_for, scan, Engine};

const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn keys_for(k: &SigningKey) -> Vec<ed25519_dalek::VerifyingKey> {
    parse_keys(&format!("# test\n{}\n", to_hex(k.verifying_key().as_bytes())))
}

/// Writes files and a manifest signed by `k`; returns the folder.
fn make_bundle(dir: &Path, k: &SigningKey, files: &[(&str, &[u8])]) {
    let mut listed = BTreeMap::new();
    for (name, data) in files {
        let p = dir.join(name);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::fs::write(&p, data).expect("write");
        listed.insert(
            name.to_string(),
            FileEntry {
                sha256: sha256_hex(data),
                size: data.len() as u64,
            },
        );
    }
    let manifest = Manifest {
        format: 1,
        version: "2026.11.25.1".into(),
        created: "2026-11-25T00:00:00Z".into(),
        files: listed,
    };
    let bytes = serde_json::to_vec(&manifest).expect("json");
    std::fs::write(dir.join("manifest.json"), &bytes).expect("write");
    std::fs::write(dir.join("manifest.sig"), b64(&k.sign(&bytes).to_bytes())).expect("write");
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("qalaa-scan-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

const RULES: &str = r#"
rule MAL_EICAR_Test_File { meta: description = "The EICAR test file" author = "Qalaa" strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }
rule SUSP_Powershell_Encoded { meta: description = "Encoded PowerShell" strings: $a = "powershell -enc" nocase condition: $a }
rule INFO_Has_Url { strings: $a = "https://" condition: $a }
"#;

#[test]
fn a_signed_bundle_opens_and_any_change_is_refused() {
    let dir = tmp("bundle");
    let k = key(7);
    make_bundle(&dir, &k, &[("rules/qalaa.yar", RULES.as_bytes())]);
    assert!(Bundle::open(&dir, &keys_for(&k)).is_ok());
    // Another key: refused.
    assert!(Bundle::open(&dir, &keys_for(&key(8))).expect_err("refused").contains("signature"));
    // No pinned key at all: nothing loads.
    assert!(Bundle::open(&dir, &[]).expect_err("refused").contains("no bundle signing key"));
    // A changed rule file: refused.
    std::fs::write(dir.join("rules/qalaa.yar"), "rule x { condition: true }").expect("write");
    assert!(Bundle::open(&dir, &keys_for(&k)).expect_err("refused").contains("doesn't match"));
    // A changed manifest (re-pointed hash) without a new signature: refused.
    make_bundle(&dir, &k, &[("rules/qalaa.yar", RULES.as_bytes())]);
    let m = std::fs::read_to_string(dir.join("manifest.json"))
        .expect("read")
        .replace("2026.11.25.1", "2026.11.25.2");
    std::fs::write(dir.join("manifest.json"), m).expect("write");
    assert!(Bundle::open(&dir, &keys_for(&k)).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn paths_that_could_leave_the_bundle_are_refused() {
    for bad in ["../x.yar", "/etc/passwd", "rules\\x.yar", "", "a/../../b", "./x"] {
        assert!(safe_relative(bad).is_none(), "{bad}");
    }
    assert!(safe_relative("rules/qalaa.yar").is_some());
    let dir = tmp("escape");
    let k = key(7);
    make_bundle(&dir, &k, &[("rules/ok.yar", b"rule a { condition: false }")]);
    let m = std::fs::read_to_string(dir.join("manifest.json"))
        .expect("read")
        .replace("rules/ok.yar", "../ok.yar");
    std::fs::write(dir.join("manifest.json"), &m).expect("write");
    std::fs::write(dir.join("manifest.sig"), b64(&k.sign(m.as_bytes()).to_bytes())).expect("write");
    assert!(Bundle::open(&dir, &keys_for(&k)).expect_err("refused").contains("unsafe path"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rule_levels_follow_the_name_prefix_and_score() {
    assert_eq!(level_for("MAL_Something", None), "malicious");
    assert_eq!(level_for("SUSP_Thing", None), "suspicious");
    assert_eq!(level_for("HKTL_Mimikatz", None), "suspicious");
    assert_eq!(level_for("INFO_Url", None), "info");
    assert_eq!(level_for("Custom", Some(90)), "malicious");
}

#[cfg(feature = "yara")]
#[test]
fn yara_rules_from_a_bundle_decide_the_verdict() {
    let dir = tmp("yara");
    let k = key(7);
    make_bundle(&dir, &k, &[("rules/qalaa.yar", RULES.as_bytes())]);
    let engine = Engine::from_bundle(&Bundle::open(&dir, &keys_for(&k)).expect("bundle"));
    let r = scan(EICAR, &engine, false);
    assert_eq!(r.verdict, "known_malicious");
    assert_eq!(r.signatures[0].rule, "MAL_EICAR_Test_File");
    assert_eq!(r.signatures[0].description.as_deref(), Some("The EICAR test file"));
    assert_eq!(scan(b"run: POWERSHELL -ENC aGk=", &engine, false).verdict, "suspicious");
    assert_eq!(scan(b"see https://example.org", &engine, false).verdict, "no_findings");
    assert_eq!(r.bundle_version.as_deref(), Some("2026.11.25.1"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn without_a_bundle_the_report_says_what_it_could_not_do() {
    let r = scan(EICAR, &Engine::empty("No rule bundle was given."), false);
    assert_eq!(r.verdict, "no_findings");
    assert!(r.limitations.iter().any(|l| l.contains("No rule bundle")));
    assert_eq!(r.sha256, sha256_hex(EICAR));
}

fn tiny_model(trees: serde_json::Value, formats: &[&str]) -> serde_json::Value {
    serde_json::json!({ "format": 1, "feature_version": features::FEATURE_VERSION, "feature_len": VECTOR_LEN, "formats": formats,
        "base": 0.0, "threshold": 0.8, "fpr": 0.01, "name": "test", "trees": trees })
}

#[test]
fn the_tree_model_evaluates_and_rejects_malformed_trees() {
    // feature 0 is the share of 0x00 bytes: mostly-zero files go right (+3), others left (-3).
    let m = Model::parse(
        &serde_json::to_vec(&tiny_model(
            serde_json::json!([{ "nodes": [
        { "f": 0, "t": 0.5, "l": 1, "r": 2, "d": true }, { "leaf": -3.0 }, { "leaf": 3.0 } ] }]),
            &["pe", "elf", "other"],
        ))
        .expect("json"),
    )
    .expect("valid");
    let zeros = features::vectorize(&features::extract(&[0u8; 4096]));
    let text = features::vectorize(&features::extract(b"hello world, nothing to see"));
    assert!(m.score(&zeros) > 0.9 && m.score(&text) < 0.1);
    let mut nan = text.clone();
    nan[0] = f64::NAN;
    assert!(m.score(&nan) < 0.1, "missing values follow the default branch");

    for bad in [
        serde_json::json!([{ "nodes": [{ "f": 0, "t": 0.5, "l": 0, "r": 0 }] }]), // loops onto itself
        serde_json::json!([{ "nodes": [{ "f": 0, "t": 0.5, "l": 1, "r": 9 }, { "leaf": 1 }] }]), // out of range
        serde_json::json!([{ "nodes": [{ "f": 999999, "t": 0.5, "l": 1, "r": 2 }, { "leaf": 1 }, { "leaf": 1 }] }]),
        serde_json::json!([{ "nodes": [] }]),
    ] {
        assert!(Model::parse(&serde_json::to_vec(&tiny_model(bad, &["pe"])).expect("json")).is_err());
    }
    let mut wrong_layout = tiny_model(serde_json::json!([{ "nodes": [{ "leaf": 1 }] }]), &["pe"]);
    wrong_layout["feature_len"] = serde_json::json!(10);
    assert!(Model::parse(&serde_json::to_vec(&wrong_layout).expect("json")).is_err());
}

#[test]
fn the_model_only_ever_says_suspicious_and_only_for_formats_it_knows() {
    let dir = tmp("model");
    let k = key(7);
    let model = serde_json::to_vec(&tiny_model(serde_json::json!([{ "nodes": [{ "leaf": 5.0 }] }]), &["pe"])).expect("json");
    make_bundle(&dir, &k, &[("model.json", &model)]);
    let engine = Engine::from_bundle(&Bundle::open(&dir, &keys_for(&k)).expect("bundle"));
    let pe = minimal_pe();
    let r = scan(&pe, &engine, false);
    assert_eq!(r.format, "pe");
    assert!(r.model.as_ref().is_some_and(|m| m.suspicious));
    assert_eq!(r.verdict, "suspicious");
    let other = scan(b"plain text", &engine, false);
    assert!(other.model.is_none());
    assert!(other.limitations.iter().any(|l| l.contains("trained on pe files only")));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A tiny, valid PE32 with one writable+executable, high-entropy section and no imports.
fn minimal_pe() -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let pe = 0x80;
    b[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    b[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes()); // i386
    b[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // one section
    b[coff + 16..coff + 18].copy_from_slice(&224u16.to_le_bytes()); // optional header size
    b[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());
    let opt = coff + 20;
    b[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32
    b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
    b[opt + 28..opt + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // image base
    b[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
    b[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
    b[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
    b[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
    b[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes()); // GUI
    b[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // data directories
    let sec = opt + 224;
    b[sec..sec + 8].copy_from_slice(b"UPX0\0\0\0\0");
    b[sec + 8..sec + 12].copy_from_slice(&0x2000u32.to_le_bytes()); // virtual size
    b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
    b[sec + 16..sec + 20].copy_from_slice(&0x2000u32.to_le_bytes()); // raw size
    b[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw pointer
    b[sec + 36..sec + 40].copy_from_slice(&0xE000_0020u32.to_le_bytes()); // code, R, W, X
                                                                          // 8 KB of pseudo-random bytes: looks packed.
    let mut x: u32 = 0x1234_5678;
    for _ in 0..0x2000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        b.push(x as u8);
    }
    b
}

#[test]
fn pe_features_and_indicators_come_from_the_headers() {
    let raw = features::extract(&minimal_pe());
    assert_eq!(raw.format, "pe", "{:?}", raw.parse_error);
    assert_eq!(raw.header.machine, "I386");
    assert_eq!(raw.sections.len(), 1);
    assert_eq!(raw.entry_section, "UPX0");
    assert!(raw.sections[0].entropy > 7.5 && raw.sections[0].executable && raw.sections[0].writable);
    let ids: Vec<&str> = qalaa_scan::scan::indicators(&raw).iter().map(|i| i.id).collect();
    for want in ["writable_code", "packed_code", "no_imports", "unusual_entry"] {
        assert!(ids.contains(&want), "{want} in {ids:?}");
    }
    assert_eq!(features::vectorize(&raw).len(), VECTOR_LEN);
}

#[test]
fn a_truncated_program_is_reported_not_crashed_on() {
    let mut pe = minimal_pe();
    pe.truncate(0x90);
    let raw = features::extract(&pe);
    assert!(raw.parse_error.is_some());
    assert!(qalaa_scan::scan::indicators(&raw).iter().any(|i| i.id == "malformed_header"));
    // Random garbage of every small length never panics.
    for n in 0..300 {
        let junk: Vec<u8> = (0..n).map(|i| (i * 37 % 251) as u8).collect();
        let mut with_mz = b"MZ".to_vec();
        with_mz.extend(&junk);
        let _ = features::vectorize(&features::extract(&junk));
        let _ = features::vectorize(&features::extract(&with_mz));
    }
}

#[test]
fn this_platforms_own_executables_parse() {
    let exe = std::fs::read(std::env::current_exe().expect("exe")).expect("read");
    let raw = features::extract(&exe);
    let want = if cfg!(windows) {
        "pe"
    } else if cfg!(target_os = "macos") {
        "macho"
    } else {
        "elf"
    };
    assert_eq!(raw.format, want);
    assert!(raw.sections.iter().any(|s| s.executable));
    assert!(!raw.imports.is_empty());
}

#[test]
fn byte_statistics_are_normalised() {
    let h = features::byte_histogram(b"aab");
    assert!((h[b'a' as usize] - 2.0 / 3.0).abs() < 1e-12);
    let e = features::byte_entropy_histogram(&vec![7u8; 10_000]);
    assert!((e.iter().sum::<f64>() - 1.0).abs() < 1e-9);
    assert_eq!(features::entropy(&[]), 0.0);
    assert!((features::entropy(&(0..=255).collect::<Vec<u8>>()) - 8.0).abs() < 1e-9);
    let s = features::strings(b"\x00hello\x00C:\\Windows\\x.exe\x00https://a.example\x00HKEY_LOCAL_MACHINE\x00ab\x00");
    assert_eq!((s.count, s.paths, s.urls, s.registry), (4, 1, 1, 1));
    assert_eq!(features::fnv1a(""), 0x811c_9dc5);
    assert_eq!(features::fnv1a("a"), 0xe40c_292c);
}

#[test]
fn vectors_match_the_training_scripts() {
    // Written by tools/scan-model/vectorize.py from the same raw features.
    let fixture: serde_json::Value = serde_json::from_str(include_str!("fixtures/vector-parity.json")).expect("fixture");
    let raw: features::RawFeatures = serde_json::from_value(fixture["raw"].clone()).expect("raw");
    let want: Vec<f64> = serde_json::from_value(fixture["vector"].clone()).expect("vector");
    let got = features::vectorize(&raw);
    assert_eq!(got.len(), want.len());
    for (i, (a, b)) in got.iter().zip(&want).enumerate() {
        assert!((a - b).abs() <= 1e-9 * a.abs().max(1.0), "feature {i}: {a} vs {b}");
    }
}

/// YARA-X must still work with the memory and CPU caps in place (its engine
/// reserves large address ranges, which is why the cap is RLIMIT_DATA).
#[cfg(all(feature = "yara", target_os = "linux"))]
#[test]
fn yara_scans_work_under_the_caps() {
    if std::env::var_os("QALAA_CAPPED_CHILD").is_some() {
        let dir = tmp("capped");
        let k = key(7);
        make_bundle(&dir, &k, &[("rules/qalaa.yar", RULES.as_bytes())]);
        let engine = Engine::from_bundle(&Bundle::open(&dir, &keys_for(&k)).expect("bundle"));
        let applied = qalaa_scan::limits::apply(qalaa_scan::limits::Caps {
            memory_mb: 512,
            cpu_seconds: 20,
        });
        assert!(applied.memory && applied.cpu);
        assert_eq!(scan(EICAR, &engine, false).verdict, "known_malicious");
        // A runaway allocation is stopped by the cap.
        let grabbed = std::panic::catch_unwind(|| {
            let mut v: Vec<Vec<u8>> = vec![];
            for _ in 0..64 {
                let mut chunk = Vec::new();
                if chunk.try_reserve_exact(64 << 20).is_err() {
                    return false;
                }
                chunk.resize(64 << 20, 1u8);
                v.push(chunk);
            }
            true
        });
        assert_eq!(grabbed.ok(), Some(false), "4 GB was allocated under a 512 MB cap");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let status = std::process::Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", "yara_scans_work_under_the_caps", "--test-threads=1"])
        .env("QALAA_CAPPED_CHILD", "1")
        .status()
        .expect("child");
    assert!(status.success());
}

/// tests/fixtures/py-bundle was written by tools/scan-bundle/build_bundle.py with
/// the test key (seed 7): what the signing tool makes, the scanner accepts.
#[test]
fn bundles_signed_by_the_python_tool_verify() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/py-bundle");
    let bundle = Bundle::open(&dir, &keys_for(&key(7))).expect("python-signed bundle");
    assert_eq!(bundle.rule_files(), vec!["rules/eicar.yar".to_string()]);
    assert!(Bundle::open(&dir, &keys_for(&key(9))).is_err());
}

/// Written by tools/scan-model/train.py's converter from a LightGBM dump.
#[test]
fn models_from_the_training_converter_load() {
    let m = Model::parse(include_bytes!("fixtures/model-from-lightgbm.json")).expect("converted model");
    let zeros = features::vectorize(&features::extract(&[0u8; 1024]));
    assert!(m.score(&zeros) > 0.8);
}
