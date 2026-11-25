//! The binary as the daemon runs it.
use std::process::Command;

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_qalaa-scan")).args(args).output().expect("run");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn scans_files_one_json_line_each() {
    let dir = std::env::temp_dir().join(format!("qalaa-scan-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let a = dir.join("a.txt");
    std::fs::write(&a, b"hello").expect("write");
    let missing = dir.join("missing.bin");
    let (code, out) = run(&["scan", a.to_str().expect("utf8"), missing.to_str().expect("utf8")]);
    assert_eq!(code, 0);
    let lines: Vec<serde_json::Value> = out.lines().map(|l| serde_json::from_str(l).expect("json")).collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["verdict"], "no_findings");
    assert!(lines[0]["limitations"][0].as_str().expect("str").contains("No rule bundle"));
    assert!(lines[1]["error"].is_string());
    if cfg!(target_os = "linux") {
        assert_eq!(lines[0]["caps"]["memory"], true);
        assert_eq!(lines[0]["caps"]["cpu"], true);
        assert_eq!(lines[0]["caps"]["no_new_privileges"], true);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn refuses_files_over_the_size_cap() {
    let p = std::env::temp_dir().join(format!("qalaa-scan-big-{}", std::process::id()));
    std::fs::write(&p, vec![0u8; 2 * 1024 * 1024]).expect("write");
    let (_, out) = run(&["scan", "--max-mb", "1", p.to_str().expect("utf8")]);
    assert!(out.contains("larger than 1 MB"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn an_unsigned_bundle_loads_nothing() {
    let dir = std::env::temp_dir().join(format!("qalaa-scan-unsigned-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(dir.join("manifest.json"), br#"{"format":1,"version":"x","files":{}}"#).expect("write");
    let (code, out) = run(&["verify", dir.to_str().expect("utf8")]);
    assert_eq!(code, 1);
    assert!(out.contains("\"ok\":false"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lists_the_pinned_keys() {
    let (code, out) = run(&["keys"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
    assert!(v["keys"].is_array());
}
