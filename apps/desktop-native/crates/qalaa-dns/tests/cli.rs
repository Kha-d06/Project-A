use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn serves_one_verdict_per_line() {
    let dir = std::env::temp_dir().join(format!("qalaa-dns-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let list = dir.join("list.txt");
    std::fs::write(&list, "||ads.example^\n").expect("write");
    let mut child = Command::new(env!("CARGO_BIN_EXE_qalaa-dns"))
        .args(["serve", list.to_str().expect("utf8")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let ready: serde_json::Value = serde_json::from_str(&lines.next().expect("line").expect("read")).expect("json");
    assert_eq!(ready["ready"], true);
    writeln!(stdin, "ads.example\nsafe-ish.example").expect("write");
    let a: serde_json::Value = serde_json::from_str(&lines.next().expect("line").expect("read")).expect("json");
    let b: serde_json::Value = serde_json::from_str(&lines.next().expect("line").expect("read")).expect("json");
    assert_eq!(a["blocked"], true);
    assert_eq!(b["blocked"], false);
    drop(stdin);
    assert!(child.wait().expect("wait").success());
    let _ = std::fs::remove_dir_all(&dir);
}
