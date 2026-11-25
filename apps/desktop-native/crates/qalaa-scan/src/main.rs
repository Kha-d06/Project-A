use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use qalaa_scan::bundle::{pinned_keys, Bundle};
use qalaa_scan::features;
use qalaa_scan::limits::{self, Caps};
use qalaa_scan::scan::{scan, Engine};

const USAGE: &str = "usage:
  qalaa-scan scan [--bundle DIR] [--features] [--max-mb N] [--memory-mb N] [--cpu-seconds N] FILE...
  qalaa-scan verify DIR
  qalaa-scan features FILE
  qalaa-scan keys";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("scan") => run_scan(&args[1..]),
        Some("verify") if args.len() == 2 => match Bundle::open(&PathBuf::from(&args[1]), &pinned_keys()) {
            Ok(b) => {
                println!(
                    "{}",
                    serde_json::json!({ "ok": true, "version": b.manifest.version, "files": b.manifest.files.len() })
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                println!("{}", serde_json::json!({ "ok": false, "error": e }));
                ExitCode::from(1)
            }
        },
        Some("keys") => {
            let keys: Vec<String> = pinned_keys().iter().map(|k| qalaa_scan::bundle::to_hex(k.as_bytes())).collect();
            println!("{}", serde_json::json!({ "keys": keys }));
            ExitCode::SUCCESS
        }
        Some("features") if args.len() == 2 => {
            limits::apply(Caps::default());
            match std::fs::read(&args[1]) {
                Ok(bytes) => {
                    let raw = features::extract(&bytes);
                    let vector = features::vectorize(&raw);
                    println!("{}", serde_json::json!({ "raw": raw, "vector": vector }));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(2)
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run_scan(args: &[String]) -> ExitCode {
    let mut bundle_dir: Option<PathBuf> = None;
    let mut with_features = false;
    let mut max_mb: u64 = 128;
    let mut caps = Caps::default();
    let mut files: Vec<PathBuf> = vec![];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let num = |it: &mut std::slice::Iter<String>| it.next().and_then(|v| v.parse::<u64>().ok());
        match a.as_str() {
            "--bundle" => bundle_dir = it.next().map(PathBuf::from),
            "--features" => with_features = true,
            "--max-mb" => max_mb = num(&mut it).unwrap_or(max_mb),
            "--memory-mb" => caps.memory_mb = num(&mut it).unwrap_or(caps.memory_mb),
            "--cpu-seconds" => caps.cpu_seconds = num(&mut it).unwrap_or(caps.cpu_seconds),
            "--" => files.extend(it.by_ref().map(PathBuf::from)),
            f => files.push(PathBuf::from(f)),
        }
    }
    if files.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    // The bundle is verified and compiled before the caps: its rules are trusted, the files to scan are not.
    let engine = match bundle_dir {
        Some(dir) => match Bundle::open(&dir, &pinned_keys()) {
            Ok(b) => Engine::from_bundle(&b),
            Err(e) => Engine::empty(format!("No rules or model were loaded: {e}.")),
        },
        None => Engine::empty("No rule bundle was given, so only built-in checks ran."),
    };
    let applied = limits::apply(caps);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for path in files {
        let line = match read_capped(&path, max_mb) {
            Ok(bytes) => {
                let mut report = serde_json::to_value(scan(&bytes, &engine, with_features)).unwrap_or_default();
                report["path"] = serde_json::Value::String(path.display().to_string());
                report["caps"] = serde_json::to_value(&applied).unwrap_or_default();
                report
            }
            Err(e) => serde_json::json!({ "path": path.display().to_string(), "error": e }),
        };
        if writeln!(out, "{line}").is_err() {
            return ExitCode::from(3);
        }
    }
    ExitCode::SUCCESS
}

fn read_capped(path: &PathBuf, max_mb: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    let cap = max_mb.saturating_mul(1024 * 1024);
    if meta.len() > cap {
        return Err(format!("larger than {max_mb} MB, so it wasn't scanned here"));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(cap + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}
