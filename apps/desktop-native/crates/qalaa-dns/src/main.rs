//! qalaa-dns: answers "is this name blocked?" for Safe DNS.
//!
//!   qalaa-dns serve LIST...   one name per line on stdin, one JSON verdict per line on stdout
//!   qalaa-dns check LIST... -- NAME...
use std::io::{BufRead, Write};
use std::process::ExitCode;

use qalaa_dns::DnsFilter;

const MAX_LIST: u64 = 64 << 20;

fn load(paths: &[String]) -> Result<DnsFilter, String> {
    let mut texts = Vec::new();
    for p in paths {
        let meta = std::fs::metadata(p).map_err(|e| format!("{p}: {e}"))?;
        if meta.len() > MAX_LIST {
            return Err(format!("{p} is larger than 64 MB"));
        }
        texts.push(std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?);
    }
    Ok(DnsFilter::from_lists(texts.iter().map(String::as_str)))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => {
            let filter = match load(&args[1..]) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            if writeln!(out, "{}", serde_json::json!({ "ready": true, "rules": filter.rules })).is_err() || out.flush().is_err() {
                return ExitCode::from(3);
            }
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                let verdict = filter.check(line.get(..300).unwrap_or(&line));
                if writeln!(out, "{}", serde_json::to_string(&verdict).unwrap_or_default()).is_err() || out.flush().is_err() {
                    return ExitCode::from(3);
                }
            }
            ExitCode::SUCCESS
        }
        Some("check") => {
            let split = args.iter().position(|a| a == "--").unwrap_or(args.len());
            let filter = match load(&args[1..split]) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            for name in args.iter().skip(split + 1) {
                println!("{}", serde_json::to_string(&filter.check(name)).unwrap_or_default());
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: qalaa-dns serve LIST... | qalaa-dns check LIST... -- NAME...");
            ExitCode::from(2)
        }
    }
}
