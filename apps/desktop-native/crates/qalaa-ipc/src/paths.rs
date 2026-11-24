//! Where the service listens; mirrors `apps/desktop/src/core/paths.ts`.
use std::env;
use std::path::PathBuf;

const APP: &str = "Qalaa Desktop";

fn home() -> PathBuf {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// The data folder shared with the service.
pub fn data_dir() -> PathBuf {
    if let Some(dir) = env::var_os("QALAA_DATA_DIR").or_else(|| env::var_os("SENTINEL_DESKTOP_PROFILE")) {
        return PathBuf::from(dir);
    }
    if cfg!(windows) {
        env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join("AppData").join("Roaming"))
            .join(APP)
    } else if cfg!(target_os = "macos") {
        home().join("Library").join("Application Support").join(APP)
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".config"))
            .join(APP)
    }
}

pub fn token_file() -> PathBuf {
    data_dir().join("ipc-token")
}

/// The socket path, or the named pipe on Windows.
pub fn endpoint() -> PathBuf {
    if let Some(endpoint) = env::var_os("QALAA_IPC_ENDPOINT") {
        return PathBuf::from(endpoint);
    }
    if cfg!(windows) {
        let user: String = env::var("USERNAME")
            .unwrap_or_default()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        return PathBuf::from(format!(r"\\.\pipe\qalaa-daemon-{user}"));
    }
    if cfg!(target_os = "macos") {
        return data_dir().join("daemon.sock");
    }
    let runtime = env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(|| {
        // Same fallback as the service: a per-user folder in the temp dir.
        env::temp_dir().join(format!("qalaa-{}", unix_uid()))
    });
    runtime.join("qalaa").join("daemon.sock")
}

#[cfg(unix)]
fn unix_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(0)
}

#[cfg(not(unix))]
fn unix_uid() -> u32 {
    0
}
