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
        // A fresh random name every time the service starts, published in a file only this
        // user can read, so another user can't create the pipe first. If the file is
        // missing the service isn't running; the name below then fails to connect (and
        // `check_pipe_server` would refuse a stranger's pipe anyway).
        return std::fs::read_to_string(data_dir().join("ipc-endpoint"))
            .ok()
            .and_then(|contents| parse_endpoint_file(&contents))
            .unwrap_or_else(|| PathBuf::from(r"\\.\pipe\qalaa-daemon-not-running"));
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

/// The pipe name in the service's endpoint file, if it is one the service could have
/// written: `\\.\pipe\qalaa-daemon-<user>-<32 hex>` and nothing else.
pub fn parse_endpoint_file(contents: &str) -> Option<PathBuf> {
    const PREFIX: &str = r"\\.\pipe\qalaa-daemon-";
    let name = contents.trim();
    let rest = name.strip_prefix(PREFIX)?;
    let (user, random) = rest.rsplit_once('-')?;
    let user_ok = user.len() <= 64 && user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    let random_ok = random.len() == 32 && random.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    (user_ok && random_ok).then(|| PathBuf::from(name))
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

#[cfg(test)]
mod tests {
    use super::parse_endpoint_file;

    #[test]
    fn accepts_only_a_name_the_service_could_have_written() {
        let good = format!(r"\\.\pipe\qalaa-daemon-Sara_K-{}", "0a".repeat(16));
        assert_eq!(
            parse_endpoint_file(&format!("{good}\r\n")).as_deref(),
            Some(std::path::Path::new(&good))
        );
        for bad in [
            r"\\.\pipe\qalaa-daemon-Sara".to_owned(),
            format!(r"\\.\pipe\other-{}", "a".repeat(32)),
            format!(r"\\.\pipe\qalaa-daemon-Sara-{}", "A".repeat(32)),
            format!(r"\\server\pipe\qalaa-daemon-Sara-{}", "a".repeat(32)),
            format!(r"\\.\pipe\qalaa-daemon-Sa ra-{}", "a".repeat(32)),
            String::new(),
        ] {
            assert_eq!(parse_endpoint_file(&bad), None, "{bad}");
        }
    }
}
