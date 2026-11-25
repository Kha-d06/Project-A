//! Caps the scanner applies to itself before it reads a file.
//!
//! The parent (the daemon) also kills it after a wall-clock timeout, so a
//! parser stuck in a loop or blocked can't hold a scan up. On Windows there
//! are no rlimits; the parent's timeout and output cap are the limits there
//! (a Job Object memory cap is planned with the Windows service).

use serde::Serialize;

#[derive(Debug, Clone, Copy)]
pub struct Caps {
    pub memory_mb: u64,
    pub cpu_seconds: u64,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            memory_mb: 1024,
            cpu_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Applied {
    pub memory: bool,
    pub cpu: bool,
    pub no_writes: bool,
    pub no_new_privileges: bool,
}

#[cfg(unix)]
fn set(resource: libc::c_int, value: u64) -> bool {
    let lim = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: setrlimit reads a valid, initialised struct.
    unsafe { libc::setrlimit(resource as _, &lim) == 0 }
}

#[cfg(unix)]
pub fn apply(caps: Caps) -> Applied {
    let bytes = caps.memory_mb.saturating_mul(1024 * 1024);
    // RLIMIT_DATA counts memory actually made writable, not the large
    // reservations YARA-X's engine maps but never touches (RLIMIT_AS would
    // refuse those). macOS doesn't enforce RLIMIT_DATA; there the parent's
    // timeout is the limit.
    let memory = cfg!(target_os = "linux") && set(libc::RLIMIT_DATA as _, bytes);
    let cpu = set(libc::RLIMIT_CPU as _, caps.cpu_seconds);
    let no_writes = set(libc::RLIMIT_FSIZE as _, 0);
    set(libc::RLIMIT_CORE as _, 0);
    #[cfg(target_os = "linux")]
    // SAFETY: plain prctl with integer arguments.
    let no_new_privileges = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 };
    #[cfg(not(target_os = "linux"))]
    let no_new_privileges = false;
    Applied {
        memory,
        cpu,
        no_writes,
        no_new_privileges,
    }
}

#[cfg(not(unix))]
pub fn apply(_caps: Caps) -> Applied {
    Applied::default()
}
