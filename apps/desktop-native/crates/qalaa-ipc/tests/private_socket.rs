//! The client sends its token only to a socket in a folder no other user controls.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;

use qalaa_ipc::{check_private_socket, check_private_socket_for};

fn temp_root(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("qalaa-ipc-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("qalaa")).expect("dirs");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    std::fs::set_permissions(root.join("qalaa"), std::fs::Permissions::from_mode(0o700)).expect("chmod");
    root
}

#[test]
fn accepts_a_private_socket_and_refuses_open_or_foreign_folders() {
    let root = temp_root("socket");
    let socket = root.join("qalaa").join("daemon.sock");
    let _listener = UnixListener::bind(&socket).expect("bind");
    check_private_socket(&socket).expect("private socket accepted");

    std::fs::set_permissions(root.join("qalaa"), std::fs::Permissions::from_mode(0o755)).expect("chmod");
    assert!(check_private_socket(&socket).is_err(), "folder others can open");
    std::fs::set_permissions(root.join("qalaa"), std::fs::Permissions::from_mode(0o700)).expect("chmod");

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).expect("chmod");
    assert!(check_private_socket(&socket).is_err(), "parent others can write to");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");

    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    assert!(
        check_private_socket_for(&socket, me.wrapping_add(1)).is_err(),
        "someone else's socket"
    );

    let plain = root.join("qalaa").join("not-a-socket");
    std::fs::write(&plain, b"x").expect("file");
    assert!(check_private_socket(&plain).is_err(), "a plain file");
    let _ = std::fs::remove_dir_all(&root);
}
