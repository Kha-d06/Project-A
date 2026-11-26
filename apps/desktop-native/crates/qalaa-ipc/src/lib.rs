//! Client side of qalaa-ipc, the local protocol between Qalaa's background
//! service (`apps/desktop/src/daemon.ts`) and the native interface.
//!
//! Newline-delimited JSON over a Unix domain socket or a Windows named pipe.
//! The first request must be `hello` with the token from a file only this user
//! can read. The types here mirror `apps/desktop/src/core/home.ts`; the shared
//! fixture in `tests/fixtures/home.json` is checked by both test suites.

mod client;
mod paths;
mod types;

#[cfg(unix)]
pub use client::check_private_socket_for;
pub use client::{check_private_socket, parse_message, Client, Event, IpcError, Message, Stream};
pub use paths::{data_dir, endpoint, token_file};
pub use types::*;

/// Protocol version spoken by this client.
pub const PROTOCOL_VERSION: u32 = 1;
