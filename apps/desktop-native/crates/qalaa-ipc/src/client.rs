use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::{Hello, PROTOCOL_VERSION};

/// Longest line accepted from the service.
const MAX_LINE: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum IpcError {
    /// The service isn't running or the socket can't be opened.
    Unavailable(io::Error),
    /// The token was refused, or the token file couldn't be read.
    Unauthorized(String),
    /// The service answered with an error.
    Remote {
        code: String,
        message: String,
    },
    /// The service sent something this client doesn't understand.
    Protocol(String),
    Io(io::Error),
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(e) => write!(f, "the Qalaa background service isn't running ({e})"),
            Self::Unauthorized(m) => write!(f, "not allowed: {m}"),
            Self::Remote { message, .. } => f.write_str(message),
            Self::Protocol(m) => write!(f, "unexpected reply: {m}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IpcError {}

impl From<io::Error> for IpcError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// An event pushed by the service, such as `home.changed`.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub name: String,
    pub payload: Value,
}

/// One line from the service.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Reply { id: u64, result: Result<Value, (String, String)> },
    Event(Event),
}

pub fn parse_message(line: &str) -> Result<Message, IpcError> {
    let value: Value = serde_json::from_str(line).map_err(|e| IpcError::Protocol(e.to_string()))?;
    if let Some(name) = value.get("event").and_then(Value::as_str) {
        return Ok(Message::Event(Event {
            name: name.to_owned(),
            payload: value.get("payload").cloned().unwrap_or(Value::Null),
        }));
    }
    let id = value
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| IpcError::Protocol("missing id".into()))?;
    if let Some(error) = value.get("error") {
        let code = error.get("code").and_then(Value::as_str).unwrap_or("failed").to_owned();
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("The request failed.")
            .to_owned();
        return Ok(Message::Reply {
            id,
            result: Err((code, message)),
        });
    }
    Ok(Message::Reply {
        id,
        result: Ok(value.get("result").cloned().unwrap_or(Value::Null)),
    })
}

/// A connection to the service. Calls are synchronous; events that arrive while
/// waiting for a reply are kept and returned by [`Client::take_events`].
pub struct Client<S: Read + Write> {
    reader: BufReader<S>,
    writer: S,
    next_id: u64,
    events: Vec<Event>,
    pub hello: Option<Hello>,
}

#[cfg(unix)]
pub type Stream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type Stream = std::fs::File;

impl Client<Stream> {
    /// Connects to the service and says hello with the token from `token_file`.
    pub fn connect(endpoint: &Path, token_file: &Path, client_name: &str) -> Result<Self, IpcError> {
        let token = std::fs::read_to_string(token_file).map_err(|e| IpcError::Unauthorized(format!("can't read the token file: {e}")))?;
        // The token goes only to a socket in a folder no other user controls.
        check_private_socket(endpoint).map_err(IpcError::Unavailable)?;
        let stream = open(endpoint).map_err(IpcError::Unavailable)?;
        let writer = stream.try_clone()?;
        let mut client = Client::from_parts(stream, writer);
        client.say_hello(token.trim(), client_name)?;
        Ok(client)
    }
}

/// The socket, its folder and the folder above must not be controlled by another
/// user. Otherwise someone who created the folder first (the temp-dir fallback when
/// XDG_RUNTIME_DIR isn't set) could put their own socket there and collect the
/// token. Mirrors `assertPrivateDir` in the service.
#[cfg(unix)]
pub fn check_private_socket(endpoint: &Path) -> io::Result<()> {
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    check_private_socket_for(endpoint, uid)
}

/// The check, for a given user id (tests pass another one to stand for a stranger).
#[cfg(unix)]
pub fn check_private_socket_for(endpoint: &Path, uid: u32) -> io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let refuse = |why: String| Err(io::Error::new(io::ErrorKind::PermissionDenied, why));
    let socket = std::fs::symlink_metadata(endpoint)?;
    if !socket.file_type().is_socket() {
        return refuse(format!("{} isn't a socket", endpoint.display()));
    }
    if socket.uid() != uid {
        return refuse(format!("{} belongs to another user", endpoint.display()));
    }
    let Some(dir) = endpoint.parent() else { return Ok(()) };
    let folder = std::fs::symlink_metadata(dir)?;
    if !folder.is_dir() || folder.uid() != uid || folder.mode() & 0o077 != 0 {
        return refuse(format!("{} isn't a private folder of this user", dir.display()));
    }
    if let Some(parent) = dir.parent() {
        let above = std::fs::symlink_metadata(parent)?;
        if (above.uid() != uid && above.uid() != 0) || (above.uid() == uid && above.mode() & 0o022 != 0) {
            return refuse(format!("{} can be changed by another user", parent.display()));
        }
    }
    Ok(())
}

/// Windows: named pipes have no folder; the check happens once the pipe is open
/// (`check_pipe_server`), before the token is sent.
#[cfg(windows)]
pub fn check_private_socket(_endpoint: &Path) -> io::Result<()> {
    Ok(())
}

/// The user (SID bytes) a process runs as.
#[cfg(windows)]
fn process_user_sid(process: windows_sys::Win32::Foundation::HANDLE) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is a valid handle; `token` receives a handle we close below.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut needed = 0u32;
    // SAFETY: a size query with no buffer; fails with ERROR_INSUFFICIENT_BUFFER and sets `needed`.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    // u64 storage keeps the buffer aligned for TOKEN_USER.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: the buffer holds at least `needed` bytes.
    let ok = unsafe { GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), needed, &mut needed) };
    // SAFETY: closing the token handle opened above.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points inside the buffer.
    let sid = unsafe { (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid };
    // SAFETY: `sid` is a valid SID for the lifetime of `buffer`.
    let len = unsafe { GetLengthSid(sid) } as usize;
    // SAFETY: `len` bytes starting at `sid` belong to the SID.
    Ok(unsafe { std::slice::from_raw_parts(sid as *const u8, len) }.to_vec())
}

/// The process serving this pipe must run as the same Windows user as this
/// client. Another user can create `\\.\pipe\qalaa-daemon-<name>` before the
/// service starts (pipe names are global); without this check the client would
/// hand that process its token. A server we can't inspect counts as a stranger.
#[cfg(windows)]
pub fn check_pipe_server(pipe: &std::fs::File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let refuse = |why: &str| io::Error::new(io::ErrorKind::PermissionDenied, why.to_owned());
    let mut pid = 0u32;
    // SAFETY: the handle is the open pipe; `pid` receives the server's process id.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as _, &mut pid) } == 0 {
        return Err(refuse("couldn't tell which program serves the Qalaa pipe"));
    }
    // SAFETY: plain query; the handle is closed below.
    let server = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if server.is_null() {
        return Err(refuse("the program serving the Qalaa pipe belongs to another user"));
    }
    let theirs = process_user_sid(server);
    // SAFETY: closing the process handle opened above.
    unsafe { CloseHandle(server) };
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing.
    let mine = process_user_sid(unsafe { GetCurrentProcess() })?;
    match theirs {
        Ok(sid) if sid == mine => Ok(()),
        _ => Err(refuse("the program serving the Qalaa pipe belongs to another user")),
    }
}

#[cfg(unix)]
fn open(endpoint: &Path) -> io::Result<Stream> {
    std::os::unix::net::UnixStream::connect(endpoint)
}

#[cfg(windows)]
fn open(endpoint: &Path) -> io::Result<Stream> {
    let pipe = std::fs::OpenOptions::new().read(true).write(true).open(endpoint)?;
    check_pipe_server(&pipe)?;
    Ok(pipe)
}

impl<S: Read + Write> Client<S> {
    /// Builds a client over any stream; the reading and writing halves may be clones.
    pub fn from_parts(reader: S, writer: S) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            next_id: 1,
            events: Vec::new(),
            hello: None,
        }
    }

    pub fn say_hello(&mut self, token: &str, client_name: &str) -> Result<Hello, IpcError> {
        let reply = self.call_raw("hello", Some(json!({ "token": token, "client": client_name })));
        let hello: Hello = match reply {
            Err(IpcError::Remote { code, message }) if code == "unauthorized" => return Err(IpcError::Unauthorized(message)),
            other => serde_json::from_value(other?).map_err(|e| IpcError::Protocol(e.to_string()))?,
        };
        if hello.protocol != PROTOCOL_VERSION {
            return Err(IpcError::Protocol(format!(
                "the service speaks protocol {}, this app speaks {PROTOCOL_VERSION}",
                hello.protocol
            )));
        }
        self.hello = Some(hello.clone());
        Ok(hello)
    }

    /// Calls a method and decodes its result.
    pub fn call<T: DeserializeOwned>(&mut self, method: &str, params: Option<Value>) -> Result<T, IpcError> {
        let value = self.call_raw(method, params)?;
        serde_json::from_value(value).map_err(|e| IpcError::Protocol(e.to_string()))
    }

    pub fn call_raw(&mut self, method: &str, params: Option<Value>) -> Result<Value, IpcError> {
        let id = self.next_id;
        self.next_id += 1;
        let mut request = json!({ "id": id, "method": method });
        if let Some(params) = params {
            request["params"] = params;
        }
        let mut line = serde_json::to_string(&request).map_err(|e| IpcError::Protocol(e.to_string()))?;
        line.push('\n');
        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()?;
        loop {
            match self.read_message()? {
                Message::Event(event) => self.events.push(event),
                Message::Reply { id: got, result } if got == id => {
                    return result.map_err(|(code, message)| IpcError::Remote { code, message });
                }
                Message::Reply { .. } => continue,
            }
        }
    }

    /// Blocks until the next message. Used by the event-listening thread.
    pub fn read_message(&mut self) -> Result<Message, IpcError> {
        let mut line = String::new();
        loop {
            line.clear();
            let read = (&mut self.reader).take(MAX_LINE as u64).read_line(&mut line)?;
            if read == 0 {
                return Err(IpcError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the service closed the connection",
                )));
            }
            if !line.trim().is_empty() {
                return parse_message(line.trim());
            }
        }
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }
}
