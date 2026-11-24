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
        let stream = open(endpoint).map_err(IpcError::Unavailable)?;
        let writer = stream.try_clone()?;
        let mut client = Client::from_parts(stream, writer);
        client.say_hello(token.trim(), client_name)?;
        Ok(client)
    }
}

#[cfg(unix)]
fn open(endpoint: &Path) -> io::Result<Stream> {
    std::os::unix::net::UnixStream::connect(endpoint)
}

#[cfg(windows)]
fn open(endpoint: &Path) -> io::Result<Stream> {
    std::fs::OpenOptions::new().read(true).write(true).open(endpoint)
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
