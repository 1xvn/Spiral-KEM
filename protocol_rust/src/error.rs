#![forbid(unsafe_code)]
use std::{fmt, io};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Input,
    Authentication,
    Crypto,
    UsedKey,
    QueueFull,
    Deadline,
    Closed,
    Transport,
    Limit(u8),
    Internal,
}
pub type Result<T> = std::result::Result<T, Error>;
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session operation failed ({self:?})")
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Self::Transport
    }
}
impl From<tokio::time::error::Elapsed> for Error {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Self::Deadline
    }
}
