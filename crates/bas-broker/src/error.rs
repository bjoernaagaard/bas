use std::fmt::{self, Display};

/// Failure with a message built only from fixed text, paths, and names, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
    kind: ErrorKind,
    http_status: Option<u16>,
}

/// What kind of failure a client call met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The broker answered and refused the request, so nothing changed.
    Refused,
    /// The socket could not be reached, or the connection broke before a whole reply.
    Unreachable,
    /// The broker sent a whole reply that this client could not read.
    Unreadable,
    /// Anything else.
    Other,
}

impl Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self::with_kind(message, ErrorKind::Other)
    }

    pub(crate) fn with_kind(message: impl Into<String>, kind: ErrorKind) -> Self {
        Self {
            message: message.into(),
            kind,
            http_status: None,
        }
    }

    pub(crate) fn refused(message: impl Into<String>, http_status: u16) -> Self {
        Self {
            message: message.into(),
            kind: ErrorKind::Refused,
            http_status: Some(http_status),
        }
    }

    /// What kind of failure this is.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The HTTP status of a refusal, and `None` for every other kind.
    #[must_use]
    pub fn http_status(&self) -> Option<u16> {
        self.http_status
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<bas_core::Error> for Error {
    fn from(err: bas_core::Error) -> Self {
        Self::new(err.to_string())
    }
}
