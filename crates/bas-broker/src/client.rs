//! The client side of the socket API, used by `bas run --with`, `bas get`, `bas add`, `bas rotate`,
//! `bas policy edit`, `bas passkey`, `bas audit` on macOS, and `bas tui` in broker
//! mode.

use std::path::{Path, PathBuf};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;

use crate::protocol::{
    Accepted, ActivePolicy, AddPasskey, AddSecret, ApprovalState, AuditEntries, DEFAULT_SOCKET,
    HelperRequest, HelperValue, PasskeyList, PolicyProposal, Refusal, RunReply, RunRequest, Status,
};
use crate::{Error, ErrorKind};

/// Environment variable that points `bas` at another broker socket, for development.
const SOCKET_VAR: &str = "BAS_BROKER_SOCKET";

/// The broker socket: `$BAS_BROKER_SOCKET`, or [`DEFAULT_SOCKET`].
pub fn socket_path() -> PathBuf {
    std::env::var_os(SOCKET_VAR).map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from)
}

/// A broker reply that either finished the request or waits for a passkey approval.
#[derive(Debug)]
pub enum Outcome<T> {
    /// HTTP 200.
    Done(T),
    /// HTTP 202.
    Waiting(Accepted),
}

/// Talks to one broker socket.
pub struct Client {
    socket: PathBuf,
}

impl Client {
    /// A client for `socket`.
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_path_buf(),
        }
    }

    /// The socket this client talks to.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The broker's version, policy hash, and pending requests.
    pub async fn status(&self) -> Result<Status, Error> {
        match self.call::<(), _>(Method::GET, "/v1/status", None).await? {
            Outcome::Done(status) => Ok(status),
            Outcome::Waiting(_) => Err(Error::new("the bas broker sent an unexpected reply")),
        }
    }

    /// Audit entries at or after `since` (RFC 3339), about `name` when given. Only the
    /// macOS broker serves them. The Linux broker writes to the journal instead.
    pub async fn audit(
        &self,
        since: Option<&str>,
        name: Option<&str>,
    ) -> Result<AuditEntries, Error> {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(since) = since {
            query.append_pair("since", since);
        }
        if let Some(name) = name {
            query.append_pair("name", name);
        }
        let path = format!("/v1/audit?{}", query.finish());
        match self.call::<(), _>(Method::GET, &path, None).await? {
            Outcome::Done(entries) => Ok(entries),
            Outcome::Waiting(_) => Err(Error::new("the bas broker sent an unexpected reply")),
        }
    }

    /// Asks the broker whether `request.names` are proxy entries, and where the proxy is.
    pub async fn run(&self, request: &RunRequest) -> Result<RunReply, Error> {
        match self.call(Method::POST, "/v1/run", Some(request)).await? {
            Outcome::Done(reply) => Ok(reply),
            Outcome::Waiting(_) => Err(Error::new("the bas broker sent an unexpected reply")),
        }
    }

    /// The value of a `[helper.NAME]` entry, for `bas get`.
    pub async fn helper(&self, request: &HelperRequest) -> Result<HelperValue, Error> {
        match self.call(Method::POST, "/v1/helper", Some(request)).await? {
            Outcome::Done(reply) => Ok(reply),
            Outcome::Waiting(_) => Err(Error::new("the bas broker sent an unexpected reply")),
        }
    }

    /// Proposes a new proxy entry. The value is typed on the approval page.
    pub async fn add_secret(
        &self,
        request: &AddSecret,
    ) -> Result<Outcome<serde_json::Value>, Error> {
        self.call(Method::POST, "/v1/secrets", Some(request)).await
    }

    /// Rotates a stored value (after an approval) or drops a minted token at once.
    pub async fn rotate(&self, name: &str) -> Result<Outcome<serde_json::Value>, Error> {
        let path = format!("/v1/secrets/{name}/rotate");
        self.call(Method::POST, &path, Some(&serde_json::json!({})))
            .await
    }

    /// The active policy.
    pub async fn policy(&self) -> Result<ActivePolicy, Error> {
        match self.call::<(), _>(Method::GET, "/v1/policy", None).await? {
            Outcome::Done(policy) => Ok(policy),
            Outcome::Waiting(_) => Err(Error::new("the bas broker sent an unexpected reply")),
        }
    }

    /// Proposes a whole new policy text.
    pub async fn propose_policy(
        &self,
        proposal: &PolicyProposal,
    ) -> Result<Outcome<serde_json::Value>, Error> {
        self.call(Method::POST, "/v1/policy", Some(proposal)).await
    }

    /// The enrolled passkeys, without their keys.
    pub async fn passkeys(&self) -> Result<PasskeyList, Error> {
        match self
            .call::<(), _>(Method::GET, "/v1/passkeys", None)
            .await?
        {
            Outcome::Done(list) => Ok(list),
            Outcome::Waiting(_) => Err(Error::new("the bas broker sent an unexpected reply")),
        }
    }

    /// Asks for an approval that lets the approver enroll one more passkey. With
    /// `replace`, the link enrolls passkeys until it expires, and the first one removes
    /// every passkey enrolled before it.
    pub async fn add_passkey(&self, replace: bool) -> Result<Outcome<serde_json::Value>, Error> {
        self.call(Method::POST, "/v1/passkeys", Some(&AddPasskey { replace }))
            .await
    }

    /// The state of one approval. Waits up to `wait_seconds` while it is pending.
    pub async fn approval(&self, id: &str, wait_seconds: u32) -> Result<ApprovalState, Error> {
        let path = format!("/v1/approvals/{id}?wait={wait_seconds}");
        match self.call::<(), _>(Method::GET, &path, None).await? {
            Outcome::Done(state) => Ok(state),
            Outcome::Waiting(_) => Err(Error::new("the bas broker sent an unexpected reply")),
        }
    }

    async fn call<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<Outcome<T>, Error> {
        let unreachable = |err: &dyn std::fmt::Display| {
            Error::new(format!(
                "could not reach the bas broker at {}: {err}",
                self.socket.display()
            ))
        };
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|err| unreachable(&err))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|err| unreachable(&err))?;
        tokio::spawn(connection);
        let body = match body {
            Some(body) => serde_json::to_vec(body)
                .map_err(|_| Error::new("could not encode the broker request"))?,
            None => Vec::new(),
        };
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| Error::new("could not build the broker request"))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|err| unreachable(&err))?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|err| unreachable(&err))?
            .to_bytes();
        let unreadable = || Error::new("the bas broker sent a reply bas could not read");
        match status {
            StatusCode::OK => serde_json::from_slice(&body)
                .map(Outcome::Done)
                .map_err(|_| unreadable()),
            StatusCode::ACCEPTED => serde_json::from_slice(&body)
                .map(Outcome::Waiting)
                .map_err(|_| unreadable()),
            _ => Err(refused(status, &body)),
        }
    }
}

fn refused(status: StatusCode, body: &[u8]) -> Error {
    let Ok(refusal) = serde_json::from_slice::<Refusal>(body) else {
        return Error::with_kind(
            format!(
                "the bas broker refused the request (HTTP {})",
                status.as_u16()
            ),
            ErrorKind::Refused,
        );
    };
    let mut message = if refusal.error == "denied" {
        match &refusal.name {
            Some(name) => format!(
                "the bas broker denied {name}: it is not a proxy entry of the active policy"
            ),
            None => "the bas broker denied the request".to_owned(),
        }
    } else {
        format!(
            "the bas broker refused the request (HTTP {}): {}",
            status.as_u16(),
            refusal.error
        )
    };
    if let Some(line) = refusal.line {
        message.push_str(&format!(" (line {line})"));
    }
    Error::with_kind(message, ErrorKind::Refused)
}
