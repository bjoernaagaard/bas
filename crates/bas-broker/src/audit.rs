//! Audit entries for every credential the broker hands out, adds, or refuses.
//!
//! Each audit entry carries `BAS_AUDIT=1` and `EVENT`, plus `NAME`, `PEER_UID`, `PEER_PID`,
//! `HOST`, `REPO`, `APPROVAL_ID`, `CLAIMED_ARGV`, and `CLAIMED_CWD` where they apply. No
//! entry ever holds a value.
//!
//! On Linux the entries go to the system journal. journald adds `_SYSTEMD_UNIT` itself, so a
//! client cannot forge an entry for the broker's unit.
//!
//! On macOS they go to an append-only file, one JSON object per line, with the same fields
//! in lowercase. Root owns the file and sets the system append-only flag on it, so the
//! broker can add lines but cannot change old ones, and other users cannot read it.
//! `GET /v1/audit` serves its lines to allowed callers.

use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::Error;

/// This crate's events at info level and above, every other crate's at warn level and
/// above, so libraries never log request details.
fn targets() -> Targets {
    Targets::new()
        .with_target(env!("CARGO_CRATE_NAME"), Level::INFO)
        .with_default(Level::WARN)
}

/// Sends `tracing` events to the journal.
#[cfg(target_os = "linux")]
pub fn init() -> Result<(), Error> {
    let journald = tracing_journald::layer()
        .map_err(|err| Error::new(format!("could not open the system journal: {err}")))?
        .with_field_prefix(None)
        .with_syslog_identifier("bas-broker".to_owned());
    tracing_subscriber::registry()
        .with(journald)
        .with(targets())
        .try_init()
        .map_err(|_| Error::new("could not install the journal logger"))
}

/// Appends this crate's events to the audit file at `path`, one JSON object per line, and
/// writes every crate's warnings to standard error, which launchd keeps in a log file.
#[cfg(not(target_os = "linux"))]
pub fn init(path: &std::path::Path) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::Mutex;
    use tracing_subscriber::Layer;

    // O_APPEND is required by the append-only flag, and each line is one write.
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o640)
        .open(path)
        .map_err(|err| crate::files::file_error("open", path, &err))?;
    let record = tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(Mutex::new(file))
        .with_filter(Targets::new().with_target(env!("CARGO_CRATE_NAME"), Level::INFO));
    let stderr = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .with_filter(Targets::new().with_default(Level::WARN));
    tracing_subscriber::registry()
        .with(record)
        .with(stderr)
        .with(targets())
        .try_init()
        .map_err(|_| Error::new("could not install the audit logger"))
}

/// Audit entries from the file at `path`, oldest first: each line that carries
/// `bas_audit`, written at or after `since`, and about `name` when one is given.
#[cfg(not(target_os = "linux"))]
pub fn read(
    path: &std::path::Path,
    since: Option<time::OffsetDateTime>,
    name: Option<&str>,
) -> Result<Vec<serde_json::Value>, Error> {
    use std::io::BufRead;
    use time::format_description::well_known::Rfc3339;

    let failed = |err: std::io::Error| crate::files::file_error("read", path, &err);
    let file = std::fs::File::open(path).map_err(failed)?;
    let mut entries = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.map_err(failed)?;
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let wanted = entry.get("bas_audit").is_some()
            && name.is_none_or(|name| entry.get("name").and_then(|n| n.as_str()) == Some(name))
            && since.is_none_or(|since| {
                entry
                    .get("timestamp")
                    .and_then(|time| time.as_str())
                    .and_then(|time| time::OffsetDateTime::parse(time, &Rfc3339).ok())
                    .is_some_and(|time| time >= since)
            });
        if wanted {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// The process on the other end of a socket connection, as the kernel reports it.
#[derive(Debug, Clone, Copy)]
pub struct Peer {
    /// User ID of the client.
    pub uid: u32,
    /// Process ID of the client, when the kernel knows it.
    pub pid: Option<i32>,
}

/// Records the names a `bas run` client will use through the proxy.
pub fn run(names: &str, peer: Peer, claimed_argv: &str, claimed_cwd: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "run",
        name = names,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        claimed_argv,
        claimed_cwd,
        "sent proxy settings for {names} to uid {}",
        peer.uid
    );
}

/// Records a value `bas get` received for a `[helper.NAME]` entry.
pub fn helper(name: &str, peer: Peer) {
    tracing::info!(
        bas_audit = 1,
        event = "helper",
        name,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        "sent the value of helper {name} to uid {}",
        peer.uid
    );
}

/// Records one signature the ssh-agent made.
pub fn sign(name: &str, peer: Peer, purpose: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "sign",
        name,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        purpose,
        "signed with ssh key {name} for uid {} ({purpose})",
        peer.uid
    );
}

/// Records that `bas rotate` dropped the cached tokens the broker minted for `name`.
pub fn rotate(name: &str, peer: Peer) {
    tracing::info!(
        bas_audit = 1,
        event = "rotate",
        name,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        "dropped the cached {name} tokens for uid {}",
        peer.uid
    );
}

/// Records a signature the ssh-agent refused.
pub fn deny_sign(name: &str, peer: Peer, reason: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "deny",
        name,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        "refused a signature with ssh key {name} for uid {}: {reason}",
        peer.uid
    );
}

/// Records a new request that waits for a passkey approval.
pub fn request(id: &str, kind: &str, name: &str, peer: Peer) {
    tracing::info!(
        bas_audit = 1,
        event = "request",
        approval_id = id,
        kind,
        name,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        "uid {} asked for approval {id} ({kind} {name})",
        peer.uid
    );
}

/// Records a request approved with a verified passkey assertion.
pub fn approve(id: &str, kind: &str, name: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "approve",
        approval_id = id,
        kind,
        name,
        "approved {id} ({kind} {name}) with a passkey"
    );
}

/// Records a refused approval attempt or a denied request.
pub fn deny_approval(id: &str, kind: &str, name: &str, reason: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "deny",
        approval_id = id,
        kind,
        name,
        "approval {id} ({kind} {name}): {reason}"
    );
}

/// Records a change of the active policy.
pub fn policy(hash: &str, approval_id: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "policy",
        approval_id,
        policy_hash = hash,
        "the active policy is now {hash}"
    );
}

/// Records a token the broker minted.
pub fn mint(name: &str, scope: &str, expires: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "mint",
        name,
        scope,
        expires,
        "minted a {name} token for {scope}, valid until {expires}"
    );
}

/// Records a passkey enrollment.
pub fn enroll(label: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "enroll",
        name = label,
        "enrolled passkey {label}"
    );
}

/// Records a passkey removed by the first enrollment through a replace link.
pub fn remove_passkey(label: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "remove",
        name = label,
        "removed passkey {label}"
    );
}

/// Records a request the policy or the peer check refused.
pub fn deny_peer(peer: Peer, reason: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "deny",
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        "refused uid {}: {reason}",
        peer.uid
    );
}

/// Records a `bas run` name that is not a proxy entry, or a `bas get` reference that is
/// not a helper entry.
pub fn deny_name(name: &str, peer: Peer, claimed_argv: &str, reason: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "deny",
        name,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        claimed_argv,
        "refused {name} to uid {}: {reason}",
        peer.uid
    );
}

/// Records a header the proxy added to one request.
pub fn inject(name: &str, host: &str, method: &str, path: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "inject",
        name,
        host,
        method,
        path,
        "added {name} to {method} https://{host}{path}"
    );
}

/// Records a GitHub tunnel refused for the repository named in its proxy user.
pub fn deny_repo(host: &str, repo: &str, reason: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "deny",
        name = "github",
        host,
        repo,
        "refused CONNECT https://{host} for {repo}: {reason}"
    );
}

/// Records a proxied request the policy refused.
pub fn deny_request(name: &str, host: &str, method: &str, path: &str, reason: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "deny",
        name,
        host,
        method,
        path,
        "refused {method} https://{host}{path}: {reason}"
    );
}
