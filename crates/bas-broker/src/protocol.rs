//! Request and reply bodies of the broker's socket API, shared by the broker and the `bas`
//! client commands. Only [`HelperValue`], the reply to `bas get` for a `[helper.NAME]`
//! entry, holds a secret value.

use serde::{Deserialize, Serialize};

pub use crate::policy::SecretFile as SecretEntry;
pub use crate::policy::{EntryKind, EntrySummary, summarize as summarize_policy};

/// Socket the broker listens on unless told otherwise.
#[cfg(target_os = "linux")]
pub const DEFAULT_SOCKET: &str = "/run/bas/broker.sock";
/// Socket the broker listens on unless told otherwise.
#[cfg(not(target_os = "linux"))]
pub const DEFAULT_SOCKET: &str = "/var/run/bas/broker.sock";
/// ssh-agent socket the broker listens on unless told otherwise.
#[cfg(target_os = "linux")]
pub const DEFAULT_SSH_AGENT_SOCKET: &str = "/run/bas/ssh-agent.sock";
/// ssh-agent socket the broker listens on unless told otherwise.
#[cfg(not(target_os = "linux"))]
pub const DEFAULT_SSH_AGENT_SOCKET: &str = "/var/run/bas/ssh-agent.sock";

/// Reply to `GET /v1/status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    /// Version of the running broker.
    pub version: String,
    /// SHA-256 of the active policy text, in lowercase hex.
    pub policy_hash: String,
    /// Requests that wait for an approval, with what each asks for.
    pub requests: Vec<PendingRequest>,
}

/// One request that waits for an approval, as `GET /v1/status` lists it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequest {
    /// Approval ID.
    pub id: String,
    /// `add`, `rotate`, `policy`, or `passkey`.
    pub kind: String,
    /// The policy name for `add` and `rotate`, the proposed policy's hash for `policy`.
    pub subject: String,
    /// User ID of the client that asked.
    pub peer_uid: u32,
    /// When it was asked, in RFC 3339.
    pub created_at: String,
    /// Seconds until it expires.
    pub expires_in: u64,
    /// Page to open in a browser.
    pub url: String,
}

/// Reply to `GET /v1/passkeys`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyList {
    /// The enrolled passkeys, oldest first.
    pub passkeys: Vec<PasskeySummary>,
}

/// One enrolled passkey, without its key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeySummary {
    /// The name given when it was enrolled.
    pub label: String,
    /// When it was enrolled, in RFC 3339.
    pub added: String,
}

/// Body of `POST /v1/passkeys`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AddPasskey {
    /// Whether the first passkey enrolled through the link removes every passkey enrolled
    /// before it.
    #[serde(default)]
    pub replace: bool,
}

/// Reply to `GET /v1/audit`, served on macOS, where callers cannot read the audit file.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntries {
    /// One JSON object per audit entry, oldest first, with lowercase field names and a
    /// `timestamp` in RFC 3339.
    pub entries: Vec<serde_json::Value>,
}

/// Body of `POST /v1/run`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunRequest {
    /// Policy names the program will use through the proxy.
    pub names: Vec<String>,
    /// Program and arguments as the client says it will run them. Recorded, not checked.
    pub argv: Vec<String>,
    /// Working directory as the client states it. Recorded, not checked.
    pub cwd: String,
}

/// Reply to an allowed `POST /v1/run`. It never holds a value: the program reaches each
/// name's host through the proxy, which adds the credential.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunReply {
    /// The names, each confirmed to be a proxy entry of the active policy.
    pub names: Vec<String>,
    /// Where the program sends its HTTPS requests.
    pub proxy: ProxyInfo,
}

/// Where a program sends HTTPS requests so the broker can add credentials.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyInfo {
    /// Proxy URL, such as `http://127.0.0.1:3128`.
    pub url: String,
    /// File with the system roots and the proxy's certificate authority.
    pub ca_bundle: String,
}

/// Body of `POST /v1/helper`, sent by `bas get`.
#[derive(Debug, Serialize, Deserialize)]
pub struct HelperRequest {
    /// `bas://PROFILE/SECRET-ID` of a `[helper.NAME]` entry of the active policy.
    pub reference: String,
}

/// Reply to an allowed `POST /v1/helper`: the raw value, which `bas get` prints for a
/// credential helper.
#[derive(Serialize, Deserialize)]
pub struct HelperValue {
    /// The `[helper.NAME]` entry that allowed it.
    pub name: String,
    /// The secret value.
    pub value: String,
}

impl std::fmt::Debug for HelperValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperValue")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Body of `POST /v1/secrets`, sent by `bas add`. The value is typed on the approval page.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddSecret {
    /// Policy name of the new entry, also the key of the new Secrets Manager secret.
    pub name: String,
    /// The `[secret.NAME]` table without `ref`.
    pub entry: SecretEntry,
}

/// Body of `POST /v1/policy`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyProposal {
    /// The whole proposed policy text.
    pub toml: String,
}

/// Reply to `GET /v1/policy`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ActivePolicy {
    /// SHA-256 of the text, in lowercase hex.
    pub hash: String,
    /// The active policy text.
    pub toml: String,
}

/// Reply to a request that waits for a passkey approval (HTTP 202).
#[derive(Debug, Serialize, Deserialize)]
pub struct Accepted {
    /// The approval to open in a browser.
    pub approval: ApprovalLink,
    /// For a policy change, the unified diff from the active policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
}

/// One pending approval.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalLink {
    /// Approval ID.
    pub id: String,
    /// Page to open in a browser.
    pub url: String,
}

/// Reply to `GET /v1/approvals/ID`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalState {
    /// `pending`, `approved`, `denied`, `expired`, or `failed`.
    pub state: String,
    /// What the approved change produced, such as the new reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Why an approved change could not be applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Body of an error reply.
#[derive(Debug, Serialize, Deserialize)]
pub struct Refusal {
    /// `denied` when policy refuses the request, or a short reason otherwise.
    pub error: String,
    /// The policy name the refusal is about, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 1-based line of a policy error, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}
