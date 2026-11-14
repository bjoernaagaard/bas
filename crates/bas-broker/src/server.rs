//! Starts the broker: loads settings and the active policy, signs in to Secrets Manager,
//! opens the socket API, the proxy, the ssh-agent, and the approval pages, and on Linux
//! tells systemd it is ready.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::extract::{FromRequestParts, Path as UrlPath, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::serve::IncomingStream;
use axum::{Json, Router};
use bas_core::Uuid;
use bas_core::credential;
use bas_core::reference::{EnvName, SecretRef};
use bas_core::secrets::Session;
use serde::Deserialize;
use similar::TextDiff;
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};

use crate::approvals::Kind;
use crate::audit::{self, Peer};
use crate::config::Config;
use crate::files::{bind_socket, file_error};
use crate::passkeys::Passkeys;
use crate::policy::{self, Policy};
use crate::protocol::{
    Accepted, ActivePolicy, AddPasskey, AddSecret, ApprovalLink, HelperRequest, HelperValue,
    PasskeyList, PendingRequest, PolicyProposal, ProxyInfo, Refusal, RunReply, RunRequest, Status,
};
use crate::state::{Broker, POLICY_FILE};
use crate::{Error, pages, proxy, ssh_agent};

/// User agent the broker sends to Secrets Manager.
const USER_AGENT: &str = concat!("bas-broker/", env!("CARGO_PKG_VERSION"));
/// Longest wait a client may ask for on `GET /v1/approvals/ID`.
const MAX_WAIT: u64 = 300;

/// Where the broker reads its settings and writes its files. The defaults match the
/// `bas-broker.service` unit on Linux and the `io.github.bjoernaagaard.bas.broker` LaunchDaemon on
/// macOS. Other paths are for development.
#[derive(Debug, Clone)]
pub struct Options {
    /// Unix socket for the API. The broker replaces a stale file there.
    pub socket: PathBuf,
    /// Unix socket for the ssh-agent.
    pub ssh_agent_socket: PathBuf,
    /// Machine settings, normally `/etc/bas/broker.toml`.
    pub config: PathBuf,
    /// Private directory for the active policy, the passkeys, and the proxy's certificate
    /// authority, normally `/var/lib/bas` on Linux and `/var/db/bas` on macOS.
    pub state_dir: PathBuf,
    /// File the broker writes with the system roots and its certificate authority, for
    /// clients of the proxy, normally `ca-bundle.pem` in the runtime directory.
    pub ca_bundle: PathBuf,
    /// Append-only audit file, normally `/var/log/bas/audit.jsonl`. Linux uses the
    /// journal instead.
    #[cfg(not(target_os = "linux"))]
    pub audit_log: PathBuf,
}

/// How long the broker waits for its runtime directory. launchd starts daemons in no
/// order, so on macOS the directory may appear a moment after the broker starts.
const RUNTIME_DIR_WAIT: Duration = Duration::from_secs(30);

/// Runs the broker until SIGTERM or SIGINT.
pub fn serve(options: &Options) -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| Error::new(format!("could not start the async runtime: {err}")))?;
    runtime.block_on(run(options))
}

async fn run(options: &Options) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    audit::init()?;
    #[cfg(not(target_os = "linux"))]
    audit::init(&options.audit_log)?;
    wait_for_runtime_dir(&options.socket).await?;
    let config = Config::load(&options.config)?;
    let policy = load_policy(&options.state_dir, &config)?;
    let token = credential::load_token(&config.profile)?;
    let session = Session::open(&config.profile, &token, USER_AGENT).await?;
    drop(token);

    let keys = Arc::new(ssh_agent::Keys::default());
    keys.set(ssh_agent::load(&policy, &session).await?);
    let passkeys = Passkeys::open(&options.state_dir, &config.approvals_origin)?;
    let authority = proxy::Authority::load_or_create(&options.state_dir)?;
    authority.write_bundle(&options.ca_bundle)?;

    let proxy_addr = config.proxy;
    let approvals_listen = config.approvals_listen.clone();
    let allow_uids = config.allow_uids.clone();
    let broker = Arc::new(Broker::new(
        config,
        options,
        session,
        policy,
        Arc::clone(&keys),
        passkeys,
    ));

    let proxy = proxy::start(proxy_addr, authority, Arc::clone(&broker)).await?;
    let agent = ssh_agent::start(&options.ssh_agent_socket, allow_uids, keys)?;
    let pages = pages::start(&approvals_listen, Arc::clone(&broker)).await?;
    // Open to every local user. The peer check, not the file mode, decides who may use it.
    let listener = bind_socket(&options.socket, 0o666)?;
    let app = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/run", post(run_request))
        .route("/v1/helper", post(helper_value))
        .route("/v1/secrets", post(add_secret))
        .route("/v1/secrets/{name}/rotate", post(rotate))
        .route("/v1/policy", get(active_policy).post(propose_policy))
        .route("/v1/approvals/{id}", get(approval_state))
        .route("/v1/passkeys", get(list_passkeys).post(add_passkey));
    #[cfg(not(target_os = "linux"))]
    let app = app.route("/v1/audit", get(audit_entries));
    let app = app
        .with_state(Arc::clone(&broker))
        .into_make_service_with_connect_info::<PeerCred>();
    let api = axum::serve(listener, app).into_future();

    let mut term = signal(SignalKind::terminate())
        .map_err(|err| Error::new(format!("could not watch SIGTERM: {err}")))?;
    let mut int = signal(SignalKind::interrupt())
        .map_err(|err| Error::new(format!("could not watch SIGINT: {err}")))?;
    tracing::info!(
        socket = %options.socket.display(),
        ssh_agent = %options.ssh_agent_socket.display(),
        proxy = %proxy_addr,
        approvals = %approvals_listen,
        "bas broker ready"
    );
    // The broker works without systemd too, so a missing notify socket is not an error.
    #[cfg(target_os = "linux")]
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);

    let result = tokio::select! {
        served = api => served.map_err(|err| Error::new(format!("the socket API stopped: {err}"))),
        served = proxy => served,
        served = agent => served,
        served = pages => served,
        _ = term.recv() => Ok(()),
        _ = int.recv() => Ok(()),
    };
    #[cfg(target_os = "linux")]
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
    let _ = std::fs::remove_file(&options.socket);
    let _ = std::fs::remove_file(&options.ssh_agent_socket);
    result
}

/// Waits until the directory of the API socket exists, for at most [`RUNTIME_DIR_WAIT`].
async fn wait_for_runtime_dir(socket: &Path) -> Result<(), Error> {
    let Some(dir) = socket.parent() else {
        return Ok(());
    };
    let deadline = tokio::time::Instant::now() + RUNTIME_DIR_WAIT;
    while !dir.is_dir() {
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::new(format!(
                "{} does not exist; on macOS the io.github.bjoernaagaard.bas.rundir daemon makes it",
                dir.display()
            )));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

/// Reads the active policy from the state directory. Before the first approved change
/// there is none, and the policy is empty.
fn load_policy(state_dir: &Path, config: &Config) -> Result<Policy, Error> {
    let path = state_dir.join(POLICY_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => policy::EMPTY.to_owned(),
        Err(err) => return Err(file_error("read", &path, &err)),
    };
    Policy::parse(&text, &config.profile.name).map_err(|invalid| {
        Error::new(format!(
            "{}{}: {}",
            path.display(),
            invalid
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default(),
            invalid.message
        ))
    })
}

/// Peer credentials of a socket connection, read once when it is accepted.
#[derive(Debug, Clone, Copy)]
struct PeerCred(Option<Peer>);

impl Connected<IncomingStream<'_, UnixListener>> for PeerCred {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self(stream.io().peer_cred().ok().map(|cred| Peer {
            uid: cred.uid(),
            pid: cred.pid(),
        }))
    }
}

/// A peer whose uid is in `allow-uids`. Extracting it refuses every other caller with 403.
struct Allowed(Peer);

impl FromRequestParts<Arc<Broker>> for Allowed {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        broker: &Arc<Broker>,
    ) -> Result<Self, Self::Rejection> {
        let refuse = || refusal(StatusCode::FORBIDDEN, "peer not allowed", None);
        let Some(ConnectInfo(PeerCred(Some(peer)))) =
            parts.extensions.get::<ConnectInfo<PeerCred>>().copied()
        else {
            return Err(refuse());
        };
        if broker.config.allow_uids.contains(&peer.uid) {
            Ok(Self(peer))
        } else {
            audit::deny_peer(peer, "uid not in allow-uids");
            Err(refuse())
        }
    }
}

fn refusal(status: StatusCode, error: &str, name: Option<&str>) -> Response {
    (
        status,
        Json(Refusal {
            error: error.to_owned(),
            name: name.map(str::to_owned),
            line: None,
        }),
    )
        .into_response()
}

/// Opens an approval and replies 202 with its link.
fn ask_approval(broker: &Broker, kind: Kind, peer: Peer, diff: Option<String>) -> Response {
    let label = kind.label();
    let subject = kind.subject();
    let id = broker.approvals.create(kind, peer);
    let id_text = id.hyphenated().to_string();
    audit::request(&id_text, label, &subject, peer);
    (
        StatusCode::ACCEPTED,
        Json(Accepted {
            approval: ApprovalLink {
                url: broker.config.approval_url(id),
                id: id_text,
            },
            diff,
        }),
    )
        .into_response()
}

async fn status(State(broker): State<Arc<Broker>>, Allowed(_): Allowed) -> Json<Status> {
    Json(Status {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        policy_hash: broker.policy().hash().to_owned(),
        requests: broker
            .approvals
            .pending()
            .iter()
            .map(|view| PendingRequest {
                id: view.id.hyphenated().to_string(),
                kind: view.kind.label().to_owned(),
                subject: view.kind.subject(),
                peer_uid: view.peer.uid,
                created_at: view.created_at.clone(),
                expires_in: view.expires_in,
                url: broker.config.approval_url(view.id),
            })
            .collect(),
    })
}

/// Confirms that every name is a proxy entry and replies with the proxy settings. A name
/// that is not refuses the whole request, so the program never starts half set up. No
/// value ever leaves the broker here.
async fn run_request(
    State(broker): State<Arc<Broker>>,
    Allowed(peer): Allowed,
    Json(request): Json<RunRequest>,
) -> Response {
    let claimed_argv = serde_json::to_string(&request.argv).unwrap_or_default();
    let policy = broker.policy();
    for name in &request.names {
        let known = match name.as_str() {
            "tailscale" => policy.tailscale().is_some(),
            "github" => policy.github().is_some(),
            _ => policy.secret(name).is_some(),
        };
        if !known {
            audit::deny_name(name, peer, &claimed_argv, "not a proxy entry of the policy");
            return refusal(StatusCode::FORBIDDEN, "denied", Some(name));
        }
    }
    audit::run(&request.names.join(" "), peer, &claimed_argv, &request.cwd);
    Json(RunReply {
        names: request.names,
        proxy: ProxyInfo {
            url: format!("http://{}", broker.config.proxy),
            ca_bundle: broker.ca_bundle.display().to_string(),
        },
    })
    .into_response()
}

/// `bas get`: replies with the value of a `[helper.NAME]` entry. A passkey approved the
/// entry, so it is the one place a value leaves the broker.
async fn helper_value(
    State(broker): State<Arc<Broker>>,
    Allowed(peer): Allowed,
    Json(request): Json<HelperRequest>,
) -> Response {
    let not_helper = "not a [helper.NAME] entry of the active policy";
    let Ok(reference) = request.reference.parse::<SecretRef>() else {
        return refusal(StatusCode::BAD_REQUEST, "not a bas:// reference", None);
    };
    let policy = broker.policy();
    let Some(name) = policy.helper(&reference) else {
        audit::deny_name(&request.reference, peer, "", not_helper);
        return refusal(StatusCode::FORBIDDEN, not_helper, None);
    };
    let value = match broker.session.get(reference.id).await {
        Ok(found) => found.into_value(),
        Err(err) => {
            tracing::warn!("could not read helper {name}: {err:?}");
            return refusal(
                StatusCode::BAD_GATEWAY,
                "the broker could not read the secret",
                Some(name),
            );
        }
    };
    audit::helper(name, peer);
    Json(HelperValue {
        name: name.to_owned(),
        value: value.expose().to_owned(),
    })
    .into_response()
}

/// `bas add`: checks the entry against the active policy and opens an approval whose page
/// asks for the value.
async fn add_secret(
    State(broker): State<Arc<Broker>>,
    Allowed(peer): Allowed,
    Json(request): Json<AddSecret>,
) -> Response {
    let name = request.name;
    if name.parse::<EnvName>().is_err() {
        return refusal(
            StatusCode::BAD_REQUEST,
            "the name must be a valid environment variable name",
            None,
        );
    }
    if !request.entry.reference.is_empty() {
        return refusal(
            StatusCode::BAD_REQUEST,
            "leave ref out; the broker creates the secret",
            Some(&name),
        );
    }
    if broker.config.project.is_none() {
        return refusal(
            StatusCode::CONFLICT,
            "broker.toml names no project in [profile], so bas add cannot create secrets",
            Some(&name),
        );
    }
    let policy = broker.policy();
    if policy.secret(&name).is_some() {
        return refusal(
            StatusCode::CONFLICT,
            "the name is already in the active policy; use bas rotate",
            Some(&name),
        );
    }
    if let Err(invalid) =
        policy.check_new_secret(&name, &request.entry, &broker.config.profile.name)
    {
        return refusal(StatusCode::BAD_REQUEST, &invalid.message, Some(&name));
    }
    ask_approval(
        &broker,
        Kind::AddSecret {
            name,
            entry: request.entry,
        },
        peer,
        None,
    )
}

/// `bas rotate`: drops minted tokens at once, and opens an approval for a stored value.
async fn rotate(
    State(broker): State<Arc<Broker>>,
    Allowed(peer): Allowed,
    UrlPath(name): UrlPath<String>,
) -> Response {
    let policy = broker.policy();
    if let Some(secret) = policy.secret(&name) {
        return ask_approval(
            &broker,
            Kind::Rotate {
                name: name.clone(),
                reference: secret.reference.clone(),
            },
            peer,
            None,
        );
    }
    let minted = match name.as_str() {
        "github" if policy.github().is_some() => {
            broker.minter.forget_github();
            true
        }
        "tailscale" if policy.tailscale().is_some() => {
            broker.minter.forget_tailscale();
            true
        }
        "github" | "tailscale" => {
            return refusal(
                StatusCode::NOT_FOUND,
                &format!("the active policy has no [{name}] table, so there is nothing to rotate"),
                Some(&name),
            );
        }
        _ => false,
    };
    if minted {
        audit::rotate(&name, peer);
        return Json(serde_json::json!({ "rotated": "minted" })).into_response();
    }
    refusal(
        StatusCode::NOT_FOUND,
        "not in the active policy",
        Some(&name),
    )
}

async fn active_policy(State(broker): State<Arc<Broker>>, Allowed(_): Allowed) -> Response {
    let policy = broker.policy();
    Json(ActivePolicy {
        hash: policy.hash().to_owned(),
        toml: policy.text().to_owned(),
    })
    .into_response()
}

/// `bas policy edit`: checks the text and opens an approval that shows the diff.
async fn propose_policy(
    State(broker): State<Arc<Broker>>,
    Allowed(peer): Allowed,
    Json(proposal): Json<PolicyProposal>,
) -> Response {
    if let Err(invalid) = Policy::parse(&proposal.toml, &broker.config.profile.name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(Refusal {
                error: invalid.message,
                name: None,
                line: invalid.line,
            }),
        )
            .into_response();
    }
    let active = broker.policy();
    if active.text() == proposal.toml {
        return Json(serde_json::json!({ "unchanged": true })).into_response();
    }
    let diff = TextDiff::from_lines(active.text(), proposal.toml.as_str())
        .unified_diff()
        .context_radius(3)
        .header("active", "proposed")
        .to_string();
    ask_approval(
        &broker,
        Kind::Policy {
            toml: proposal.toml,
            base_hash: active.hash().to_owned(),
            diff: diff.clone(),
        },
        peer,
        Some(diff),
    )
}

/// `bas passkey list`: the enrolled passkeys' labels and when each was added, never a key.
async fn list_passkeys(
    State(broker): State<Arc<Broker>>,
    Allowed(_): Allowed,
) -> Json<PasskeyList> {
    Json(PasskeyList {
        passkeys: broker.passkeys.list(),
    })
}

/// `bas passkey add`: opens an approval whose page shows an enrollment link.
async fn add_passkey(
    State(broker): State<Arc<Broker>>,
    Allowed(peer): Allowed,
    Json(request): Json<AddPasskey>,
) -> Response {
    ask_approval(
        &broker,
        Kind::Passkey {
            replace: request.replace,
        },
        peer,
        None,
    )
}

#[derive(Deserialize)]
struct WaitQuery {
    wait: Option<u64>,
}

async fn approval_state(
    State(broker): State<Arc<Broker>>,
    Allowed(_): Allowed,
    UrlPath(id): UrlPath<String>,
    Query(query): Query<WaitQuery>,
) -> Response {
    let Ok(id) = Uuid::parse_str(&id) else {
        return refusal(StatusCode::NOT_FOUND, "no such approval", None);
    };
    let wait = Duration::from_secs(query.wait.unwrap_or(0).min(MAX_WAIT));
    match broker.approvals.wait(id, wait).await {
        Some(state) => Json(state).into_response(),
        None => refusal(StatusCode::NOT_FOUND, "no such approval", None),
    }
}

#[derive(Deserialize)]
#[cfg(not(target_os = "linux"))]
struct AuditQuery {
    /// RFC 3339 time of the oldest entry to return.
    since: Option<String>,
    /// Policy name the entries must be about.
    name: Option<String>,
}

/// `bas audit` on macOS: the audit file's entries, which the caller cannot read itself.
#[cfg(not(target_os = "linux"))]
async fn audit_entries(
    State(broker): State<Arc<Broker>>,
    Allowed(_): Allowed,
    Query(query): Query<AuditQuery>,
) -> Response {
    let since = match query.since.as_deref().map(|since| {
        time::OffsetDateTime::parse(since, &time::format_description::well_known::Rfc3339)
    }) {
        None => None,
        Some(Ok(since)) => Some(since),
        Some(Err(_)) => {
            return refusal(
                StatusCode::BAD_REQUEST,
                "since must be an RFC 3339 time",
                None,
            );
        }
    };
    let path = broker.audit_log.clone();
    let read =
        tokio::task::spawn_blocking(move || audit::read(&path, since, query.name.as_deref()))
            .await
            .unwrap_or_else(|err| Err(Error::new(err.to_string())));
    match read {
        Ok(entries) => Json(crate::protocol::AuditEntries { entries }).into_response(),
        Err(err) => {
            tracing::warn!("{err}");
            refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the broker could not read its audit file",
                None,
            )
        }
    }
}
