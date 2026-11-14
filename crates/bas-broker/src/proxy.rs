//! HTTPS proxy on a loopback port that adds a policy credential to requests for one host.
//!
//! Only `CONNECT host:443` is accepted. A host without a policy rule gets a plain tunnel,
//! so the broker never sees its traffic. For a rule host the broker ends the client's TLS
//! with a certificate from its own authority, checks that the inner `Host` is the
//! `CONNECT` host and that the request is allowed, removes any client `Authorization`,
//! sets its own, and opens its own TLS connection upstream, verified against the Mozilla
//! roots.
//!
//! Three kinds of rule host exist:
//!
//! - A `[secret.NAME]` host gets the stored value in the entry's header, for requests that
//!   match `allow`.
//! - With `[github]`, `api.github.com`, `uploads.github.com`, and `github.com` get an App
//!   installation token for one repository. The repository comes from the request path
//!   (`/repos/OWNER/REPO/...` on the API, `/OWNER/REPO.git/...` for git) or from the proxy
//!   user, as in `HTTPS_PROXY=http://gh:OWNER%2FREPO@127.0.0.1:3128`. It must be listed in
//!   `[[github.repo]]`. On `github.com` only git's HTTPS paths are allowed.
//! - With `[tailscale]`, `api.tailscale.com` gets an OAuth access token, for requests that
//!   match `api_allow`.

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::header::{AUTHORIZATION, HOST, HeaderValue, PROXY_AUTHORIZATION};
use hudsucker::hyper::http::uri::Scheme;
use hudsucker::hyper::{Method, Request, Response, StatusCode};
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use hudsucker::rustls::crypto::ring;
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use crate::files::{file_error, replace};
use crate::policy::{self, GITHUB_HOSTS, Route};
use crate::state::Broker;
use crate::{Error, audit};

const CA_KEY_FILE: &str = "ca.key";
const CA_CERT_FILE: &str = "ca.pem";
/// How many generated host certificates the proxy keeps in memory.
const CERT_CACHE: u64 = 1_000;
/// System trust bundles, in the order Debian, Fedora, and Arch-like systems keep them.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
];

/// The proxy's certificate authority, kept in the broker's state directory.
pub struct Authority {
    key_pem: Zeroizing<String>,
    cert_pem: String,
}

impl Authority {
    /// Loads the authority from `state_dir`, or creates it when the key or the certificate
    /// is missing. The private key file is mode 0600.
    pub fn load_or_create(state_dir: &Path) -> Result<Self, Error> {
        let key_path = state_dir.join(CA_KEY_FILE);
        let cert_path = state_dir.join(CA_CERT_FILE);
        let missing = |err: &std::io::Error| err.kind() == std::io::ErrorKind::NotFound;
        match (
            std::fs::read_to_string(&key_path),
            std::fs::read_to_string(&cert_path),
        ) {
            (Ok(key_pem), Ok(cert_pem)) => {
                return Ok(Self {
                    key_pem: Zeroizing::new(key_pem),
                    cert_pem,
                });
            }
            (Err(err), _) if !missing(&err) => return Err(file_error("read", &key_path, &err)),
            (_, Err(err)) if !missing(&err) => return Err(file_error("read", &cert_path, &err)),
            _ => {}
        }
        let failed = |err: hudsucker::rcgen::Error| {
            Error::new(format!("could not create the proxy authority: {err}"))
        };
        let key = KeyPair::generate().map_err(failed)?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "bas broker proxy authority");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(3650);
        let cert = params.self_signed(&key).map_err(failed)?;
        let authority = Self {
            key_pem: Zeroizing::new(key.serialize_pem()),
            cert_pem: cert.pem(),
        };
        // The certificate goes last, so a crash before it leaves a key alone, which the
        // next start replaces.
        replace(&key_path, authority.key_pem.as_bytes(), 0o600)?;
        replace(&cert_path, authority.cert_pem.as_bytes(), 0o644)?;
        Ok(authority)
    }

    /// Writes the system roots followed by this authority to `path`, mode 0644, replacing
    /// the file in one rename.
    pub fn write_bundle(&self, path: &Path) -> Result<(), Error> {
        let system = SYSTEM_BUNDLES
            .iter()
            .find_map(|candidate| std::fs::read_to_string(candidate).ok())
            .ok_or_else(|| Error::new("could not find the system certificate bundle"))?;
        let mut bundle = system;
        if !bundle.ends_with('\n') {
            bundle.push('\n');
        }
        bundle.push_str("# bas broker proxy authority\n");
        bundle.push_str(&self.cert_pem);
        replace(path, bundle.as_bytes(), 0o644)
    }

    fn rcgen(&self) -> Result<RcgenAuthority, Error> {
        let failed = |err: hudsucker::rcgen::Error| {
            Error::new(format!(
                "the proxy authority in the state directory is unusable: {err}"
            ))
        };
        let key = KeyPair::from_pem(&self.key_pem).map_err(failed)?;
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, key).map_err(failed)?;
        Ok(RcgenAuthority::new(
            issuer,
            CERT_CACHE,
            ring::default_provider(),
        ))
    }
}

/// Binds the proxy port and returns the future that serves it.
pub async fn start(
    addr: SocketAddr,
    authority: Authority,
    broker: Arc<Broker>,
) -> Result<impl Future<Output = Result<(), Error>>, Error> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|err| Error::new(format!("could not listen on {addr}: {err}")))?;
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(authority.rcgen()?)
        .with_rustls_connector(ring::default_provider())
        .with_http_handler(Injector {
            broker,
            tunnel: None,
        })
        .build()
        .map_err(|err| Error::new(format!("could not build the proxy: {err}")))?;
    Ok(async move {
        proxy
            .start()
            .await
            .map_err(|err| Error::new(format!("the proxy stopped: {err}")))
    })
}

/// Request handler. hudsucker clones it for each connection, and the clone that handled a
/// `CONNECT` also handles every request inside that tunnel, so `tunnel` is per tunnel.
#[derive(Clone)]
struct Injector {
    broker: Arc<Broker>,
    tunnel: Option<Arc<Tunnel>>,
}

/// A `CONNECT` to a rule host.
enum Tunnel {
    /// A `[secret.NAME]` host, with the header value fetched for it.
    Secret {
        name: String,
        host: String,
        value: HeaderValue,
    },
    /// A GitHub host, with the repository the proxy user claimed, if any.
    Github { host: String, claim: Option<String> },
    /// The Tailscale API.
    Tailscale { host: String },
}

impl Tunnel {
    fn host(&self) -> &str {
        match self {
            Self::Secret { host, .. } | Self::Github { host, .. } | Self::Tailscale { host } => {
                host
            }
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Secret { name, .. } => name,
            Self::Github { .. } => "github",
            Self::Tailscale { .. } => "tailscale",
        }
    }
}

impl HttpHandler for Injector {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse {
        if request.method() == Method::CONNECT {
            return self.connect(request).await;
        }
        match self.tunnel.clone() {
            Some(tunnel) => self.inject(request, &tunnel).await,
            None => reply(
                StatusCode::FORBIDDEN,
                "the bas proxy accepts only CONNECT to port 443\n".to_owned(),
            ),
        }
    }

    async fn should_intercept_connect(
        &mut self,
        _ctx: &HttpContext,
        _request: &Request<Body>,
    ) -> bool {
        self.tunnel.is_some()
    }
}

impl Injector {
    /// Accepts `CONNECT host:443`. For a secret host it fetches the secret now, so a
    /// failure refuses the tunnel instead of each request in it.
    async fn connect(&mut self, request: Request<Body>) -> RequestOrResponse {
        let Some(authority) = request.uri().authority() else {
            return reply(
                StatusCode::BAD_REQUEST,
                "CONNECT needs host:port\n".to_owned(),
            );
        };
        if authority.port_u16() != Some(443) {
            return reply(
                StatusCode::FORBIDDEN,
                "the bas proxy accepts only CONNECT to port 443\n".to_owned(),
            );
        }
        let host = normalize_host(authority.host());
        let claim = proxy_claim(&request);
        let policy = self.broker.policy();
        let tunnel = match policy.route(&host) {
            None => {
                if claim.is_some() && GITHUB_HOSTS.contains(&host.as_str()) {
                    audit::deny_request("github", &host, "CONNECT", "", "no [github] table");
                    return reply(
                        StatusCode::FORBIDDEN,
                        "the active policy has no [github] table, so the bas broker cannot \
                         mint GitHub tokens\n"
                            .to_owned(),
                    );
                }
                return request.into();
            }
            Some(Route::Secret(secret)) => {
                let value = match self.broker.session.get(secret.reference.id).await {
                    Ok(found) => found.into_value(),
                    Err(err) => {
                        tracing::warn!("could not read {} for {host}: {err:?}", secret.name);
                        return reply(
                            StatusCode::BAD_GATEWAY,
                            "the broker could not read the secret\n".to_owned(),
                        );
                    }
                };
                let Some(value) = secret.rule.header_value(value.expose()) else {
                    tracing::warn!("{} does not fit in an HTTP header value", secret.name);
                    return reply(
                        StatusCode::BAD_GATEWAY,
                        "the secret is not a valid header value\n".to_owned(),
                    );
                };
                Tunnel::Secret {
                    name: secret.name.clone(),
                    host,
                    value,
                }
            }
            Some(Route::Github(github)) => {
                if let Some(repo) = &claim
                    && !github.repos.contains_key(&repo.to_ascii_lowercase())
                {
                    audit::deny_repo(&host, repo, "repository not in [github]");
                    return reply(
                        StatusCode::FORBIDDEN,
                        format!("the bas policy has no [[github.repo]] entry for {repo}\n"),
                    );
                }
                Tunnel::Github { host, claim }
            }
            Some(Route::Tailscale(_)) => Tunnel::Tailscale { host },
        };
        self.tunnel = Some(Arc::new(tunnel));
        request.into()
    }

    /// Checks one request inside a rule host's tunnel and sets the credential on it.
    async fn inject(&self, mut request: Request<Body>, tunnel: &Tunnel) -> RequestOrResponse {
        let method = request.method().as_str().to_owned();
        let path = request.uri().path().to_owned();
        let host = tunnel.host();
        let refuse = |status: StatusCode, reason: &str| {
            audit::deny_request(tunnel.name(), host, &method, &path, reason);
            reply(status, format!("refused by bas policy: {reason}\n"))
        };
        if request.uri().scheme() != Some(&Scheme::HTTPS) {
            return refuse(StatusCode::FORBIDDEN, "not TLS inside the tunnel");
        }
        let inner_host = request
            .headers()
            .get(HOST)
            .and_then(|host| host.to_str().ok())
            .map(|host| normalize_host(host.strip_suffix(":443").unwrap_or(host)));
        let target_host = request.uri().host().map(normalize_host);
        if inner_host.as_deref() != Some(host) || target_host.as_deref() != Some(host) {
            return refuse(StatusCode::FORBIDDEN, "Host differs from the CONNECT host");
        }
        let policy = self.broker.policy();
        let (header, value, audit_name) = match (tunnel, policy.route(host)) {
            (Tunnel::Secret { name, value, .. }, Some(Route::Secret(secret)))
                if secret.name == *name =>
            {
                if !secret.rule.allows(request.method(), request.uri()) {
                    return refuse(StatusCode::FORBIDDEN, "method and path not in allow");
                }
                (secret.rule.header.clone(), value.clone(), name.clone())
            }
            (Tunnel::Github { claim, .. }, Some(Route::Github(github))) => {
                let repo = match github_repo(host, &path, claim.as_deref()) {
                    Ok(repo) => repo,
                    Err(reason) => return refuse(StatusCode::FORBIDDEN, reason),
                };
                let Some(entry) = github.repos.get(&repo.to_ascii_lowercase()) else {
                    return refuse(StatusCode::FORBIDDEN, "repository not in [github]");
                };
                let minted = match self.broker.minter.github(github, entry).await {
                    Ok(minted) => minted,
                    Err(err) => {
                        audit::deny_request("github", host, &method, &path, &err.to_string());
                        return reply(StatusCode::BAD_GATEWAY, format!("bas broker: {err}\n"));
                    }
                };
                let text = if host == "github.com" {
                    let basic = Zeroizing::new(format!("x-access-token:{}", minted.token.as_str()));
                    format!("Basic {}", BASE64.encode(basic.as_bytes()))
                } else {
                    format!("Bearer {}", minted.token.as_str())
                };
                let Some(value) = policy::sensitive(&Zeroizing::new(text)) else {
                    return reply(
                        StatusCode::BAD_GATEWAY,
                        "bas broker: unusable token\n".to_owned(),
                    );
                };
                (AUTHORIZATION, value, format!("github:{}", entry.name))
            }
            (Tunnel::Tailscale { .. }, Some(Route::Tailscale(tailscale))) => {
                if !tailscale.api_allow.allows(request.method(), request.uri()) {
                    return refuse(StatusCode::FORBIDDEN, "method and path not in api_allow");
                }
                let minted = match self.broker.minter.tailscale(tailscale).await {
                    Ok(minted) => minted,
                    Err(err) => {
                        audit::deny_request("tailscale", host, &method, &path, &err.to_string());
                        return reply(StatusCode::BAD_GATEWAY, format!("bas broker: {err}\n"));
                    }
                };
                let text = Zeroizing::new(format!("Bearer {}", minted.token.as_str()));
                let Some(value) = policy::sensitive(&text) else {
                    return reply(
                        StatusCode::BAD_GATEWAY,
                        "bas broker: unusable token\n".to_owned(),
                    );
                };
                (AUTHORIZATION, value, "tailscale".to_owned())
            }
            _ => return refuse(StatusCode::FORBIDDEN, "the policy for the host changed"),
        };
        let headers = request.headers_mut();
        headers.remove(AUTHORIZATION);
        headers.remove(PROXY_AUTHORIZATION);
        headers.remove(&header);
        headers.insert(header, value);
        audit::inject(&audit_name, host, &method, &path);
        request.into()
    }
}

/// The repository a GitHub request is for: from the path when it names one, else from the
/// proxy user. Both must agree when both exist.
fn github_repo(host: &str, path: &str, claim: Option<&str>) -> Result<String, &'static str> {
    let mut parts = path.trim_start_matches('/').splitn(3, '/');
    let in_path = if host == "github.com" {
        let owner = parts.next().unwrap_or_default();
        let repo = parts.next().unwrap_or_default();
        let rest = parts.next().unwrap_or_default();
        let git = [
            "info/refs",
            "git-upload-pack",
            "git-receive-pack",
            "info/lfs/",
        ]
        .iter()
        .any(|prefix| rest.starts_with(prefix));
        if owner.is_empty() || repo.is_empty() || !git || policy::ambiguous_path(path) {
            return Err("only git over HTTPS is allowed on github.com");
        }
        Some(format!(
            "{owner}/{}",
            repo.strip_suffix(".git").unwrap_or(repo)
        ))
    } else if parts.next() == Some("repos") {
        match (parts.next(), parts.next()) {
            (Some(owner), Some(rest)) if !owner.is_empty() => {
                let repo = rest.split('/').next().unwrap_or_default();
                (!repo.is_empty()).then(|| format!("{owner}/{repo}"))
            }
            _ => None,
        }
    } else {
        None
    };
    match (in_path, claim) {
        (Some(path_repo), Some(claim)) if !path_repo.eq_ignore_ascii_case(claim) => {
            Err("the path names another repository than the proxy user")
        }
        (Some(repo), _) => Ok(repo),
        (None, Some(claim)) => Ok(claim.to_owned()),
        (None, None) => {
            Err("no repository: put it in the path or in the proxy user, as gh:OWNER%2FREPO")
        }
    }
}

/// The repository claimed in `Proxy-Authorization: Basic base64(user:OWNER/REPO)`.
fn proxy_claim(request: &Request<Body>) -> Option<String> {
    let header = request.headers().get(PROXY_AUTHORIZATION)?.to_str().ok()?;
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = Zeroizing::new(BASE64.decode(encoded.trim()).ok()?);
    let text = std::str::from_utf8(&decoded).ok()?;
    let (_, repo) = text.split_once(':')?;
    let repo = repo.replace("%2F", "/").replace("%2f", "/");
    (!repo.is_empty()).then_some(repo)
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn reply(status: StatusCode, text: String) -> RequestOrResponse {
    let mut response = Response::new(Body::from(text));
    *response.status_mut() = status;
    response.into()
}
