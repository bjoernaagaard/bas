//! Machine settings from `/etc/bas/broker.toml`, which root owns and nothing syncs.
//!
//! ```toml
//! allow-uids = [1000]
//! proxy = "127.0.0.1:3128"
//!
//! [profile]
//! name = "home"
//! organization = "<organization-id>"
//! api-url = "https://api.bitwarden.com"
//! identity-url = "https://identity.bitwarden.com"
//! project = "<project-id>"          # where `bas add` creates secrets
//!
//! [approvals]
//! listen = "127.0.0.1:793"                  # or "unix:/var/run/bas/approve.sock"
//! origin = "https://bas.example.ts.net"
//! ```

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use bas_core::Uuid;
use bas_core::profile::{CredentialSource, EndpointFlags, Endpoints, Profile};
use bas_core::reference::ProfileName;
use serde::Deserialize;
use webauthn_rs::prelude::Url;

use crate::Error;

/// Proxy address used when `broker.toml` names none.
const DEFAULT_PROXY: &str = "127.0.0.1:3128";
/// Approval page address used when `broker.toml` names none. The port is below 1024, so
/// only a process with `CAP_NET_BIND_SERVICE` can take it while the broker is down.
#[cfg(target_os = "linux")]
const DEFAULT_APPROVALS: &str = "127.0.0.1:793";
/// Approval page socket used when `broker.toml` names none. macOS does not keep low ports
/// from other users the way Linux does, so the pages listen on a socket in the broker's
/// own runtime directory, which no other user can create or replace.
#[cfg(not(target_os = "linux"))]
const DEFAULT_APPROVALS: &str = "unix:/var/run/bas/approve.sock";
/// Prefix of a unix socket path in `approvals.listen`.
const UNIX_PREFIX: &str = "unix:";

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ConfigFile {
    allow_uids: Vec<u32>,
    proxy: Option<SocketAddr>,
    profile: ProfileFile,
    approvals: ApprovalsFile,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ProfileFile {
    name: ProfileName,
    organization: Uuid,
    api_url: String,
    identity_url: String,
    project: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ApprovalsFile {
    listen: Option<String>,
    origin: Url,
}

/// Validated machine settings.
#[derive(Debug)]
pub struct Config {
    /// Unix user IDs that may use the socket API and the ssh-agent socket.
    pub allow_uids: BTreeSet<u32>,
    /// Loopback address of the HTTPS proxy.
    pub proxy: SocketAddr,
    /// The one Secrets Manager profile the broker reads secrets through. Its token comes
    /// from the file `bws` in `$CREDENTIALS_DIRECTORY`, which systemd fills on Linux and
    /// the launchd plist names on macOS.
    pub profile: Profile,
    /// Project that `bas add` creates secrets in. Without it, `bas add` is refused.
    pub project: Option<Uuid>,
    /// Where the approval pages listen.
    pub approvals_listen: Listen,
    /// HTTPS origin the approver opens the approval pages on. Its host is the WebAuthn
    /// relying party ID.
    pub approvals_origin: Url,
}

impl Config {
    /// Reads and checks the settings file.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| Error::new(format!("could not read {}: {err}", path.display())))?;
        Self::parse(&text, path)
    }

    /// Checks settings text as [`Config::load`] checks the file at `path`.
    pub fn parse(text: &str, path: &Path) -> Result<Self, Error> {
        let file: ConfigFile = toml::from_str(text)
            .map_err(|err| Error::new(format!("{} is malformed: {err}", path.display())))?;
        let invalid = |reason: &str| Error::new(format!("{}: {reason}", path.display()));
        if file.allow_uids.is_empty() {
            return Err(invalid("allow-uids must list at least one uid"));
        }
        let proxy = loopback(file.proxy, DEFAULT_PROXY)
            .ok_or_else(|| invalid("proxy must be a loopback address"))?;
        let approvals_listen = Listen::parse(
            file.approvals
                .listen
                .as_deref()
                .unwrap_or(DEFAULT_APPROVALS),
        )
        .ok_or_else(|| {
            invalid("approvals.listen must be a loopback address, or unix: and an absolute path")
        })?;
        let origin = file.approvals.origin;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || origin.path() != "/"
            || origin.query().is_some()
        {
            return Err(invalid(
                "approvals.origin must look like https://bas.example.ts.net, with no path",
            ));
        }
        let endpoints = Endpoints::from_flags(&EndpointFlags {
            api_url: Some(file.profile.api_url),
            identity_url: Some(file.profile.identity_url),
            ..EndpointFlags::default()
        })
        .map_err(|err| invalid(&err.to_string()))?;
        Ok(Self {
            allow_uids: file.allow_uids.into_iter().collect(),
            proxy,
            profile: Profile {
                name: file.profile.name,
                organization: file.profile.organization,
                endpoints,
                credential: CredentialSource::SystemdCredential,
            },
            project: file.profile.project,
            approvals_listen,
            approvals_origin: origin,
        })
    }

    /// The approval page for one request, as the approver opens it.
    pub fn approval_url(&self, id: Uuid) -> String {
        format!("{}a/{}", self.approvals_origin, id.hyphenated())
    }
}

fn loopback(given: Option<SocketAddr>, default: &str) -> Option<SocketAddr> {
    let addr = match given {
        Some(addr) => addr,
        None => default.parse().ok()?,
    };
    addr.ip().is_loopback().then_some(addr)
}

/// Where the approval pages listen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listen {
    /// A loopback address and port.
    Tcp(SocketAddr),
    /// A unix socket, mode 0600, for a reverse proxy that runs as root.
    Unix(PathBuf),
}

impl Listen {
    fn parse(text: &str) -> Option<Self> {
        if let Some(path) = text.strip_prefix(UNIX_PREFIX) {
            let path = PathBuf::from(path);
            return path.is_absolute().then_some(Self::Unix(path));
        }
        let addr: SocketAddr = text.parse().ok()?;
        addr.ip().is_loopback().then_some(Self::Tcp(addr))
    }
}

impl fmt::Display for Listen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "{addr}"),
            Self::Unix(path) => write!(f, "{UNIX_PREFIX}{}", path.display()),
        }
    }
}
