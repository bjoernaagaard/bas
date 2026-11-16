//! The active policy, `policy.toml` in the broker's state directory, which says how each
//! credential may be used. It changes only after a passkey approval.
//!
//! ```toml
//! version = 1
//!
//! [secret.JINA_API_KEY]
//! ref = "bas://home/<secret-id>"
//! delivery = "proxy"                    # the only delivery; "env" is refused
//! host = "api.jina.ai"
//! header = "Authorization"
//! value = "Bearer {secret}"
//! allow = ["GET /v1/*", "POST /v1/*"]   # method and path globs, default deny
//!
//! [helper.CLIPROXY_MANAGEMENT_KEY]
//! ref = "bas://home/<secret-id>"        # `bas get` prints this value, for credential helpers
//!
//! [ssh.git_signing]
//! ref = "bas://home/<secret-id>"        # an ed25519 or rsa OpenSSH key, no passphrase
//! use = ["sign-git"]                    # sign-git, auth, or both
//!
//! [github]
//! app_id = 123456
//! private_key = "bas://home/<secret-id>"
//! user_token = "bas://home/<secret-id>"  # optional, for requests that name no repository
//! [[github.repo]]
//! name = "OWNER/REPO"
//! installation_id = 7654321
//! permissions = { contents = "write", pull_requests = "write" }
//!
//! [tailscale]
//! client_id = "bas://home/<secret-id>"
//! client_secret = "bas://home/<secret-id>"
//! scopes = ["devices:core:read"]
//! api_allow = ["GET /api/v2/tailnet/-/devices"]
//! ```
//!
//! Unknown tables and keys make the policy fail to load, so a rule the broker does not
//! understand is never silently ignored.

use std::collections::BTreeMap;

use bas_core::reference::{EnvName, ProfileName, SecretRef};
use hudsucker::hyper::header::{HeaderName, HeaderValue};
use hudsucker::hyper::{Method, Uri};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Placeholder in `value` that the secret replaces.
const SECRET_PLACEHOLDER: &str = "{secret}";
/// Hosts the GitHub minter serves when `[github]` exists.
pub const GITHUB_HOSTS: &[&str] = &["api.github.com", "uploads.github.com", "github.com"];
/// Host the Tailscale minter serves when `[tailscale]` exists.
pub const TAILSCALE_HOST: &str = "api.tailscale.com";
/// The text of a policy with no rules, used before the first approved change.
pub const EMPTY: &str = "version = 1\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyFile {
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) secret: BTreeMap<String, SecretFile>,
    #[serde(default)]
    pub(crate) helper: BTreeMap<String, HelperFile>,
    #[serde(default)]
    pub(crate) ssh: BTreeMap<String, SshFile>,
    pub(crate) github: Option<GithubFile>,
    pub(crate) tailscale: Option<TailscaleFile>,
}

/// One `[secret.NAME]` table, as `bas add` sends it and as it is written to the policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretFile {
    /// Where the value lives. `bas add` leaves it out, and the broker fills it in.
    #[serde(rename = "ref", default, skip_serializing_if = "String::is_empty")]
    pub reference: String,
    /// Must be `proxy`.
    pub delivery: String,
    /// Host the proxy adds the header for.
    pub host: Option<String>,
    /// Header name.
    pub header: Option<String>,
    /// Header value template with `{secret}` once.
    pub value: Option<String>,
    /// `METHOD /path/glob` entries.
    pub allow: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HelperFile {
    #[serde(rename = "ref")]
    pub(crate) reference: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SshFile {
    #[serde(rename = "ref")]
    pub(crate) reference: String,
    #[serde(rename = "use")]
    pub(crate) uses: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GithubFile {
    pub(crate) app_id: u64,
    pub(crate) private_key: String,
    pub(crate) user_token: Option<String>,
    #[serde(default)]
    pub(crate) repo: Vec<RepoFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepoFile {
    pub(crate) name: String,
    pub(crate) installation_id: u64,
    #[serde(default)]
    pub(crate) permissions: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TailscaleFile {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) api_allow: Vec<String>,
}

/// Why a policy text was refused, with the 1-based line when one is known.
#[derive(Debug, Clone)]
pub struct Invalid {
    /// What is wrong.
    pub message: String,
    /// Line of the problem.
    pub line: Option<usize>,
}

/// The loaded policy.
#[derive(Debug)]
pub struct Policy {
    text: String,
    hash: String,
    secrets: BTreeMap<String, Secret>,
    helpers: BTreeMap<String, SecretRef>,
    ssh: BTreeMap<String, SshKey>,
    github: Option<Github>,
    tailscale: Option<Tailscale>,
}

/// One `[secret.NAME]` entry.
#[derive(Debug)]
pub struct Secret {
    /// The policy name.
    pub name: String,
    /// Where the value lives in Secrets Manager.
    pub reference: SecretRef,
    /// What the proxy does with it.
    pub rule: ProxyRule,
}

/// What the proxy does for one host.
#[derive(Debug)]
pub struct ProxyRule {
    /// Lowercase host name, without a port.
    pub host: String,
    /// Header the proxy sets.
    pub header: HeaderName,
    value: String,
    allow: AllowList,
}

/// `METHOD /path/glob` entries. A request must match one.
#[derive(Debug)]
pub struct AllowList(Vec<Allow>);

#[derive(Debug)]
struct Allow {
    method: Method,
    path: Regex,
}

/// One `[ssh.NAME]` entry.
#[derive(Debug)]
pub struct SshKey {
    /// Where the OpenSSH private key lives.
    pub reference: SecretRef,
    /// The key may sign git objects (`ssh-keygen -Y sign -n git`).
    pub sign_git: bool,
    /// The key may sign SSH logins.
    pub auth: bool,
}

/// The `[github]` table.
#[derive(Debug)]
pub struct Github {
    /// The GitHub App's ID.
    pub app_id: u64,
    /// Where the App's private key (PEM) lives.
    pub private_key: SecretRef,
    /// Where a GitHub user token lives, for requests that name no repository.
    pub user_token: Option<SecretRef>,
    /// Repositories a token may be minted for, keyed by lowercase `owner/repo`.
    pub repos: BTreeMap<String, Repo>,
}

/// One `[[github.repo]]` entry.
#[derive(Debug)]
pub struct Repo {
    /// `owner/repo` as written in the policy.
    pub name: String,
    /// Installation of the App that covers the repository.
    pub installation_id: u64,
    /// Permissions asked for each token, such as `contents = "write"`.
    pub permissions: BTreeMap<String, String>,
}

/// The `[tailscale]` table.
#[derive(Debug)]
pub struct Tailscale {
    /// Where the OAuth client ID lives.
    pub client_id: SecretRef,
    /// Where the OAuth client secret lives.
    pub client_secret: SecretRef,
    /// Scopes asked for each access token.
    pub scopes: Vec<String>,
    /// API requests the proxy lets through.
    pub api_allow: AllowList,
}

/// What the proxy does for one host.
pub enum Route<'a> {
    /// Adds a stored secret.
    Secret(&'a Secret),
    /// Adds a one-repository GitHub App installation token.
    Github(&'a Github),
    /// Adds a Tailscale OAuth access token.
    Tailscale(&'a Tailscale),
}

impl ProxyRule {
    /// The header value with the secret in place of `{secret}`, marked sensitive so hyper
    /// keeps it out of debug output and HTTP/2 header compression.
    pub fn header_value(&self, secret: &str) -> Option<HeaderValue> {
        sensitive(&self.value.replace(SECRET_PLACEHOLDER, secret))
    }

    /// Whether the method and path are in `allow`.
    pub fn allows(&self, method: &Method, uri: &Uri) -> bool {
        self.allow.allows(method, uri)
    }
}

/// A header value marked sensitive, or `None` when the text cannot be one.
pub fn sensitive(text: &str) -> Option<HeaderValue> {
    let mut value = HeaderValue::from_str(text).ok()?;
    value.set_sensitive(true);
    Some(value)
}

impl AllowList {
    /// Whether some entry matches the method and path of `uri`.
    ///
    /// Paths with `.` or `..` segments, backslashes, or encoded dots, slashes, or
    /// backslashes never match, because the upstream server could read them as another
    /// path than the one checked here.
    pub fn allows(&self, method: &Method, uri: &Uri) -> bool {
        let path = uri.path();
        !ambiguous_path(path)
            && self
                .0
                .iter()
                .any(|allow| allow.method == method && allow.path.is_match(path))
    }
}

/// A path the upstream server could read differently from the proxy.
pub fn ambiguous_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    path.contains('\\')
        || ["%2e", "%2f", "%5c"]
            .iter()
            .any(|encoded| lower.contains(encoded))
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

/// Names `bas run` takes to mean the `[github]` and `[tailscale]` tables.
const BUILT_IN_NAMES: &[&str] = &["github", "tailscale"];
const BUILT_IN_REASON: &str =
    "the name is taken by the [github] and [tailscale] tables, so pick another";

impl Policy {
    /// Parses and checks a policy text. Every `ref` must name `profile`, the broker's
    /// profile.
    pub fn parse(text: &str, profile: &ProfileName) -> Result<Self, Invalid> {
        let file: PolicyFile = toml::from_str(text).map_err(|err| Invalid {
            message: err.message().to_owned(),
            line: err.span().map(|span| line_at(text, span.start)),
        })?;
        let at = |needle: &str, message: String| Invalid {
            message,
            line: line_of(text, needle),
        };
        if file.version != 1 {
            return Err(at("version", "version must be 1".to_owned()));
        }
        let reference = |raw: &str, table: &str, key: &str| -> Result<SecretRef, Invalid> {
            let parsed: SecretRef = raw.parse().map_err(|_| {
                at(
                    table,
                    format!("{table}: {key} must look like bas://<profile>/<secret-id>"),
                )
            })?;
            if parsed.profile != *profile {
                return Err(at(
                    table,
                    format!("{table}: {key} must use the broker's profile '{profile}'"),
                ));
            }
            Ok(parsed)
        };

        let mut hosts: BTreeMap<String, String> = BTreeMap::new();
        let github = match file.github {
            Some(github) => {
                for host in GITHUB_HOSTS {
                    hosts.insert((*host).to_owned(), "[github]".to_owned());
                }
                Some(github_table(github, &reference, &at)?)
            }
            None => None,
        };
        let tailscale = match file.tailscale {
            Some(tailscale) => {
                hosts.insert(TAILSCALE_HOST.to_owned(), "[tailscale]".to_owned());
                Some(Tailscale {
                    client_id: reference(&tailscale.client_id, "[tailscale]", "client_id")?,
                    client_secret: reference(
                        &tailscale.client_secret,
                        "[tailscale]",
                        "client_secret",
                    )?,
                    scopes: tailscale.scopes,
                    api_allow: allow_list(&tailscale.api_allow)
                        .map_err(|reason| at("[tailscale]", format!("[tailscale]: {reason}")))?,
                })
            }
            None => None,
        };

        let mut secrets = BTreeMap::new();
        for (name, entry) in file.secret {
            let table = format!("[secret.{name}]");
            let invalid = |reason: &str| at(&table, format!("secret.{name}: {reason}"));
            name.parse::<EnvName>()
                .map_err(|_| invalid("the name must be a valid environment variable name"))?;
            if BUILT_IN_NAMES.contains(&name.as_str()) {
                return Err(invalid(BUILT_IN_REASON));
            }
            let reference = reference(&entry.reference, &table, "ref")?;
            let rule = proxy_rule(entry).map_err(|reason| invalid(&reason))?;
            if let Some(other) = hosts.insert(rule.host.clone(), format!("secret.{name}")) {
                return Err(invalid(&format!(
                    "host {} is already used by {other}",
                    rule.host
                )));
            }
            secrets.insert(
                name.clone(),
                Secret {
                    name,
                    reference,
                    rule,
                },
            );
        }

        let mut helpers = BTreeMap::new();
        for (name, entry) in file.helper {
            let table = format!("[helper.{name}]");
            name.parse::<EnvName>().map_err(|_| {
                at(
                    &table,
                    format!("helper.{name}: the name must be a valid environment variable name"),
                )
            })?;
            if BUILT_IN_NAMES.contains(&name.as_str()) {
                return Err(at(&table, format!("helper.{name}: {BUILT_IN_REASON}")));
            }
            helpers.insert(name, reference(&entry.reference, &table, "ref")?);
        }

        let mut ssh = BTreeMap::new();
        for (name, entry) in file.ssh {
            let table = format!("[ssh.{name}]");
            let invalid = |reason: &str| at(&table, format!("ssh.{name}: {reason}"));
            let name_ok = !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
            if !name_ok {
                return Err(invalid("the name may hold only letters, digits, _ and -"));
            }
            let reference = reference(&entry.reference, &table, "ref")?;
            let mut key = SshKey {
                reference,
                sign_git: false,
                auth: false,
            };
            for purpose in &entry.uses {
                match purpose.as_str() {
                    "sign-git" => key.sign_git = true,
                    "auth" => key.auth = true,
                    _ => return Err(invalid("use entries must be \"sign-git\" or \"auth\"")),
                }
            }
            if !key.sign_git && !key.auth {
                return Err(invalid("use must list \"sign-git\", \"auth\", or both"));
            }
            ssh.insert(name, key);
        }

        Ok(Self {
            text: text.to_owned(),
            hash: hash(text),
            secrets,
            helpers,
            ssh,
            github,
            tailscale,
        })
    }

    /// The policy text as approved.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// SHA-256 of the policy text, in lowercase hex.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// The entry for a policy name.
    pub fn secret(&self, name: &str) -> Option<&Secret> {
        self.secrets.get(name)
    }

    /// The name of the `[helper.NAME]` entry whose value `bas get` may print for this
    /// reference, or `None` when no entry has it.
    pub fn helper(&self, reference: &SecretRef) -> Option<&str> {
        self.helpers
            .iter()
            .find(|(_, helper)| *helper == reference)
            .map(|(name, _)| name.as_str())
    }

    /// `[ssh.NAME]` entries.
    pub fn ssh(&self) -> &BTreeMap<String, SshKey> {
        &self.ssh
    }

    /// The `[github]` table.
    pub fn github(&self) -> Option<&Github> {
        self.github.as_ref()
    }

    /// The `[tailscale]` table.
    pub fn tailscale(&self) -> Option<&Tailscale> {
        self.tailscale.as_ref()
    }

    /// Every distinct reference with each policy key that holds it, such as
    /// `secret.NAME.ref` or `github.private_key`.
    pub fn references(&self) -> BTreeMap<&SecretRef, Vec<String>> {
        let mut located: BTreeMap<&SecretRef, Vec<String>> = BTreeMap::new();
        let mut add = |reference, location: String| {
            located.entry(reference).or_default().push(location);
        };
        for (name, secret) in &self.secrets {
            add(&secret.reference, format!("secret.{name}.ref"));
        }
        for (name, reference) in &self.helpers {
            add(reference, format!("helper.{name}.ref"));
        }
        for (name, key) in &self.ssh {
            add(&key.reference, format!("ssh.{name}.ref"));
        }
        if let Some(github) = &self.github {
            add(&github.private_key, "github.private_key".to_owned());
            if let Some(user_token) = &github.user_token {
                add(user_token, "github.user_token".to_owned());
            }
        }
        if let Some(tailscale) = &self.tailscale {
            add(&tailscale.client_id, "tailscale.client_id".to_owned());
            add(
                &tailscale.client_secret,
                "tailscale.client_secret".to_owned(),
            );
        }
        located
    }

    /// What the proxy does for a lowercase host name, or `None` for a plain tunnel.
    pub fn route(&self, host: &str) -> Option<Route<'_>> {
        if let Some(github) = &self.github
            && GITHUB_HOSTS.contains(&host)
        {
            return Some(Route::Github(github));
        }
        if let Some(tailscale) = &self.tailscale
            && host == TAILSCALE_HOST
        {
            return Some(Route::Tailscale(tailscale));
        }
        self.secrets
            .values()
            .find(|secret| secret.rule.host == host)
            .map(Route::Secret)
    }

    /// Checks that adding `entry` as `[secret.NAME]` gives a valid policy, before its secret
    /// exists. A nil ID stands in for the reference the broker creates later.
    pub fn check_new_secret(
        &self,
        name: &str,
        entry: &SecretFile,
        profile: &ProfileName,
    ) -> Result<(), Invalid> {
        let mut candidate = entry.clone();
        candidate.reference = SecretRef {
            profile: profile.clone(),
            id: bas_core::Uuid::nil(),
        }
        .to_string();
        self.with_secret(name, &candidate, profile).map(drop)
    }

    /// This policy with one more `[secret.NAME]` table at the end.
    pub fn with_secret(
        &self,
        name: &str,
        entry: &SecretFile,
        profile: &ProfileName,
    ) -> Result<Self, Invalid> {
        let mut table = BTreeMap::new();
        table.insert(name.to_owned(), entry.clone());
        let mut wrapper = BTreeMap::new();
        wrapper.insert("secret", table);
        let added = toml::to_string(&wrapper).map_err(|err| Invalid {
            message: format!("could not write the new entry: {err}"),
            line: None,
        })?;
        let mut text = self.text.clone();
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push('\n');
        text.push_str(&added);
        Self::parse(&text, profile)
    }
}

/// SHA-256 of a policy text, in lowercase hex.
pub fn hash(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn github_table(
    github: GithubFile,
    reference: &impl Fn(&str, &str, &str) -> Result<SecretRef, Invalid>,
    at: &impl Fn(&str, String) -> Invalid,
) -> Result<Github, Invalid> {
    let private_key = reference(&github.private_key, "[github]", "private_key")?;
    let user_token = github
        .user_token
        .map(|raw| reference(&raw, "[github]", "user_token"))
        .transpose()?;
    let mut repos = BTreeMap::new();
    for repo in github.repo {
        let invalid = |reason: &str| at("[[github.repo]]", format!("github.repo: {reason}"));
        let valid_part = |part: &str| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        };
        match repo.name.split_once('/') {
            Some((owner, name)) if valid_part(owner) && valid_part(name) => {}
            _ => return Err(invalid("name must look like OWNER/REPO")),
        }
        if repo.permissions.values().any(|level| level.is_empty()) {
            return Err(invalid("each permission needs a level such as \"read\""));
        }
        let key = repo.name.to_ascii_lowercase();
        let entry = Repo {
            name: repo.name,
            installation_id: repo.installation_id,
            permissions: repo.permissions,
        };
        if repos.insert(key, entry).is_some() {
            return Err(invalid("a repository is listed twice"));
        }
    }
    Ok(Github {
        app_id: github.app_id,
        private_key,
        user_token,
        repos,
    })
}

fn proxy_rule(entry: SecretFile) -> Result<ProxyRule, String> {
    match entry.delivery.as_str() {
        "proxy" => {}
        "env" => {
            return Err(
                "delivery = \"env\" is refused: this broker sends keys through the proxy only"
                    .to_owned(),
            );
        }
        _ => return Err("delivery must be \"proxy\"".to_owned()),
    }
    let (Some(host), Some(header), Some(value), Some(allow)) =
        (entry.host, entry.header, entry.value, entry.allow)
    else {
        return Err("delivery = \"proxy\" needs host, header, value, and allow".to_owned());
    };
    let host = host.to_ascii_lowercase();
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && !host.starts_with('.')
        && !host.ends_with('.');
    if !host_ok {
        return Err("host must be a DNS name without a port".to_owned());
    }
    let header: HeaderName = header
        .parse()
        .map_err(|_| "header must be a valid HTTP header name".to_owned())?;
    if value.matches(SECRET_PLACEHOLDER).count() != 1 {
        return Err("value must contain {secret} exactly once".to_owned());
    }
    if HeaderValue::from_str(&value).is_err() {
        return Err("value must be a valid HTTP header value".to_owned());
    }
    Ok(ProxyRule {
        host,
        header,
        value,
        allow: allow_list(&allow)?,
    })
}

fn allow_list(entries: &[String]) -> Result<AllowList, String> {
    entries
        .iter()
        .map(|entry| parse_allow(entry))
        .collect::<Result<Vec<_>, _>>()
        .map(AllowList)
}

/// Parses `METHOD /path/glob`, where `*` in the path matches any run of characters,
/// including `/`.
fn parse_allow(entry: &str) -> Result<Allow, String> {
    let invalid = || format!("allow entry '{entry}' must look like \"GET /v1/*\"");
    let (method, path) = entry.split_once(' ').ok_or_else(invalid)?;
    if !path.starts_with('/') || path.contains(' ') {
        return Err(invalid());
    }
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| invalid())?;
    let pattern = path
        .split('*')
        .map(regex::escape)
        .collect::<Vec<_>>()
        .join(".*");
    let path = Regex::new(&format!("^{pattern}$")).map_err(|_| invalid())?;
    Ok(Allow { method, path })
}

/// 1-based line of a byte offset.
fn line_at(text: &str, offset: usize) -> usize {
    text.get(..offset)
        .map_or(0, |before| before.matches('\n').count())
        + 1
}

/// 1-based line of the first line that starts with `needle`, ignoring leading spaces.
fn line_of(text: &str, needle: &str) -> Option<usize> {
    text.lines()
        .position(|line| line.trim_start().starts_with(needle))
        .map(|index| index + 1)
}
