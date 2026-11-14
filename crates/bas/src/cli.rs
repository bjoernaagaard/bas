//! Command-line grammar for `bas`.
//!
//! Profile names, IDs, and references are taken as plain strings and parsed by `bas`, so a
//! rejected value is never echoed back. It might be a pasted secret.

use std::ffi::OsString;
use std::path::PathBuf;

use bas_core::profile::{EndpointFlags, Region};
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

/// Reference-based access to Bitwarden Secrets Manager for coding agents.
///
/// Commands print references, metadata, and receipts, never secret values. The one
/// exception is `bas get`, for references the operator allowlisted with `bas helper allow`.
#[derive(Debug, Parser)]
#[command(name = "bas", version, about, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Connect, inspect, and remove profiles bound to an organization and endpoint.
    #[command(subcommand)]
    Auth(AuthCommand),
    /// Find secret references by key without retrieving values.
    Find(FindArgs),
    /// Run a program with referenced secrets in its environment.
    ///
    /// Every reference is resolved before the program starts; if any is missing or denied,
    /// the program does not start. References to a remote profile are requested one by one
    /// from its paired listener, and each needs approval or an exact grant there; a remote
    /// failure never falls back to a machine token. Arguments after -- reach the program
    /// unchanged, without a shell. BWS_ACCESS_TOKEN and AAC_TOKEN are removed from its
    /// environment. Each injected value of 4 or more bytes is replaced with [bas:NAME] in the
    /// program's stdout and stderr. Masking isn't a sandbox, because the program can still
    /// write a value to a file or send it elsewhere. Before the program starts, bas appends
    /// one JSON line per binding to audit.log in BAS_STATE_DIR or the user state directory,
    /// and the line never holds a value. If the audit line can't be written, the program
    /// doesn't start.
    ///
    /// With --with NAME (Linux and macOS), the program never receives the value of the policy
    /// entry NAME. The bas broker confirms that NAME is a proxy entry, and bas sets
    /// HTTPS_PROXY, https_proxy, SSL_CERT_FILE, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE,
    /// NODE_EXTRA_CA_CERTS, and GIT_SSL_CAINFO so the program's HTTPS requests go through
    /// the broker's proxy, which adds the credential for the entry's host. The broker
    /// records an audit entry. BAS_BROKER_SOCKET overrides the socket path
    /// (/run/bas/broker.sock on Linux, /var/run/bas/broker.sock on macOS). Go programs on
    /// macOS, gh among them, ignore SSL_CERT_FILE and so cannot use the proxy.
    Run(RunArgs),
    /// Print the raw value of one allowlisted reference, for credential helpers.
    ///
    /// For tools that run a command and read one secret from its stdout, such as pi's
    /// "!cmd" keys, git credential helpers, and apiKeyHelper. bas prints the value with no
    /// trailing newline, only when the reference is on the list that `bas helper allow`
    /// keeps and stdout is not a terminal. References of a remote profile still need
    /// approval or a grant on the listener. Before the value is printed, bas appends one
    /// JSON line with the reference and the parent process to audit.log, and the line never
    /// holds the value. If the audit line can't be written, nothing is printed.
    ///
    /// On a machine with a bas broker (Linux and macOS), bas get asks the broker instead,
    /// which answers only for references in a [helper.NAME] table of its policy and records
    /// each read in its audit log. Add one with `bas policy edit`.
    Get(GetArgs),
    /// Allow, list, and revoke the references that `bas get` may print.
    ///
    /// The list is stored in helpers.toml in the bas configuration directory. On a machine
    /// with a bas broker, list shows the [helper.NAME] tables of the broker's policy, and
    /// allow and revoke refuse, because bas get reads only the broker's policy there.
    #[command(subcommand)]
    Helper(HelperCommand),
    /// Write or run reference-only environment templates.
    #[command(subcommand)]
    Env(EnvCommand),
    /// Create a secret from piped stdin or the clipboard and print a JSON receipt.
    ///
    /// Input bytes are preserved, including terminal line endings. The receipt outcome
    /// is verified (exit 0), written_unverified (exit 3), or unknown (exit
    /// 4). A refused write prints an error instead. Writes are never retried.
    Create(CreateArgs),
    /// Replace the value of an existing secret, keeping its key, note, and project.
    ///
    /// Input and receipts work as for create.
    Update(UpdateArgs),
    /// Report readiness. Offline unless --profile is given.
    Doctor(DoctorArgs),
    /// Serve paired remote devices through Agent Access until interrupted.
    ///
    /// A request is answered only when the device is paired and asks for one explicit
    /// secret ID listed with --allow. Then an active `bas grant` for that device, this
    /// profile and organization, and that secret delivers it without a prompt. Otherwise
    /// the operator must type the one-time code shown on this terminal for that request;
    /// without a terminal the request is denied. The value is retrieved from Secrets
    /// Manager only after that. Pairing, profile, and grant are checked again on disk
    /// before each reply is released. Domain and search requests are denied. Status lines
    /// go to stderr; values are never printed.
    Listen(ListenArgs),
    /// Pair this machine with a listener and save a remote profile.
    ///
    /// Asks on this terminal for the code that `bas listen --pair` shows, then for the
    /// handshake fingerprint shown on the listener. The profile stores no Secrets Manager
    /// token. Its bas://PROFILE/SECRET-ID references resolve only through that listener,
    /// one request at a time, and each needs approval or an exact grant there. Pairing
    /// grants no secret by itself.
    Pair(PairArgs),
    /// Create, list, and revoke standing grants for paired devices.
    ///
    /// A grant lets one paired device receive exact secret IDs from one listener profile
    /// and organization without a prompt, until revoked. It never widens the listener's
    /// --allow scope or pairs a device. Grants are stored in grants.toml in the bas
    /// configuration directory.
    #[command(subcommand)]
    Grant(GrantCommand),
    /// Browse and edit secrets and projects in a terminal UI, or manage a bas broker's policy.
    ///
    /// Without --profile it opens broker mode when the bas broker at BAS_BROKER_SOCKET, or
    /// the default socket, answers. Broker mode needs no machine token: it lists policy
    /// entries without values, and adds, rotates, edits, and enrolls passkeys through passkey
    /// approvals. Broker mode is for Linux and macOS. --broker opens it even when the broker
    /// does not answer yet.
    ///
    /// With --profile, or when no broker answers, it opens the profile named default, or the
    /// only profile. When the profile does not exist yet, it asks for a machine token and
    /// saves the profile as `bas auth login` does.
    Tui(TuiArgs),
    /// Run the credential broker, normally as the systemd service bas-broker.service on
    /// Linux or the LaunchDaemon io.github.bjoernaagaard.bas.broker on macOS.
    ///
    /// The broker reads the machine token from the file bws in $CREDENTIALS_DIRECTORY,
    /// serves an HTTP and JSON API on a unix socket to the uids in broker.toml, runs an
    /// HTTPS proxy that adds policy credentials to requests for policy hosts, an ssh-agent
    /// that signs with policy keys, and approval pages where a passkey approves
    /// changes. It records one audit entry with BAS_AUDIT=1 per credential use,
    /// change, or refusal: in the journal on Linux, in an append-only file on macOS.
    #[cfg(unix)]
    Broker(BrokerArgs),
    /// Propose a new proxy secret. You type its value on the approval page.
    ///
    /// The broker opens an approval and bas prints its URL, then waits. After a passkey
    /// approves, the broker creates the secret in Bitwarden, adds [secret.NAME] to the
    /// active policy, and bas rewrites your policy proposal from the active policy.
    /// The value never passes through this terminal.
    #[cfg(unix)]
    Add(AddArgs),
    /// Rotate a secret: drop minted tokens at once, or replace a stored value.
    ///
    /// NAME is a [secret.NAME] entry, whose new value you type on the approval page, or
    /// github or tailscale, whose cached tokens the broker drops so the next request mints
    /// new ones.
    #[cfg(unix)]
    Rotate(RotateArgs),
    /// Edit the policy proposal and ask a passkey to approve it.
    #[cfg(unix)]
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Show the broker's audit entries.
    ///
    /// On Linux, reads `journalctl _SYSTEMD_UNIT=UNIT BAS_AUDIT=1 -o json`, which needs
    /// membership in the adm or systemd-journal group. On macOS, asks the broker, because
    /// only the broker can read its audit file.
    #[cfg(unix)]
    Audit(AuditArgs),
    /// Manage the passkeys that approve broker requests.
    #[cfg(unix)]
    #[command(subcommand)]
    Passkey(PasskeyCommand),
}

#[cfg(unix)]
#[derive(Debug, Args)]
pub struct AddArgs {
    /// Policy name of the new entry, also the key of the new Bitwarden secret.
    pub name: String,
    /// Host the proxy adds the credential for, such as api.example.com.
    #[arg(long)]
    pub host: String,
    /// Header the proxy sets.
    #[arg(long, default_value = "Authorization")]
    pub header: String,
    /// Header value, with {secret} where the value goes.
    #[arg(long, default_value = "Bearer {secret}")]
    pub value: String,
    /// Allowed request, as "METHOD /path/glob" where * matches anything. Repeat for more.
    #[arg(long, required = true, value_name = "METHOD PATH")]
    pub allow: Vec<String>,
}

#[cfg(unix)]
#[derive(Debug, Args)]
pub struct RotateArgs {
    /// A [secret.NAME] entry, github, or tailscale.
    pub name: String,
}

#[cfg(unix)]
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Open the proposal in $VISUAL or $EDITOR, send it, and wait for approval.
    ///
    /// The proposal is policy.toml in the bas configuration directory: BAS_CONFIG_DIR, or
    /// ~/.config/bas on Linux and ~/Library/Application Support/bas on macOS. When it does
    /// not exist, bas starts it from the active policy. After you save and quit, bas shows
    /// the diff from the active policy and the approval URL, then waits. After a passkey
    /// approves, bas rewrites the proposal from the active policy.
    Edit,
    /// List what the active policy lets programs on this machine use, without values.
    ///
    /// Prints one line per entry: its kind, its name, how to use it, and its settings.
    /// Proxy secrets work with `bas run --with NAME`, helper entries with `bas get REF`, ssh
    /// keys through the broker's ssh-agent, and github and tailscale through the proxy.
    Show(PolicyShowArgs),
}

#[cfg(unix)]
#[derive(Debug, Args)]
pub struct PolicyShowArgs {
    /// Print {"policy_hash","entries":[{"kind","name","use","details":[{"label","value"}]}]} instead of text.
    #[arg(long)]
    pub json: bool,
}

#[cfg(unix)]
#[derive(Debug, Subcommand)]
pub enum PasskeyCommand {
    /// Ask an enrolled passkey to approve enrolling one more.
    ///
    /// The approval page shows a one-time link, valid for 15 minutes. Open it on the
    /// device that should hold the new passkey. The link never reaches this terminal.
    Add(PasskeyAddArgs),
    /// List the passkeys that can approve requests, by name and the time each was added.
    List(PasskeyListArgs),
}

#[cfg(unix)]
#[derive(Debug, Args)]
pub struct PasskeyAddArgs {
    /// Replace every enrolled passkey with the ones you enroll through the link.
    ///
    /// The link stays valid for 15 minutes and enrolls as many passkeys as you like. The
    /// first passkey enrolled through it removes every passkey that was enrolled when you
    /// approved, so they can no longer approve. A new passkey may reuse the name of one
    /// it removes.
    #[arg(long)]
    pub replace: bool,
}

#[cfg(unix)]
#[derive(Debug, Args)]
pub struct PasskeyListArgs {
    /// Print {"passkeys":[{"label","added"}]} instead of text.
    #[arg(long)]
    pub json: bool,
}

#[cfg(unix)]
#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Show entries since this time: a span such as 30m, 1h, or 2d. On Linux also
    /// anything journalctl --since accepts, on macOS also an RFC 3339 time.
    #[arg(long)]
    pub since: Option<String>,
    /// Show only entries about this policy name.
    #[arg(long)]
    pub name: Option<String>,
    /// Broker unit. Defaults to BAS_BROKER_UNIT, or bas-broker.service.
    #[cfg(target_os = "linux")]
    #[arg(long)]
    pub unit: Option<String>,
    /// Print each entry as one JSON object per line.
    #[arg(long)]
    pub json: bool,
}

#[cfg(unix)]
#[derive(Debug, Args)]
pub struct BrokerArgs {
    /// Unix socket for the API.
    #[arg(long, value_name = "PATH", default_value = bas_broker::protocol::DEFAULT_SOCKET)]
    pub socket: PathBuf,
    /// Unix socket for the ssh-agent.
    #[arg(long, value_name = "PATH", default_value = bas_broker::protocol::DEFAULT_SSH_AGENT_SOCKET)]
    pub ssh_agent_socket: PathBuf,
    /// Machine settings: allowed uids, the Secrets Manager profile, and the addresses.
    #[arg(long, value_name = "PATH", default_value = "/etc/bas/broker.toml")]
    pub config: PathBuf,
    /// Private directory for the active policy, the passkeys, and the proxy's certificate
    /// authority.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_STATE_DIR)]
    pub state_dir: PathBuf,
    /// File to write with the system roots and the proxy's certificate authority.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_CA_BUNDLE)]
    pub ca_bundle: PathBuf,
    /// Append-only audit file. Root creates it and sets the sappnd flag on it.
    #[cfg(not(target_os = "linux"))]
    #[arg(long, value_name = "PATH", default_value = "/var/log/bas/audit.jsonl")]
    pub audit_log: PathBuf,
}

#[cfg(target_os = "linux")]
const DEFAULT_STATE_DIR: &str = "/var/lib/bas";
#[cfg(all(unix, not(target_os = "linux")))]
const DEFAULT_STATE_DIR: &str = "/var/db/bas";
#[cfg(target_os = "linux")]
const DEFAULT_CA_BUNDLE: &str = "/run/bas/ca-bundle.pem";
#[cfg(all(unix, not(target_os = "linux")))]
const DEFAULT_CA_BUNDLE: &str = "/var/run/bas/ca-bundle.pem";

#[derive(Debug, Args)]
pub struct TuiArgs {
    /// Direct profile to open, or to create on the sign-in screen.
    #[arg(long)]
    pub profile: Option<String>,
    /// Manage the bas broker's policy instead of a direct profile.
    #[cfg(unix)]
    #[arg(long, conflicts_with = "profile")]
    pub broker: bool,
}

#[derive(Debug, Subcommand)]
pub enum GrantCommand {
    /// Let one paired device receive exact secrets without a prompt, until revoked.
    ///
    /// The device must be paired with the listener of --profile, and the grant is bound
    /// to that profile's organization. Prints the grant as one JSON line:
    /// {"id","state","device","profile","organization","secrets"}. An identical active
    /// grant is printed instead of a duplicate.
    Add(GrantAddArgs),
    /// List grants, active and revoked.
    List(GrantListArgs),
    /// Revoke a grant and report only after the revocation is on disk.
    ///
    /// Waits while a listener commits a reply to its relay client, so once this succeeds
    /// no listener commits another reply under this grant, including on open connections.
    /// Already queued responses may arrive later and cannot be recalled. Prints the grant
    /// as one JSON line.
    Revoke(GrantRevokeArgs),
}

#[derive(Debug, Args)]
pub struct GrantAddArgs {
    /// Direct profile whose listener delivers the secrets.
    #[arg(long)]
    pub profile: String,
    /// Identity fingerprint of the paired device, as shown by `bas auth list`.
    #[arg(long, value_name = "FINGERPRINT")]
    pub device: String,
    /// Secret ID the device may receive. Repeat for more IDs.
    #[arg(long = "secret", value_name = "SECRET-ID", required = true)]
    pub secrets: Vec<String>,
}

#[derive(Debug, Args)]
pub struct GrantListArgs {
    /// Only grants of this listener profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Print {"grants":[...]} instead of text lines.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct GrantRevokeArgs {
    /// ID of the grant, as printed by `bas grant add` or `bas grant list`.
    pub grant: String,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Authenticate a machine token and save the profile only after it succeeds.
    ///
    /// In a terminal without an input flag, bas asks for the token and hides what you
    /// paste. --stdin and --clipboard read it from piped stdin or the clipboard. Either way
    /// it is saved in the OS credential store, or with --from-env the profile reads
    /// BWS_ACCESS_TOKEN at every use. Never pass a token as an argument. The organization
    /// comes from Bitwarden's answer, and without an endpoint bas tries bitwarden.com, then
    /// bitwarden.eu.
    Login(LoginArgs),
    /// Authenticate an existing profile and report its organization and endpoint.
    Status(ProfileArg),
    /// Delete a profile and its stored machine token.
    ///
    /// For a direct profile this also removes its paired devices and revokes its grants.
    Logout(ProfileArg),
    /// List configured profiles and paired devices without contacting a server.
    List,
}

#[derive(Debug, Args)]
pub struct ListenArgs {
    /// Direct profile whose Secrets Manager access the listener uses.
    #[arg(long)]
    pub profile: String,
    /// Agent Access relay: wss://HOST, or ws:// to a loopback address.
    #[arg(long, value_name = "URL")]
    pub relay: String,
    /// Secret ID remote devices may request. Repeat for more IDs.
    #[arg(long = "allow", value_name = "SECRET-ID", required = true)]
    pub allow: Vec<String>,
    /// Show a pairing code on this terminal and accept one new device.
    #[arg(long)]
    pub pair: bool,
    /// Label for the device paired with --pair.
    #[arg(long, value_name = "NAME", requires = "pair")]
    pub peer_name: Option<String>,
}

#[derive(Debug, Args)]
pub struct PairArgs {
    /// Name of the remote profile to create, used in bas://PROFILE/SECRET-ID references.
    pub profile: String,
    /// Agent Access relay the listener uses: wss://HOST, or ws:// to a loopback address.
    /// Required.
    #[arg(long, value_name = "URL")]
    pub relay: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("token").args(["stdin", "clipboard", "from_env"])))]
pub struct LoginArgs {
    /// Profile name used in bas://PROFILE/SECRET-ID references.
    #[arg(default_value = bas_core::login::DEFAULT_PROFILE)]
    pub profile: String,
    /// Organization ID the machine token must belong to. Default: the token's own.
    #[arg(long, value_name = "UUID")]
    pub organization: Option<String>,
    #[command(flatten)]
    pub endpoint: EndpointArgs,
    /// Read the machine token from piped stdin and store it in the OS credential store.
    #[arg(long)]
    pub stdin: bool,
    /// Read the machine token from the clipboard and store it in the OS credential store.
    #[arg(long)]
    pub clipboard: bool,
    /// Store nothing; read BWS_ACCESS_TOKEN at every use (headless automation).
    #[arg(long)]
    pub from_env: bool,
}

#[derive(Debug, Args)]
pub struct EndpointArgs {
    /// Hosted Bitwarden region. Default: the profile's, else us, then eu.
    #[arg(long, value_enum)]
    pub region: Option<RegionArg>,
    /// Self-hosted server base URL; uses URL/api and URL/identity.
    #[arg(long, value_name = "URL")]
    pub server_url: Option<String>,
    /// Explicit API URL, together with --identity-url.
    #[arg(long, value_name = "URL", requires = "identity_url")]
    pub api_url: Option<String>,
    /// Explicit identity URL, together with --api-url.
    #[arg(long, value_name = "URL", requires = "api_url")]
    pub identity_url: Option<String>,
}

/// Hosted Bitwarden region, as named on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RegionArg {
    /// bitwarden.com
    Us,
    /// bitwarden.eu
    Eu,
}

impl From<RegionArg> for Region {
    fn from(region: RegionArg) -> Self {
        match region {
            RegionArg::Us => Self::Us,
            RegionArg::Eu => Self::Eu,
        }
    }
}

impl From<EndpointArgs> for EndpointFlags {
    fn from(args: EndpointArgs) -> Self {
        Self {
            region: args.region.map(Region::from),
            server_url: args.server_url,
            api_url: args.api_url,
            identity_url: args.identity_url,
        }
    }
}

#[derive(Debug, Args)]
pub struct ProfileArg {
    /// Profile name.
    pub profile: String,
}

#[derive(Debug, Args)]
pub struct FindArgs {
    /// Case-insensitive key fragments. Each matching secret is listed once. No query lists all.
    pub queries: Vec<String>,
    /// Profile to search.
    #[arg(long)]
    pub profile: String,
    /// Restrict the search to one project ID.
    #[arg(long, value_name = "UUID")]
    pub project: Option<String>,
    /// Print {"matches":[...],"unmatched":[...]} instead of text lines.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("secrets").required(true).multiple(true).args(["bindings", "with"])))]
pub struct RunArgs {
    /// Binding NAME=bas://PROFILE/SECRET-ID. Repeat for more variables.
    #[arg(long = "env", value_name = "NAME=REFERENCE")]
    pub bindings: Vec<String>,
    /// Proxy entry of the broker's policy the program uses through the proxy. Repeat for
    /// more. The program gets proxy settings, never the value.
    #[arg(long = "with", value_name = "NAME")]
    pub with: Vec<String>,
    /// Program and arguments, after --.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Reference bas://PROFILE/SECRET-ID on the helper allowlist.
    pub reference: String,
}

#[derive(Debug, Subcommand)]
pub enum HelperCommand {
    /// Let `bas get` print the value of one reference.
    ///
    /// Asks you to type a one-time code on the controlling terminal, so a program without
    /// your terminal cannot add a reference by itself.
    Allow(HelperReferenceArgs),
    /// List the references that `bas get` may print.
    List(HelperListArgs),
    /// Stop `bas get` from printing the value of one reference.
    Revoke(HelperReferenceArgs),
}

#[derive(Debug, Args)]
pub struct HelperReferenceArgs {
    /// Reference bas://PROFILE/SECRET-ID.
    pub reference: String,
}

#[derive(Debug, Args)]
pub struct HelperListArgs {
    /// Print {"helpers":[...]} instead of one reference per line.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// Write a template of NAME=bas://PROFILE/SECRET-ID lines. Values are never written.
    Write(EnvWriteArgs),
    /// Run a program with the bindings of a template, like `bas run`.
    ///
    /// Template lines are blank, # comments, or NAME=bas://PROFILE/SECRET-ID. Nothing is
    /// expanded or evaluated by a shell.
    Run(EnvRunArgs),
}

#[derive(Debug, Args)]
pub struct EnvWriteArgs {
    /// Template file to create.
    pub file: PathBuf,
    /// Binding NAME=bas://PROFILE/SECRET-ID. Repeat for more variables.
    #[arg(long = "env", value_name = "NAME=REFERENCE", required = true)]
    pub bindings: Vec<String>,
    /// Replace the file if it exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct EnvRunArgs {
    /// Template file to read.
    pub file: PathBuf,
    /// Program and arguments, after --.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("input").required(true).args(["stdin", "clipboard"])))]
pub struct CreateArgs {
    /// Profile to write to.
    #[arg(long)]
    pub profile: String,
    /// Secret key (name).
    #[arg(long)]
    pub key: String,
    /// Project ID the secret belongs to.
    #[arg(long, value_name = "UUID")]
    pub project: String,
    /// Read the value from piped stdin.
    #[arg(long)]
    pub stdin: bool,
    /// Read the value from the clipboard.
    #[arg(long)]
    pub clipboard: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("input").required(true).args(["stdin", "clipboard"])))]
pub struct UpdateArgs {
    /// Reference bas://PROFILE/SECRET-ID of the secret to update.
    pub reference: String,
    /// Read the new value from piped stdin.
    #[arg(long)]
    pub stdin: bool,
    /// Read the new value from the clipboard.
    #[arg(long)]
    pub clipboard: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Also authenticate this profile and confirm its organization.
    #[arg(long)]
    pub profile: Option<String>,
}
