//! `bas add`, `bas rotate`, `bas policy edit`, `bas passkey`, `bas audit`, and the broker
//! side of `bas get` and `bas helper list`: the commands that talk to the bas broker or read
//! its journal. Linux and macOS.
//!
//! Only `bas get` handles a secret value, the value of a `[helper.NAME]` entry that a
//! passkey approved. Other values are typed on the approval page.

use std::io::{self, Write};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::process::ExitCode;

use bas_broker::client::{self, Client, Outcome};
use bas_broker::proposal;
use bas_broker::protocol::{
    Accepted, AddSecret, ApprovalState, EntryKind, EntrySummary, HelperRequest, PolicyProposal,
    SecretEntry,
};
use bas_core::credential::SecretText;
use bas_core::reference::{EnvName, SecretRef};
use serde::Serialize;

use crate::cli::{AddArgs, AuditArgs};
use crate::output::{self, Error, Result};

/// Unit whose journal entries `bas audit` reads by default.
#[cfg(target_os = "linux")]
const DEFAULT_UNIT: &str = "bas-broker.service";
/// Environment variable that names another broker unit, such as a development unit.
#[cfg(target_os = "linux")]
const UNIT_VAR: &str = "BAS_BROKER_UNIT";
/// How long each wait on the broker lasts before bas asks again.
const WAIT_SECONDS: u32 = 60;

fn client() -> Client {
    Client::new(&client::socket_path())
}

/// Whether this machine runs a bas broker. Then `bas get` reads only the `[helper.NAME]`
/// entries of the broker's policy, because the broker holds the machine token.
pub fn is_broker_host() -> bool {
    client::socket_path().exists()
}

/// Asks the broker for the value of a `[helper.NAME]` entry.
pub fn helper_value(reference: &SecretRef) -> Result<SecretText> {
    let request = HelperRequest {
        reference: reference.to_string(),
    };
    let reply = crate::runtime()?
        .block_on(client().helper(&request))
        .map_err(|err| match err.kind() {
            bas_broker::ErrorKind::Refused => Error::new(format!(
                "{err}. On a broker host, bas get reads only references in a [helper.NAME] \
                 table of the broker's policy; add one with `bas policy edit`"
            )),
            _ => broker_error(err),
        })?;
    Ok(SecretText::new(reply.value))
}

/// The references of the `[helper.NAME]` entries of the broker's active policy.
pub fn helper_references() -> Result<Vec<String>> {
    let policy = crate::runtime()?
        .block_on(client().policy())
        .map_err(broker_error)?;
    let entries = bas_broker::protocol::summarize_policy(&policy.toml).map_err(Error::new)?;
    Ok(entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Helper)
        .filter_map(|entry| reference(entry).map(str::to_owned))
        .collect())
}

/// The `ref` setting of a policy entry.
fn reference(entry: &EntrySummary) -> Option<&str> {
    entry
        .details
        .iter()
        .find(|(label, _)| label == "ref")
        .map(|(_, text)| text.as_str())
}

fn broker_error(err: bas_broker::Error) -> Error {
    Error::new(err.to_string())
}

fn say(text: &str) -> Result<()> {
    writeln!(io::stdout().lock(), "{text}").map_err(crate::stdout_failed)
}

/// Prints the approval URL and waits until a passkey answers or the request expires.
fn wait(client: &Client, accepted: &Accepted) -> Result<ApprovalState> {
    eprintln!(
        "Approve with your passkey: {}\nWaiting for approval {} (it expires in 15 minutes)...",
        accepted.approval.url, accepted.approval.id
    );
    let runtime = crate::runtime()?;
    loop {
        let state = runtime
            .block_on(client.approval(&accepted.approval.id, WAIT_SECONDS))
            .map_err(broker_error)?;
        match state.state.as_str() {
            "pending" => {}
            "approved" => return Ok(state),
            "failed" => {
                return Err(Error::new(format!(
                    "the passkey approved, but the broker could not apply the change: {}",
                    state.error.unwrap_or_default()
                )));
            }
            other => return Err(Error::new(format!("the request was {other}"))),
        }
    }
}

/// Writes the active policy to the proposal file.
fn sync_proposal(client: &Client, path: &Path) -> Result<()> {
    let active = crate::runtime()?
        .block_on(client.policy())
        .map_err(broker_error)?;
    proposal::write(path, &active.toml).map_err(broker_error)
}

/// `bas add NAME --host H --allow ...`.
pub fn add(args: AddArgs) -> Result<ExitCode> {
    args.name
        .parse::<EnvName>()
        .map_err(|_| Error::usage("NAME must be a valid environment variable name"))?;
    let request = AddSecret {
        name: args.name.clone(),
        entry: SecretEntry {
            reference: String::new(),
            delivery: "proxy".to_owned(),
            host: Some(args.host),
            header: Some(args.header),
            value: Some(args.value),
            allow: Some(args.allow),
        },
    };
    let client = client();
    let outcome = crate::runtime()?
        .block_on(client.add_secret(&request))
        .map_err(broker_error)?;
    let Outcome::Waiting(accepted) = outcome else {
        return Err(Error::new("the bas broker sent an unexpected reply"));
    };
    let state = wait(&client, &accepted)?;
    let reference = state
        .result
        .as_ref()
        .and_then(|result| result.get("reference"))
        .and_then(|reference| reference.as_str())
        .unwrap_or("an unknown reference");
    sync_proposal(&client, &proposal::path().map_err(broker_error)?)?;
    say(&format!("added {} as {reference}", args.name))?;
    Ok(ExitCode::SUCCESS)
}

/// `bas rotate NAME`.
pub fn rotate(name: &str) -> Result<ExitCode> {
    let name_ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !name_ok {
        return Err(Error::usage(
            "NAME must be a policy name, github, or tailscale",
        ));
    }
    let client = client();
    let outcome = crate::runtime()?
        .block_on(client.rotate(name))
        .map_err(broker_error)?;
    match outcome {
        Outcome::Done(_) => say(&format!(
            "dropped the cached {name} tokens; the next request mints new ones"
        ))?,
        Outcome::Waiting(accepted) => {
            wait(&client, &accepted)?;
            say(&format!("rotated {name}"))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// One entry of `bas policy show`.
#[derive(Serialize)]
struct PolicyRow<'a> {
    kind: &'static str,
    name: &'a str,
    #[serde(rename = "use")]
    usage: String,
    // A list, not an object: a label such as `repo` repeats once per repository.
    details: Vec<Detail<'a>>,
}

#[derive(Serialize)]
struct Detail<'a> {
    label: &'a str,
    value: &'a str,
}

/// `bas policy show`: lists the entries of the active policy, without values.
pub fn policy_show(json: bool) -> Result<ExitCode> {
    let policy = crate::runtime()?
        .block_on(client().policy())
        .map_err(broker_error)?;
    let entries = bas_broker::protocol::summarize_policy(&policy.toml).map_err(Error::new)?;
    let rows: Vec<PolicyRow<'_>> = entries
        .iter()
        .map(|entry| {
            let (kind, usage) = match entry.kind {
                EntryKind::Secret => ("secret", format!("bas run --with {} -- CMD", entry.name)),
                EntryKind::Helper => (
                    "helper",
                    format!("bas get {}", reference(entry).unwrap_or_default()),
                ),
                EntryKind::Ssh => (
                    "ssh",
                    "ssh and git through the broker's ssh-agent".to_owned(),
                ),
                EntryKind::Github => (
                    "github",
                    "gh and git for the listed repositories".to_owned(),
                ),
                EntryKind::Tailscale => ("tailscale", "bas run --with tailscale -- CMD".to_owned()),
            };
            PolicyRow {
                kind,
                name: &entry.name,
                usage,
                details: entry
                    .details
                    .iter()
                    .map(|(label, value)| Detail { label, value })
                    .collect(),
            }
        })
        .collect();
    let mut out = io::stdout().lock();
    let written = if json {
        output::write_json(
            &mut out,
            &serde_json::json!({ "policy_hash": policy.hash, "entries": rows }),
        )
    } else {
        rows.iter().try_for_each(|row| {
            let details: String = row
                .details
                .iter()
                .map(|detail| format!("  {}={}", detail.label, detail.value))
                .collect();
            writeln!(
                out,
                "{:<9}  {}  use: {}{details}",
                row.kind, row.name, row.usage
            )
        })
    };
    written.map_err(crate::stdout_failed)?;
    Ok(ExitCode::SUCCESS)
}

/// `bas policy edit`.
pub fn policy_edit() -> Result<ExitCode> {
    let client = client();
    let path = proposal::path().map_err(broker_error)?;
    if !path.exists() {
        sync_proposal(&client, &path)?;
    }
    let status = proposal::editor(&path)
        .status()
        .map_err(|err| Error::new(format!("could not start the editor: {err}")))?;
    if !status.success() {
        return Err(Error::new("the editor failed; nothing was sent"));
    }
    let toml = proposal::read(&path).map_err(broker_error)?;
    let outcome = crate::runtime()?
        .block_on(client.propose_policy(&PolicyProposal { toml }))
        .map_err(|err| Error::new(format!("{}: {err}", path.display())))?;
    let accepted = match outcome {
        Outcome::Done(_) => {
            say("the proposal matches the active policy; nothing to approve")?;
            return Ok(ExitCode::SUCCESS);
        }
        Outcome::Waiting(accepted) => accepted,
    };
    if let Some(diff) = &accepted.diff {
        write!(io::stdout().lock(), "{diff}").map_err(crate::stdout_failed)?;
    }
    let state = wait(&client, &accepted)?;
    sync_proposal(&client, &path)?;
    let hash = state
        .result
        .as_ref()
        .and_then(|result| result.get("hash"))
        .and_then(|hash| hash.as_str())
        .unwrap_or_default()
        .to_owned();
    say(&format!("the active policy is now {hash}"))?;
    Ok(ExitCode::SUCCESS)
}

/// `bas passkey add [--replace]`.
pub fn passkey_add(replace: bool) -> Result<ExitCode> {
    let client = client();
    let outcome = crate::runtime()?
        .block_on(client.add_passkey(replace))
        .map_err(broker_error)?;
    let Outcome::Waiting(accepted) = outcome else {
        return Err(Error::new("the bas broker sent an unexpected reply"));
    };
    if replace {
        eprintln!(
            "The first passkey enrolled through the link removes every passkey enrolled now."
        );
    }
    wait(&client, &accepted)?;
    say(if replace {
        "approved; the approval page shows the enrollment link, which enrolls passkeys \
         for 15 minutes"
    } else {
        "approved; the approval page shows the one-time enrollment link"
    })?;
    Ok(ExitCode::SUCCESS)
}

/// `bas passkey list`: the enrolled passkeys, by name and the time each was added.
pub fn passkey_list(json: bool) -> Result<ExitCode> {
    let list = crate::runtime()?
        .block_on(client().passkeys())
        .map_err(broker_error)?;
    let mut out = io::stdout().lock();
    let written = if json {
        output::write_json(&mut out, &list)
    } else {
        list.passkeys
            .iter()
            .try_for_each(|passkey| writeln!(out, "{}  added {}", passkey.label, passkey.added))
    };
    written.map_err(crate::stdout_failed)?;
    Ok(ExitCode::SUCCESS)
}

/// `bas audit` on macOS: the broker reads its audit file for the caller.
#[cfg(not(target_os = "linux"))]
pub fn audit(args: AuditArgs) -> Result<ExitCode> {
    let since = args.since.as_deref().map(since_time).transpose()?;
    let client = client();
    let reply = crate::runtime()?
        .block_on(client.audit(since.as_deref(), args.name.as_deref()))
        .map_err(broker_error)?;
    let mut stdout = io::stdout().lock();
    for entry in &reply.entries {
        let field = |key: &str| {
            entry
                .get(key)
                .and_then(|value| value.as_str())
                .unwrap_or("")
        };
        let time = chrono::DateTime::parse_from_rfc3339(field("timestamp"))
            .map(|time| {
                time.with_timezone(&chrono::Utc)
                    .format("%Y-%m-%dT%H:%M:%SZ")
                    .to_string()
            })
            .unwrap_or_default();
        let written = if args.json {
            let mut object = serde_json::Map::new();
            object.insert("time".to_owned(), time.into());
            if let Some(fields) = entry.as_object() {
                for (key, value) in fields {
                    let shown =
                        !matches!(key.as_str(), "timestamp" | "level" | "target" | "bas_audit");
                    if shown {
                        let value = match value {
                            serde_json::Value::String(_) => value.clone(),
                            other => other.to_string().into(),
                        };
                        object.insert(key.clone(), value);
                    }
                }
            }
            writeln!(stdout, "{}", serde_json::Value::Object(object))
        } else {
            writeln!(stdout, "{time}  {:<8} {}", field("event"), field("message"))
        };
        written.map_err(crate::stdout_failed)?;
    }
    if reply.entries.is_empty() {
        output::write_error(&format!(
            "no audit entries from the broker at {}",
            client.socket().display()
        ));
    }
    Ok(ExitCode::SUCCESS)
}

/// Turns a span such as `30m`, `1h`, or `2d` into the RFC 3339 time that long ago. An RFC
/// 3339 time passes through.
#[cfg(not(target_os = "linux"))]
fn since_time(since: &str) -> Result<String> {
    if chrono::DateTime::parse_from_rfc3339(since).is_ok() {
        return Ok(since.to_owned());
    }
    let digits = since.trim_end_matches(['s', 'm', 'h', 'd']);
    let amount = digits
        .parse::<i64>()
        .ok()
        .filter(|_| since.len() - digits.len() == 1);
    let span = amount.and_then(|amount| match &since[digits.len()..] {
        "s" => chrono::Duration::try_seconds(amount),
        "m" => chrono::Duration::try_minutes(amount),
        "h" => chrono::Duration::try_hours(amount),
        _ => chrono::Duration::try_days(amount),
    });
    let span = span.ok_or_else(|| {
        Error::usage("--since takes a span such as 30m, 1h, or 2d, or an RFC 3339 time")
    })?;
    Ok((chrono::Utc::now() - span).to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// `bas audit` on Linux: reads the broker unit's journal entries.
#[cfg(target_os = "linux")]
pub fn audit(args: AuditArgs) -> Result<ExitCode> {
    let mut unit = args
        .unit
        .or_else(|| std::env::var(UNIT_VAR).ok().filter(|unit| !unit.is_empty()))
        .unwrap_or_else(|| DEFAULT_UNIT.to_owned());
    if !unit.contains('.') {
        unit.push_str(".service");
    }
    let mut command = Command::new("journalctl");
    command
        .arg(format!("_SYSTEMD_UNIT={unit}"))
        .arg("BAS_AUDIT=1")
        .args(["-o", "json", "--no-pager"]);
    if let Some(name) = &args.name {
        command.arg(format!("NAME={name}"));
    }
    if let Some(since) = &args.since {
        command.arg(format!("--since={}", since_arg(since)));
    }
    let output = command
        .output()
        .map_err(|err| Error::new(format!("could not run journalctl: {err}")))?;
    if !output.status.success() {
        return Err(Error::new(format!(
            "journalctl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let mut stdout = io::stdout().lock();
    let mut count = 0usize;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let field = |key: &str| {
            entry
                .get(key)
                .and_then(|value| value.as_str())
                .unwrap_or("")
        };
        let time = field("__REALTIME_TIMESTAMP")
            .parse::<i64>()
            .ok()
            .and_then(chrono::DateTime::from_timestamp_micros)
            .map(|time| time.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_default();
        let written = if args.json {
            let mut object = serde_json::Map::new();
            object.insert("time".to_owned(), time.into());
            if let Some(fields) = entry.as_object() {
                for (key, value) in fields {
                    let shown = !key.starts_with('_')
                        && !key.starts_with("SYSLOG")
                        && !matches!(
                            key.as_str(),
                            "PRIORITY" | "CODE_FILE" | "CODE_LINE" | "TARGET" | "BAS_AUDIT"
                        );
                    if shown && value.is_string() {
                        object.insert(key.to_lowercase(), value.clone());
                    }
                }
            }
            writeln!(stdout, "{}", serde_json::Value::Object(object))
        } else {
            writeln!(stdout, "{time}  {:<8} {}", field("EVENT"), field("MESSAGE"))
        };
        written.map_err(crate::stdout_failed)?;
        count += 1;
    }
    if count == 0 {
        output::write_error(&format!("no audit entries for {unit}"));
    }
    Ok(ExitCode::SUCCESS)
}

/// Turns a span such as `30m`, `1h`, or `2d` into journalctl's `-30m`. Anything else
/// passes through.
#[cfg(target_os = "linux")]
fn since_arg(since: &str) -> String {
    let digits = since.trim_end_matches(['s', 'm', 'h', 'd']);
    let unit_len = since.len() - digits.len();
    if unit_len == 1 && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        format!("-{since}")
    } else {
        since.to_owned()
    }
}
