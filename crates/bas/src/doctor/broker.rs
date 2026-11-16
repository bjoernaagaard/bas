//! The broker checks: whether this client reads the running broker's status and policy,
//! and whether the broker's machine account can see every reference of that policy.

use std::time::Duration;

use bas_broker::ErrorKind;
use bas_broker::client::{self, Client};
use bas_broker::protocol::{Listing, PolicyReferences};

use crate::output::{Check, Status};

const COMPATIBILITY: &str = "broker compatibility";
const REFERENCES: &str = "policy references";
/// Longest wait for each socket request.
const DEADLINE: Duration = Duration::from_secs(10);
const UPDATE_CLIENT: &str = "Update the client to a release supporting broker entry summaries, \
                             then rerun policy display. Inspect the actual reply if an updated \
                             client still fails.";
const RERUN: &str = "Rerun `bas doctor --broker` before changing a reference.";

/// Checks the broker at `BAS_BROKER_SOCKET`, or the default socket: compatibility first,
/// then the references of the policy whose identity the compatibility check saw.
pub async fn broker() -> [Check; 2] {
    let client = Client::new(&client::socket_path());
    let (compatibility, policy_hash) = compatibility(&client).await;
    let references = match policy_hash {
        Some(before) => references(&client, &before).await,
        None => Check {
            status: Status::Warning,
            label: REFERENCES,
            detail: "not checked, because the broker gave no current policy identity".to_owned(),
            evidence: Vec::new(),
            fix: Some(format!(
                "Resolve the {COMPATIBILITY} result first, then rerun `bas doctor --broker`."
            )),
        },
    };
    [compatibility, references]
}

/// A socket request that gave no usable reply.
enum Failure {
    TimedOut,
    Unreachable(bas_broker::Error),
    Unreadable(bas_broker::Error),
    Refused {
        http_status: Option<u16>,
        error: bas_broker::Error,
    },
    Other(bas_broker::Error),
}

async fn within<T>(call: impl Future<Output = Result<T, bas_broker::Error>>) -> Result<T, Failure> {
    match tokio::time::timeout(DEADLINE, call).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(error)) => Err(match error.kind() {
            ErrorKind::Unreachable => Failure::Unreachable(error),
            ErrorKind::Unreadable => Failure::Unreadable(error),
            ErrorKind::Refused => Failure::Refused {
                http_status: error.http_status(),
                error,
            },
            _ => Failure::Other(error),
        }),
        Err(_) => Err(Failure::TimedOut),
    }
}

/// Reads `GET /v1/status` and `GET /v1/policy` the way `bas policy show` does. Returns the
/// policy identity from the status reply when there was one.
async fn compatibility(client: &Client) -> (Check, Option<String>) {
    let socket = client.socket().display().to_string();
    let mut evidence = vec![format!("socket {socket}")];
    let status = match within(client.status()).await {
        Ok(status) => status,
        Err(failure) => {
            return (
                unavailable(COMPATIBILITY, "GET /v1/status", &failure, &socket, evidence),
                None,
            );
        }
    };
    evidence.push(format!(
        "GET /v1/status: broker {}, policy {}",
        status.version,
        short_hash(&status.policy_hash)
    ));
    let policy = match within(client.policy()).await {
        Ok(policy) => policy,
        Err(failure) => {
            return (
                unavailable(COMPATIBILITY, "GET /v1/policy", &failure, &socket, evidence),
                Some(status.policy_hash),
            );
        }
    };
    let source = if policy.entries.is_some() {
        "the broker's entry summaries"
    } else {
        "the policy text, because the broker sent no summaries"
    };
    let entries = match policy.entries() {
        Ok(entries) => entries,
        Err(reason) => {
            evidence.push(reason);
            return (
                Check {
                    status: Status::Failed,
                    label: COMPATIBILITY,
                    detail: "decoding: this client cannot display the active policy".to_owned(),
                    evidence,
                    fix: Some(UPDATE_CLIENT.to_owned()),
                },
                Some(status.policy_hash),
            );
        }
    };
    evidence.push(format!(
        "GET /v1/policy: {} entries through ActivePolicy::entries() from {source}",
        entries.len()
    ));
    let mine = env!("CARGO_PKG_VERSION");
    let check = if status.version == mine {
        Check {
            status: Status::Ready,
            label: COMPATIBILITY,
            detail: format!(
                "status and policy display work with broker {}: {} entries",
                status.version,
                entries.len()
            ),
            evidence,
            fix: None,
        }
    } else {
        Check {
            status: Status::Warning,
            label: COMPATIBILITY,
            detail: format!(
                "status and policy display work, but bas {mine} and broker {} differ",
                status.version
            ),
            evidence,
            fix: Some(drift_fix(mine, &status.version)),
        }
    };
    (check, Some(status.policy_hash))
}

/// The fix for a version drift, by which side is older.
fn drift_fix(mine: &str, broker: &str) -> String {
    let parse = |version: &str| {
        version
            .split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()
    };
    let client_older = matches!(
        (parse(mine), parse(broker)),
        (Some(mine), Some(broker)) if mine < broker
    );
    if client_older {
        format!("Update bas to {broker}, then rerun `bas doctor --broker`.")
    } else {
        "Restart the broker through its configured service manager, then query /v1/status \
         again. Updating a binary does not replace a running process."
            .to_owned()
    }
}

/// Asks the broker which references its machine account can see, and accepts the answer
/// only for the policy identity seen before and after it.
async fn references(client: &Client, before: &str) -> Check {
    let socket = client.socket().display().to_string();
    let operation = "GET /v1/doctor/references";
    let reply = match within(client.doctor_references()).await {
        Ok(reply) => reply,
        Err(failure) => {
            return unavailable(REFERENCES, operation, &failure, &socket, Vec::new());
        }
    };
    let after = within(client.status())
        .await
        .ok()
        .map(|status| status.policy_hash);
    let PolicyReferences {
        policy_hash,
        listing,
    } = reply;
    let mut evidence = vec![
        format!("{operation}: listing {}", listing.outcome()),
        format!(
            "policy {} before, {} in the reply, {} after",
            short_hash(before),
            short_hash(&policy_hash),
            after.as_deref().map_or("unavailable", short_hash)
        ),
    ];
    let current = policy_hash == before && after.as_deref() == Some(before);
    let warning = |detail: String, evidence: Vec<String>, fix: &str| Check {
        status: Status::Warning,
        label: REFERENCES,
        detail,
        evidence,
        fix: Some(fix.to_owned()),
    };
    let settled = matches!(listing, Listing::NotNeeded | Listing::Listed { .. });
    if settled && !current {
        return warning(
            "the policy changed during the check, so the result is not current".to_owned(),
            evidence,
            "Rerun `bas doctor --broker`.",
        );
    }
    match listing {
        Listing::NotNeeded => Check {
            status: Status::Ready,
            label: REFERENCES,
            detail: "the policy names no reference; 0 checked".to_owned(),
            evidence,
            fix: None,
        },
        Listing::Listed { references } => {
            let total = references.len();
            let hidden: Vec<_> = references
                .into_iter()
                .filter(|reference| !reference.visible)
                .collect();
            if hidden.is_empty() {
                return Check {
                    status: Status::Ready,
                    label: REFERENCES,
                    detail: format!(
                        "all {total} distinct references are visible to the broker's machine \
                         account"
                    ),
                    evidence,
                    fix: None,
                };
            }
            evidence.extend(hidden.iter().map(|reference| {
                format!(
                    "{} at {}",
                    reference.reference,
                    reference.locations.join(", ")
                )
            }));
            Check {
                status: Status::Failed,
                label: REFERENCES,
                detail: format!(
                    "{} of {total} references are not visible to the broker's machine account",
                    hidden.len()
                ),
                evidence,
                fix: Some(
                    "Check the broker machine account's project access. Restore the intended \
                     access, or propose the correct reference with `bas policy edit` for \
                     approval. bas never deletes or rotates a secret for this."
                        .to_owned(),
                ),
            }
        }
        Listing::Empty { references } => warning(
            format!(
                "the broker's machine account listed no identifiers, so the visibility of {} \
                 references is unknown",
                references.len()
            ),
            evidence,
            &format!("Check the broker machine account's project access. {RERUN}"),
        ),
        Listing::Failed { references } => warning(
            format!(
                "the broker could not list secret identifiers, so the visibility of {} \
                 references is unknown; its log has the reason",
                references.len()
            ),
            evidence,
            &format!(
                "Restore the broker's connection to Secrets Manager or its machine account's \
                 authentication. {RERUN}"
            ),
        ),
        Listing::TimedOut { references } => warning(
            format!(
                "the broker's identifier listing did not finish within its deadline, so the \
                 visibility of {} references is unknown",
                references.len()
            ),
            evidence,
            RERUN,
        ),
        Listing::PolicyChanged { .. } => warning(
            "the policy changed while the broker listed identifiers".to_owned(),
            evidence,
            "Rerun `bas doctor --broker`.",
        ),
        Listing::Unknown => warning(
            "this client does not know the broker's listing outcome".to_owned(),
            evidence,
            "Update bas to the broker's version, then rerun `bas doctor --broker`.",
        ),
    }
}

/// The verdict for a request that gave no usable reply.
fn unavailable(
    label: &'static str,
    operation: &str,
    failure: &Failure,
    socket: &str,
    mut evidence: Vec<String>,
) -> Check {
    let reconnect = format!(
        "Restore the connection to the broker at {socket}, for example by starting its \
         service, then rerun `bas doctor --broker`."
    );
    let uid = rustix::process::getuid().as_raw();
    let (status, detail, fix) = match failure {
        Failure::TimedOut => (
            Status::Warning,
            format!(
                "{operation} did not answer within {} seconds",
                DEADLINE.as_secs()
            ),
            Some(reconnect),
        ),
        Failure::Unreachable(error) => {
            evidence.push(error.to_string());
            (
                Status::Warning,
                format!("could not reach the broker for {operation}"),
                Some(reconnect),
            )
        }
        Failure::Unreadable(error) => {
            evidence.push(error.to_string());
            (
                Status::Failed,
                format!("decoding: this client could not read the reply to {operation}"),
                Some(UPDATE_CLIENT.to_owned()),
            )
        }
        Failure::Refused {
            http_status: Some(404),
            error,
        } if label == REFERENCES => {
            evidence.push(error.to_string());
            (
                Status::Warning,
                format!("the broker does not support {operation} (HTTP 404)"),
                Some(
                    "Update the broker to a release containing the endpoint and restart it. The \
                     reference result stays unavailable until then."
                        .to_owned(),
                ),
            )
        }
        Failure::Refused { http_status, error } => {
            evidence.push(error.to_string());
            let code = http_status.map_or_else(|| "no status".to_owned(), |code| code.to_string());
            let detail = if *http_status == Some(403) {
                format!("authorization: the broker refused {operation} for uid {uid} (HTTP 403)")
            } else {
                format!("the broker refused {operation} (HTTP {code})")
            };
            // A refused status or policy request is a compatibility failure. The reference
            // check only lacks evidence then, and the compatibility check already failed.
            let status = if label == COMPATIBILITY {
                Status::Failed
            } else {
                Status::Warning
            };
            let fix = (*http_status == Some(403)).then(|| {
                format!(
                    "Restore UID access: add uid {uid} to allow-uids in the broker's settings, \
                     then rerun `bas doctor --broker`."
                )
            });
            (status, detail, fix)
        }
        Failure::Other(error) => {
            evidence.push(error.to_string());
            (Status::Warning, format!("could not send {operation}"), None)
        }
    };
    Check {
        status,
        label,
        detail,
        evidence,
        fix,
    }
}

/// The first 12 hex digits, enough to tell policy snapshots apart in a report.
fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}
