//! Requests that wait for a passkey approval.
//!
//! Each request keeps the WebAuthn challenges issued for it, at most eight, so an assertion
//! approves only the request whose challenge it signed. The first assertion that passes
//! clears them, so none can approve twice. A failed assertion uses nothing up, so a forged
//! answer cannot cancel the real one. Requests expire after 15 minutes. They live in
//! memory, so a broker restart drops every pending request.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use bas_core::Uuid;
use bas_core::reference::SecretRef;
use tokio::sync::Notify;
use webauthn_rs::prelude::PasskeyAuthentication;

use crate::audit::Peer;
use crate::passkeys::now_text;
use crate::policy::SecretFile;
use crate::protocol::ApprovalState;

/// How long a request waits for an approval.
const LIFETIME: Duration = Duration::from_secs(15 * 60);
/// Challenges kept per request.
const MAX_CHALLENGES: usize = 8;
/// How long a finished request stays readable.
const KEEP: Duration = Duration::from_secs(60 * 60);

/// What a request asks for.
#[derive(Debug, Clone)]
pub enum Kind {
    /// `bas add`: create a secret from a value typed on the approval page, and add its entry.
    AddSecret {
        /// Policy name and secret key.
        name: String,
        /// The entry without `ref`.
        entry: SecretFile,
    },
    /// `bas rotate`: replace a stored value with one typed on the approval page.
    Rotate {
        /// Policy name.
        name: String,
        /// The secret to update.
        reference: SecretRef,
    },
    /// `bas policy edit`: replace the active policy.
    Policy {
        /// The proposed text.
        toml: String,
        /// Hash of the active policy the diff was made against.
        base_hash: String,
        /// Unified diff from the active policy.
        diff: String,
    },
    /// `bas passkey add`: show a new enrollment link on the approval page.
    Passkey {
        /// `--replace`: the link enrolls passkeys until it expires, and the first one
        /// removes every passkey enrolled when the link was made.
        replace: bool,
    },
}

impl Kind {
    /// Short name of the kind, used in audit entries.
    pub fn label(&self) -> &'static str {
        match self {
            Self::AddSecret { .. } => "add",
            Self::Rotate { .. } => "rotate",
            Self::Policy { .. } => "policy",
            Self::Passkey { .. } => "passkey",
        }
    }

    /// What the request is about, used in audit entries.
    pub fn subject(&self) -> String {
        match self {
            Self::AddSecret { name, .. } | Self::Rotate { name, .. } => name.clone(),
            Self::Policy { toml, .. } => crate::policy::hash(toml),
            Self::Passkey { replace } => {
                if *replace {
                    "replace".to_owned()
                } else {
                    String::new()
                }
            }
        }
    }

    /// Whether the approver must type a secret value to approve.
    pub fn needs_value(&self) -> bool {
        matches!(self, Self::AddSecret { .. } | Self::Rotate { .. })
    }
}

/// Where a request stands.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// Waiting for an approval.
    Pending,
    /// Approved and applied, with what the change produced.
    Approved(serde_json::Value),
    /// Denied on the approval page.
    Denied,
    /// Nobody answered in time.
    Expired,
    /// Approved, but the change could not be applied.
    Failed(String),
}

impl Outcome {
    fn state(&self) -> ApprovalState {
        let (state, result, error) = match self {
            Self::Pending => ("pending", None, None),
            Self::Approved(result) => ("approved", Some(result.clone()), None),
            Self::Denied => ("denied", None, None),
            Self::Expired => ("expired", None, None),
            Self::Failed(error) => ("failed", None, Some(error.clone())),
        };
        ApprovalState {
            state: state.to_owned(),
            result,
            error,
        }
    }
}

/// What the approval page shows.
#[derive(Debug, Clone)]
pub struct View {
    /// Approval ID.
    pub id: Uuid,
    /// What is asked.
    pub kind: Kind,
    /// Who asked, from the kernel.
    pub peer: Peer,
    /// When, in RFC 3339.
    pub created_at: String,
    /// Where it stands.
    pub outcome: Outcome,
    /// Seconds until it expires, while pending.
    pub expires_in: u64,
}

struct Approval {
    kind: Kind,
    peer: Peer,
    created_at: String,
    created: Instant,
    finished: Option<Instant>,
    outcome: Outcome,
    challenges: Vec<PasskeyAuthentication>,
    /// An assertion passed and the change is being applied.
    applying: bool,
}

/// Why a step on the approval page was refused.
#[derive(Debug)]
pub enum Refused {
    /// No such request.
    Unknown,
    /// The request is no longer pending, or is being applied.
    NotPending,
    /// No challenge was started for the request.
    NoChallenge,
}

/// Every request, pending or recently finished.
#[derive(Default)]
pub struct Approvals {
    inner: Mutex<BTreeMap<Uuid, Approval>>,
    changed: Notify,
}

impl Approvals {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<Uuid, Approval>> {
        let mut map = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        for approval in map.values_mut() {
            if matches!(approval.outcome, Outcome::Pending)
                && !approval.applying
                && now.duration_since(approval.created) > LIFETIME
            {
                approval.outcome = Outcome::Expired;
                approval.challenges.clear();
                approval.finished = Some(now);
            }
        }
        map.retain(|_, approval| {
            approval
                .finished
                .is_none_or(|finished| now.duration_since(finished) < KEEP)
        });
        map
    }

    /// Adds a pending request and returns its ID.
    pub fn create(&self, kind: Kind, peer: Peer) -> Uuid {
        let id = Uuid::new_v4();
        self.lock().insert(
            id,
            Approval {
                kind,
                peer,
                created_at: now_text(),
                created: Instant::now(),
                finished: None,
                outcome: Outcome::Pending,
                challenges: Vec::new(),
                applying: false,
            },
        );
        id
    }

    /// Pending requests, oldest first.
    pub fn pending(&self) -> Vec<View> {
        let map = self.lock();
        let mut views: Vec<View> = map
            .iter()
            .filter(|(_, approval)| matches!(approval.outcome, Outcome::Pending))
            .map(|(id, approval)| view(*id, approval))
            .collect();
        views.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        views
    }

    /// The page view of one request.
    pub fn view(&self, id: Uuid) -> Option<View> {
        self.lock().get(&id).map(|approval| view(id, approval))
    }

    /// The state of one request, waiting up to `wait` while it is pending.
    pub async fn wait(&self, id: Uuid, wait: Duration) -> Option<ApprovalState> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let outcome = self
                .lock()
                .get(&id)
                .map(|approval| approval.outcome.clone())?;
            if !matches!(outcome, Outcome::Pending) {
                return Some(outcome.state());
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Some(outcome.state());
            }
            // Wake at least once a minute so a request that expires is reported.
            let _ = tokio::time::timeout(left.min(Duration::from_secs(60)), notified).await;
        }
    }

    /// Stores a new challenge for a pending request. The oldest of more than eight is
    /// dropped.
    pub fn set_challenge(&self, id: Uuid, challenge: PasskeyAuthentication) -> Result<(), Refused> {
        let mut map = self.lock();
        let approval = map.get_mut(&id).ok_or(Refused::Unknown)?;
        if !matches!(approval.outcome, Outcome::Pending) || approval.applying {
            return Err(Refused::NotPending);
        }
        if approval.challenges.len() == MAX_CHALLENGES {
            approval.challenges.remove(0);
        }
        approval.challenges.push(challenge);
        Ok(())
    }

    /// The request's open challenges.
    pub fn challenges(&self, id: Uuid) -> Result<(Kind, Vec<PasskeyAuthentication>), Refused> {
        let mut map = self.lock();
        let approval = map.get_mut(&id).ok_or(Refused::Unknown)?;
        if !matches!(approval.outcome, Outcome::Pending) || approval.applying {
            return Err(Refused::NotPending);
        }
        if approval.challenges.is_empty() {
            return Err(Refused::NoChallenge);
        }
        Ok((approval.kind.clone(), approval.challenges.clone()))
    }

    /// Marks a request as approved on the approval page and being applied, and clears its
    /// challenges. Fails when it expired, was denied, or another assertion won meanwhile.
    pub fn start_applying(&self, id: Uuid) -> Result<(), Refused> {
        let mut map = self.lock();
        let approval = map.get_mut(&id).ok_or(Refused::Unknown)?;
        if !matches!(approval.outcome, Outcome::Pending) || approval.applying {
            return Err(Refused::NotPending);
        }
        approval.applying = true;
        approval.challenges.clear();
        Ok(())
    }

    /// Records the final outcome and wakes every waiting client.
    pub fn finish(&self, id: Uuid, outcome: Outcome) {
        if let Some(approval) = self.lock().get_mut(&id) {
            approval.outcome = outcome;
            approval.challenges.clear();
            approval.applying = false;
            approval.finished = Some(Instant::now());
        }
        self.changed.notify_waiters();
    }

    /// Denies a pending request that is not being applied.
    pub fn deny(&self, id: Uuid) -> Result<Kind, Refused> {
        let kind = {
            let mut map = self.lock();
            let approval = map.get_mut(&id).ok_or(Refused::Unknown)?;
            if !matches!(approval.outcome, Outcome::Pending) || approval.applying {
                return Err(Refused::NotPending);
            }
            approval.outcome = Outcome::Denied;
            approval.challenges.clear();
            approval.finished = Some(Instant::now());
            approval.kind.clone()
        };
        self.changed.notify_waiters();
        Ok(kind)
    }
}

fn view(id: Uuid, approval: &Approval) -> View {
    View {
        id,
        kind: approval.kind.clone(),
        peer: approval.peer,
        created_at: approval.created_at.clone(),
        outcome: approval.outcome.clone(),
        expires_in: LIFETIME
            .saturating_sub(approval.created.elapsed())
            .as_secs(),
    }
}
