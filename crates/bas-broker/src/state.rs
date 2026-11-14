//! What every part of the broker shares, and the changes an approval applies.

use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};

use bas_core::Uuid;
use bas_core::credential::SecretText;
use bas_core::reference::SecretRef;
use bas_core::secrets::{Failure, Session, WriteRequest};

use crate::approvals::{Approvals, Kind, Outcome};
use crate::config::Config;
use crate::mint::Minter;
use crate::passkeys::Passkeys;
use crate::policy::{Policy, SecretFile};
use crate::server::Options;
use crate::{Error, audit, files, ssh_agent};

/// File name of the active policy in the state directory.
pub const POLICY_FILE: &str = "policy.toml";

/// Shared by the socket API, the proxy, the ssh-agent, and the approval pages.
pub struct Broker {
    /// Machine settings.
    pub config: Config,
    /// Private directory with the policy, passkeys, and proxy authority.
    pub state_dir: PathBuf,
    /// Bundle file for proxy clients.
    pub ca_bundle: PathBuf,
    /// Append-only audit file that `GET /v1/audit` reads.
    #[cfg(not(target_os = "linux"))]
    pub audit_log: PathBuf,
    /// Secrets Manager session.
    pub session: Session,
    /// Keys the ssh-agent signs with.
    pub keys: Arc<ssh_agent::Keys>,
    /// GitHub and Tailscale token minter.
    pub minter: Minter,
    /// Requests that wait for an approval.
    pub approvals: Approvals,
    /// Enrolled passkeys.
    pub passkeys: Passkeys,
    policy: RwLock<Arc<Policy>>,
    /// Held for the whole of `apply`, so one approval reads the policy and writes the next
    /// one before another starts.
    applying: tokio::sync::Mutex<()>,
}

/// What an approved request produced, and a link shown only to the approval page.
pub struct Applied {
    /// Final state.
    pub outcome: Outcome,
    /// Enrollment link for `bas passkey add`.
    pub enroll_url: Option<String>,
}

impl Broker {
    /// Puts the parts together. The paths come from `options`.
    pub fn new(
        config: Config,
        options: &Options,
        session: Session,
        policy: Policy,
        keys: Arc<ssh_agent::Keys>,
        passkeys: Passkeys,
    ) -> Self {
        Self {
            config,
            state_dir: options.state_dir.clone(),
            ca_bundle: options.ca_bundle.clone(),
            #[cfg(not(target_os = "linux"))]
            audit_log: options.audit_log.clone(),
            minter: Minter::new(session.clone()),
            session,
            keys,
            approvals: Approvals::default(),
            passkeys,
            policy: RwLock::new(Arc::new(policy)),
            applying: tokio::sync::Mutex::new(()),
        }
    }

    /// The active policy.
    pub fn policy(&self) -> Arc<Policy> {
        Arc::clone(&self.policy.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Applies an approved request. `value` is the text typed on the approval page.
    pub async fn apply(&self, id: Uuid, kind: &Kind, value: Option<SecretText>) -> Applied {
        let _applying = self.applying.lock().await;
        let mut enroll_url = None;
        let result = match kind {
            Kind::AddSecret { name, entry } => self.add_secret(id, name, entry, value).await,
            Kind::Rotate { name, reference } => self.rotate(name, reference, value).await,
            Kind::Policy {
                toml, base_hash, ..
            } => self.replace_policy(id, toml, base_hash).await,
            Kind::Passkey { replace } => {
                enroll_url = Some(self.passkeys.new_link(*replace));
                Ok(serde_json::json!({ "enroll": "the link is shown on the approval page" }))
            }
        };
        let outcome = match result {
            Ok(result) => Outcome::Approved(result),
            Err(err) => {
                tracing::warn!("approval {id} could not be applied: {err}");
                Outcome::Failed(err.to_string())
            }
        };
        Applied {
            outcome,
            enroll_url,
        }
    }

    async fn add_secret(
        &self,
        id: Uuid,
        name: &str,
        entry: &SecretFile,
        value: Option<SecretText>,
    ) -> Result<serde_json::Value, Error> {
        let value = value.ok_or_else(|| Error::new("no value was typed"))?;
        let project = self.config.project.ok_or_else(|| {
            Error::new(
                "broker.toml names no project in [profile], so bas add cannot create secrets",
            )
        })?;
        let policy = self.policy();
        if policy.secret(name).is_some() {
            return Err(Error::new(format!(
                "secret.{name} is already in the active policy"
            )));
        }
        let profile = &self.config.profile.name;
        policy
            .check_new_secret(name, entry, profile)
            .map_err(|invalid| Error::new(invalid.message))?;

        let note = SecretText::new(String::new());
        let created = self
            .session
            .create(&WriteRequest {
                key: name,
                value: &value,
                note: &note,
                project_ids: &[project],
            })
            .await
            .map_err(|failure| write_failed(failure, name, "create"))?;
        let reference = SecretRef {
            profile: profile.clone(),
            id: created.id(),
        };
        let mut candidate = entry.clone();
        candidate.reference = reference.to_string();
        let next = policy
            .with_secret(name, &candidate, profile)
            .map_err(|invalid| Error::new(invalid.message))?;
        self.install(next, id).await.map_err(|err| {
            Error::new(format!(
                "created {reference} but could not add it to the policy: {err}"
            ))
        })?;
        Ok(serde_json::json!({ "name": name, "reference": reference.to_string() }))
    }

    async fn rotate(
        &self,
        name: &str,
        reference: &SecretRef,
        value: Option<SecretText>,
    ) -> Result<serde_json::Value, Error> {
        let value = value.ok_or_else(|| Error::new("no value was typed"))?;
        let profile = self.session.profile();
        let current = self
            .session
            .get(reference.id)
            .await
            .map_err(|failure| failure.read_error(profile, "read the secret"))?;
        let projects: Vec<Uuid> = current.project_id().into_iter().collect();
        self.session
            .update(
                reference.id,
                &WriteRequest {
                    key: current.key(),
                    value: &value,
                    note: current.note(),
                    project_ids: &projects,
                },
            )
            .await
            .map_err(|failure| write_failed(failure, name, "update"))?;
        let stored = self
            .session
            .get(reference.id)
            .await
            .map_err(|failure| failure.read_error(profile, "read the secret back"))?;
        if stored.value().expose() != value.expose() {
            return Err(Error::new(format!(
                "Secrets Manager acknowledged the update of {name}, but reading it back \
                 returned another value"
            )));
        }
        // An ssh key may share the secret, so reload the keys from the new value.
        let keys = ssh_agent::load(&self.policy(), &self.session).await?;
        self.keys.set(keys);
        Ok(serde_json::json!({ "name": name, "rotated": "stored" }))
    }

    async fn replace_policy(
        &self,
        id: Uuid,
        toml: &str,
        base_hash: &str,
    ) -> Result<serde_json::Value, Error> {
        if self.policy().hash() != base_hash {
            return Err(Error::new(
                "the active policy changed after this request; run bas policy edit again",
            ));
        }
        let next = Policy::parse(toml, &self.config.profile.name)
            .map_err(|invalid| Error::new(invalid.message))?;
        let hash = next.hash().to_owned();
        self.install(next, id).await?;
        Ok(serde_json::json!({ "hash": hash }))
    }

    /// Loads the new policy's ssh keys, writes the policy, and makes it active. Nothing
    /// changes when a key cannot be loaded.
    async fn install(&self, next: Policy, approval_id: Uuid) -> Result<(), Error> {
        let keys = ssh_agent::load(&next, &self.session).await?;
        files::replace(
            &self.state_dir.join(POLICY_FILE),
            next.text().as_bytes(),
            0o600,
        )?;
        let hash = next.hash().to_owned();
        *self.policy.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
        self.keys.set(keys);
        self.minter.forget_github();
        self.minter.forget_tailscale();
        audit::policy(&hash, &approval_id.hyphenated().to_string());
        Ok(())
    }
}

fn write_failed(failure: Failure, name: &str, action: &str) -> Error {
    if failure.is_rejection() {
        Error::new(format!(
            "Secrets Manager refused to {action} {name} ({failure:?}); nothing was written"
        ))
    } else {
        Error::new(format!(
            "the outcome of the {action} of {name} is unknown ({failure:?}); check Secrets \
             Manager before you try again"
        ))
    }
}
