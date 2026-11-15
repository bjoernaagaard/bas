//! Authenticated Secrets Manager operations through the published SDK.
//!
//! SDK request and response types stay inside this module. Callers receive
//! [`Identifier`] metadata and [`Secret`] values whose `Debug` output is redacted.

use std::collections::BTreeSet;
use std::fmt;

use bitwarden::secrets_manager::projects::{
    ProjectCreateRequest, ProjectPutRequest, ProjectResponse, ProjectsDeleteRequest,
    ProjectsListRequest,
};
use bitwarden::secrets_manager::secrets::{
    SecretCreateRequest, SecretGetRequest, SecretIdentifiersByProjectRequest,
    SecretIdentifiersRequest, SecretPutRequest, SecretResponse, SecretsDeleteRequest,
    SecretsGetRequest,
};
use bitwarden::secrets_manager::{
    AccessTokenLoginRequest, ClientSettings, DeviceType, SecretsManagerClient,
};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::Error;
use crate::credential::{MachineToken, SecretText};
use crate::profile::{CredentialSource, Endpoints, Profile};
use crate::reference::ProfileName;

/// How an SDK call failed, derived without reading the upstream message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Failure {
    /// The server answered with this HTTP status.
    Status(u16),
    /// The identity server refused the credential.
    IdentityRejected,
    /// No usable response arrived: connection, TLS, timeout, or I/O failure.
    Transport,
    /// The SDK refused the request before sending it.
    Validation,
    /// The response arrived but could not be decoded or decrypted.
    Unprocessable,
    /// The server answered a bulk delete but did not delete the requested item.
    NotDeleted,
    /// The server returned a secret from an organization other than the profile's.
    OtherOrganization,
}

impl Failure {
    /// Classifies an SDK error by its derived `Debug` variant name.
    ///
    /// The published SDK keeps `SecretsManagerError` in a private module, so its variants
    /// cannot be matched by path. Variant names are stable for the locked SDK version, and
    /// anything unrecognized becomes [`Failure::Unprocessable`], which callers treat as an
    /// unknown outcome. The rendered text is inspected here and never printed.
    fn classify(err: &impl fmt::Debug) -> Self {
        let rendered = format!("{err:?}");
        if let Some(rest) = rendered.strip_prefix("Api(ResponseContent { status: ") {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            return digits.parse().map_or(Self::Unprocessable, Self::Status);
        }
        if rendered.starts_with("Api(Reqwest") || rendered.starts_with("Api(Io(") {
            Self::Transport
        } else if rendered.starts_with("IdentityFail(") {
            Self::IdentityRejected
        } else if rendered.starts_with("Validation(") {
            Self::Validation
        } else {
            Self::Unprocessable
        }
    }

    /// The SDK or server refused the request, so the service performed no change.
    #[must_use]
    pub fn is_rejection(self) -> bool {
        matches!(self, Self::Status(400..=499) | Self::Validation)
    }

    /// Describes a failed read or listing with fixed wording.
    ///
    /// `operation` completes the phrase "could not ...", such as "read the secret".
    pub fn read_error(self, profile: &Profile, operation: &str) -> Error {
        let name = &profile.name;
        match self {
            Self::Status(401 | 403) => {
                Error::new(format!("profile '{name}' is not authorized to {operation}"))
            }
            Self::Status(404) => Error::new(format!(
                "could not {operation}: not found or not accessible to profile '{name}'"
            )),
            Self::Status(status) => Error::new(format!(
                "Secrets Manager refused to {operation} for profile '{name}' (HTTP {status})"
            )),
            Self::Transport => Error::new(format!(
                "could not reach Secrets Manager at {} to {operation}",
                profile.endpoints.api()
            )),
            Self::NotDeleted => Error::new(format!(
                "Secrets Manager refused to {operation} for profile '{name}'"
            )),
            Self::OtherOrganization => Error::new(format!(
                "could not {operation}: Secrets Manager returned a secret outside the \
                 organization of profile '{name}'"
            )),
            Self::IdentityRejected => Error::new(format!(
                "could not {operation}: Secrets Manager refused the machine token of profile \
                 '{name}'"
            )),
            Self::Validation | Self::Unprocessable => Error::new(format!(
                "could not {operation}: the Secrets Manager response was unusable"
            )),
        }
    }
}

impl fmt::Display for Failure {
    /// Names the cause in fixed wording that never repeats a server body.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(401 | 403) => f.write_str("the machine account is not allowed to do this"),
            Self::Status(404) => f.write_str("not found, or not visible to this machine account"),
            Self::Status(status) => {
                write!(f, "Secrets Manager refused the request (HTTP {status})")
            }
            Self::IdentityRejected => f.write_str("Secrets Manager refused the machine token"),
            Self::Transport => f.write_str("could not reach Secrets Manager"),
            Self::Validation => f.write_str("a field is empty, only whitespace, or too long"),
            Self::Unprocessable => f.write_str("the Secrets Manager response could not be read"),
            Self::NotDeleted => f.write_str("Secrets Manager answered but did not delete it"),
            Self::OtherOrganization => {
                f.write_str("Secrets Manager returned a secret from another organization")
            }
        }
    }
}

impl std::error::Error for Failure {}

/// Why the identity server did not sign the token in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignInFailure {
    /// The identity server refused the token as unknown there, so another deployment may know
    /// it. A wrong hosted region answers `400 {"error": "invalid_client"}`.
    Refused,
    /// The identity server declined the request for another reason, such as a rate limit.
    Declined,
    /// No usable response arrived.
    Unreachable,
    /// The answer could not be used.
    Failed,
    /// The answer did not authenticate the token.
    NotAuthenticated,
    /// The answer named no organization.
    NoOrganization,
}

impl SignInFailure {
    fn error(self, name: &ProfileName, endpoints: &Endpoints) -> Error {
        Error::new(match self {
            Self::Refused | Self::Declined => {
                format!("Secrets Manager refused the machine token for profile '{name}'")
            }
            Self::Unreachable => format!(
                "could not reach the identity endpoint {} for profile '{name}'",
                endpoints.identity()
            ),
            Self::Failed => format!("authentication failed for profile '{name}'"),
            Self::NotAuthenticated => {
                format!("Secrets Manager did not authenticate profile '{name}'")
            }
            Self::NoOrganization => {
                format!("the machine token for profile '{name}' names no organization")
            }
        })
    }
}

/// Logs in at `endpoints` and returns the client with the organization the server named.
async fn authenticate(
    endpoints: &Endpoints,
    token: &MachineToken,
    user_agent: &str,
) -> Result<(SecretsManagerClient, Uuid), SignInFailure> {
    let client = SecretsManagerClient::new(Some(ClientSettings {
        identity_url: endpoints.identity().to_owned(),
        api_url: endpoints.api().to_owned(),
        user_agent: user_agent.to_owned(),
        device_type: DeviceType::SDK,
        device_identifier: None,
        bitwarden_client_version: None,
        bitwarden_package_type: None,
    }));
    let request = Wiped::new(
        AccessTokenLoginRequest {
            access_token: token.expose().to_owned(),
            state_file: None,
        },
        |request| request.access_token.zeroize(),
    );
    let result = client.auth().login_access_token(&request).await;
    drop(request);
    let authenticated = match result {
        Ok(response) => response.authenticated,
        Err(err) => {
            return Err(match Failure::classify(&err) {
                Failure::IdentityRejected | Failure::Status(400 | 401) => SignInFailure::Refused,
                Failure::Status(400..=499) => SignInFailure::Declined,
                Failure::Transport => SignInFailure::Unreachable,
                _ => SignInFailure::Failed,
            });
        }
    };
    if !authenticated {
        return Err(SignInFailure::NotAuthenticated);
    }
    let organization = client
        .get_access_token_organization()
        .map(Uuid::from)
        .ok_or(SignInFailure::NoOrganization)?;
    Ok((client, organization))
}

/// Refuses a token whose organization differs from the one the user named.
fn check_organization(
    name: &ProfileName,
    found: Uuid,
    expected: Option<Uuid>,
) -> Result<(), Error> {
    match expected {
        Some(expected) if expected != found => Err(Error::new(format!(
            "the machine token for profile '{name}' belongs to organization {found}, not the \
             configured {expected}"
        ))),
        _ => Ok(()),
    }
}

/// Secret metadata from the identifier listing, which carries no values.
///
/// Only [`Session::list_identifiers`] creates one, and only for the profile's organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identifier {
    id: Uuid,
    key: String,
    project_ids: Vec<Uuid>,
}

impl Identifier {
    /// Secret ID.
    #[must_use]
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Secret key (name). Keys are not unique.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Every project the secret belongs to.
    #[must_use]
    pub fn project_ids(&self) -> &[Uuid] {
        &self.project_ids
    }
}

/// A retrieved secret. Value and note are redacted from `Debug` and zeroed on drop.
///
/// Only [`Session`] creates one, from a Secrets Manager response.
pub struct Secret {
    id: Uuid,
    organization_id: Uuid,
    project_id: Option<Uuid>,
    key: String,
    value: SecretText,
    note: SecretText,
}

impl Secret {
    /// Secret ID.
    #[must_use]
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Organization the secret belongs to.
    #[must_use]
    pub fn organization_id(&self) -> Uuid {
        self.organization_id
    }

    /// First project of the secret. [`Identifier::project_ids`] lists all of them.
    #[must_use]
    pub fn project_id(&self) -> Option<Uuid> {
        self.project_id
    }

    /// Secret key (name).
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Secret value.
    #[must_use]
    pub fn value(&self) -> &SecretText {
        &self.value
    }

    /// Note, which people often use for more secrets.
    #[must_use]
    pub fn note(&self) -> &SecretText {
        &self.note
    }

    /// Keeps only the value, dropping the rest.
    #[must_use]
    pub fn into_value(self) -> SecretText {
        self.value
    }

    fn from_response(response: SecretResponse) -> Self {
        let SecretResponse {
            id,
            organization_id,
            project_id,
            key,
            value,
            note,
            ..
        } = response;
        Self {
            id,
            organization_id,
            project_id,
            key,
            value: SecretText::new(value),
            note: SecretText::new(note),
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .field("project_id", &self.project_id)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// A project visible to the machine account.
///
/// Only [`Session`] creates one, and only for the profile's organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    id: Uuid,
    name: String,
}

impl Project {
    /// Project ID.
    #[must_use]
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Project name. Names are not unique.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    fn from_response(response: ProjectResponse) -> Self {
        Self {
            id: response.id,
            name: response.name,
        }
    }
}

/// Fields written by a create or full update. `Debug` shows only the key and projects.
pub struct WriteRequest<'a> {
    /// Secret key (name).
    pub key: &'a str,
    /// Secret value.
    pub value: &'a SecretText,
    /// Note.
    pub note: &'a SecretText,
    /// Projects the secret belongs to after the write.
    pub project_ids: &'a [Uuid],
}

impl fmt::Debug for WriteRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteRequest")
            .field("key", &self.key)
            .field("project_ids", &self.project_ids)
            .finish_non_exhaustive()
    }
}

/// An authenticated SDK client confirmed to belong to the profile's organization.
///
/// The SDK keeps its session in memory only; no state file is written. A clone shares the
/// signed-in client, so concurrent tasks can each hold one.
#[derive(Clone)]
pub struct Session {
    client: SecretsManagerClient,
    profile: Profile,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Authenticates with the machine token and confirms the organization.
    ///
    /// `user_agent` is sent with every request, such as `bas/0.1.0`.
    ///
    /// # Errors
    ///
    /// Fails when the token is refused, the service is unreachable, or the token belongs
    /// to a different organization than the profile names.
    pub async fn open(
        profile: &Profile,
        token: &MachineToken,
        user_agent: &str,
    ) -> Result<Self, Error> {
        let (client, organization) = authenticate(&profile.endpoints, token, user_agent)
            .await
            .map_err(|refusal| refusal.error(&profile.name, &profile.endpoints))?;
        check_organization(&profile.name, organization, Some(profile.organization))?;
        Ok(Self {
            client,
            profile: profile.clone(),
        })
    }

    /// Signs in at the first deployment in `candidates` whose identity server accepts the
    /// token, and learns the organization from the server's answer.
    ///
    /// A deployment that refuses the token passes the attempt to the next one. Any other
    /// failure stops the search, because the token may belong to the unreachable one. The
    /// session's profile is named `name`, uses `credential`, and is not saved.
    ///
    /// # Errors
    ///
    /// Fails when every candidate refuses the token, a candidate cannot be reached, or the
    /// token belongs to another organization than `organization`, when one is given.
    pub async fn sign_in(
        name: &ProfileName,
        candidates: &[Endpoints],
        organization: Option<Uuid>,
        credential: CredentialSource,
        token: &MachineToken,
        user_agent: &str,
    ) -> Result<Self, Error> {
        for (index, endpoints) in candidates.iter().enumerate() {
            let (client, found) = match authenticate(endpoints, token, user_agent).await {
                Ok(signed_in) => signed_in,
                Err(SignInFailure::Refused) if index + 1 < candidates.len() => continue,
                Err(SignInFailure::Refused) if candidates.len() > 1 => {
                    let tried: Vec<&str> = candidates.iter().map(Endpoints::identity).collect();
                    return Err(Error::new(format!(
                        "Secrets Manager refused the machine token for profile '{name}' at {}; \
                         check that you copied the whole token, or pass --server-url for a \
                         self-hosted server",
                        tried.join(" and ")
                    )));
                }
                Err(refusal) => return Err(refusal.error(name, endpoints)),
            };
            check_organization(name, found, organization)?;
            return Ok(Self {
                client,
                profile: Profile {
                    name: name.clone(),
                    organization: found,
                    endpoints: endpoints.clone(),
                    credential,
                },
            });
        }
        Err(Error::usage("no Secrets Manager endpoint to sign in to"))
    }

    /// The profile this session signed in for.
    #[must_use]
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Lists secret identifiers visible to the machine account, optionally in one project.
    ///
    /// Uses the identifier endpoints, which return keys and project IDs but no values.
    ///
    /// # Errors
    ///
    /// Fails when the listing is refused or unusable.
    pub async fn list_identifiers(&self, project: Option<Uuid>) -> Result<Vec<Identifier>, Error> {
        let secrets = self.client.secrets();
        let response = match project {
            Some(project_id) => {
                secrets
                    .list_by_project(&SecretIdentifiersByProjectRequest { project_id })
                    .await
            }
            None => {
                secrets
                    .list(&SecretIdentifiersRequest {
                        organization_id: self.profile.organization,
                    })
                    .await
            }
        };
        let response = response.map_err(|err| {
            Failure::classify(&err).read_error(&self.profile, "list secret identifiers")
        })?;
        Ok(response
            .data
            .into_iter()
            .filter(|identifier| identifier.organization_id == self.profile.organization)
            .map(|identifier| Identifier {
                id: identifier.id,
                key: identifier.key,
                project_ids: identifier.project_ids,
            })
            .collect())
    }

    /// Retrieves exactly the given secrets in one request.
    ///
    /// # Errors
    ///
    /// Fails when the request is refused or any secret is in another organization.
    pub async fn get_many(&self, ids: &[Uuid]) -> Result<Vec<Secret>, Error> {
        let response = self
            .client
            .secrets()
            .get_by_ids(SecretsGetRequest { ids: ids.to_vec() })
            .await
            .map_err(|err| {
                Failure::classify(&err).read_error(&self.profile, "retrieve the selected secrets")
            })?;
        let secrets: Vec<Secret> = response
            .data
            .into_iter()
            .map(Secret::from_response)
            .collect();
        if secrets
            .iter()
            .all(|secret| secret.organization_id == self.profile.organization)
        {
            Ok(secrets)
        } else {
            Err(Failure::OtherOrganization
                .read_error(&self.profile, "retrieve the selected secrets"))
        }
    }

    /// Retrieves one secret.
    ///
    /// # Errors
    ///
    /// Returns the classified failure, or [`Failure::OtherOrganization`] when the secret
    /// belongs to an organization other than the profile's.
    pub async fn get(&self, id: Uuid) -> Result<Secret, Failure> {
        let secret = self
            .client
            .secrets()
            .get(&SecretGetRequest { id })
            .await
            .map(Secret::from_response)
            .map_err(|err| Failure::classify(&err))?;
        if secret.organization_id == self.profile.organization {
            Ok(secret)
        } else {
            Err(Failure::OtherOrganization)
        }
    }

    /// Creates a secret in the profile's organization. Never retried.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn create(&self, write: &WriteRequest<'_>) -> Result<Secret, Failure> {
        let request = Wiped::new(
            SecretCreateRequest {
                organization_id: self.profile.organization,
                key: write.key.to_owned(),
                value: write.value.expose().to_owned(),
                note: write.note.expose().to_owned(),
                project_ids: Some(write.project_ids.to_vec()),
            },
            |request| {
                request.value.zeroize();
                request.note.zeroize();
            },
        );
        let result = self.client.secrets().create(&request).await;
        drop(request);
        result
            .map(Secret::from_response)
            .map_err(|err| Failure::classify(&err))
    }

    /// Deletes one secret. The server moves it to the organization's trash, which only an
    /// organization admin can empty or restore from.
    ///
    /// # Errors
    ///
    /// Returns the classified failure, or [`Failure::NotDeleted`] when the server answered
    /// without deleting the secret.
    pub async fn delete(&self, id: Uuid) -> Result<(), Failure> {
        if self.delete_many(&[id]).await?.contains(&id) {
            Ok(())
        } else {
            Err(Failure::NotDeleted)
        }
    }

    /// Deletes several secrets in one request and returns the ones the server deleted.
    /// The server moves them to the organization's trash, as [`Session::delete`] describes.
    ///
    /// The server answers for each secret on its own, so a requested ID missing from the
    /// returned set was not deleted.
    ///
    /// # Errors
    ///
    /// Returns the classified failure when the request as a whole failed.
    pub async fn delete_many(&self, ids: &[Uuid]) -> Result<BTreeSet<Uuid>, Failure> {
        let response = self
            .client
            .secrets()
            .delete(SecretsDeleteRequest { ids: ids.to_vec() })
            .await
            .map_err(|err| Failure::classify(&err))?;
        Ok(response
            .data
            .into_iter()
            .filter(|item| item.error.is_none())
            .map(|item| item.id)
            .collect())
    }

    /// Lists the projects the machine account can read.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn list_projects(&self) -> Result<Vec<Project>, Failure> {
        let organization_id = self.profile.organization;
        let response = self
            .client
            .projects()
            .list(&ProjectsListRequest { organization_id })
            .await
            .map_err(|err| Failure::classify(&err))?;
        Ok(response
            .data
            .into_iter()
            .filter(|project| project.organization_id == organization_id)
            .map(Project::from_response)
            .collect())
    }

    /// Creates a project. The server gives the creating machine account read and write
    /// access to it. Never retried.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn create_project(&self, name: &str) -> Result<Project, Failure> {
        self.client
            .projects()
            .create(&ProjectCreateRequest {
                organization_id: self.profile.organization,
                name: name.to_owned(),
            })
            .await
            .map(Project::from_response)
            .map_err(|err| Failure::classify(&err))
    }

    /// Renames a project. Never retried.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn rename_project(&self, id: Uuid, name: &str) -> Result<Project, Failure> {
        self.client
            .projects()
            .update(&ProjectPutRequest {
                id,
                organization_id: self.profile.organization,
                name: name.to_owned(),
            })
            .await
            .map(Project::from_response)
            .map_err(|err| Failure::classify(&err))
    }

    /// Deletes one project. The server deletes it outright, because projects have no trash.
    ///
    /// # Errors
    ///
    /// Returns the classified failure, or [`Failure::NotDeleted`] when the server answered
    /// without deleting the project.
    pub async fn delete_project(&self, id: Uuid) -> Result<(), Failure> {
        let response = self
            .client
            .projects()
            .delete(ProjectsDeleteRequest { ids: vec![id] })
            .await
            .map_err(|err| Failure::classify(&err))?;
        if response
            .data
            .iter()
            .any(|item| item.id == id && item.error.is_none())
        {
            Ok(())
        } else {
            Err(Failure::NotDeleted)
        }
    }

    /// Replaces a secret's key, value, note, and project. Never retried.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn update(&self, id: Uuid, write: &WriteRequest<'_>) -> Result<Secret, Failure> {
        let request = Wiped::new(
            SecretPutRequest {
                id,
                organization_id: self.profile.organization,
                key: write.key.to_owned(),
                value: write.value.expose().to_owned(),
                note: write.note.expose().to_owned(),
                project_ids: Some(write.project_ids.to_vec()),
            },
            |request| {
                request.value.zeroize();
                request.note.zeroize();
            },
        );
        let result = self.client.secrets().update(&request).await;
        drop(request);
        result
            .map(Secret::from_response)
            .map_err(|err| Failure::classify(&err))
    }
}

/// An SDK request holding secret text, wiped when dropped.
///
/// Dropping also happens when the caller cancels the future that awaits the SDK call, so the
/// secret copy is cleared on every path, not only after the call returns.
struct Wiped<T> {
    value: T,
    wipe: fn(&mut T),
}

impl<T> Wiped<T> {
    fn new(value: T, wipe: fn(&mut T)) -> Self {
        Self { value, wipe }
    }
}

impl<T> std::ops::Deref for Wiped<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> Drop for Wiped<T> {
    fn drop(&mut self) {
        (self.wipe)(&mut self.value);
    }
}
