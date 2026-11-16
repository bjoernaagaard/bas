//! Diagnostics that never read, print, or retrieve secret values.

#[cfg(unix)]
mod broker;
#[cfg(unix)]
mod signing;

use std::env;

use crate::output::{Check, Status};
use bas_core::credential::{self, ACCESS_TOKEN_VAR};
use bas_core::profile::{Profile, Profiles};
use bas_core::secrets::Session;

#[cfg(unix)]
pub use broker::broker;
#[cfg(unix)]
pub use signing::git_signing;

/// Runs every offline check and returns the results in display order.
///
/// No check opens a network connection or authenticates. Environment variables are
/// tested for presence only and their values are never read into output.
pub fn offline() -> Vec<Check> {
    vec![build(), profile_configuration(), access_token_variable()]
}

/// Authenticates one profile and confirms its organization without retrieving secrets.
pub async fn authenticated(profile: &Profile) -> Check {
    let label = "profile";
    let session = match credential::load_token(profile) {
        Ok(token) => Session::open(profile, &token, crate::USER_AGENT).await,
        Err(err) => Err(err),
    };
    match session {
        Ok(_) => Check::new(
            Status::Ready,
            label,
            format!(
                "'{}' authenticated to organization {} at {} using the {}",
                profile.name,
                profile.organization,
                profile.endpoints.api(),
                profile.credential
            ),
        ),
        Err(err) => Check::new(Status::Failed, label, err.to_string()),
    }
}

fn build() -> Check {
    Check::new(
        Status::Ready,
        "build",
        format!(
            "bas {} on {}-{}",
            env!("CARGO_PKG_VERSION"),
            env::consts::OS,
            env::consts::ARCH
        ),
    )
}

fn profile_configuration() -> Check {
    let label = "profiles";
    match Profiles::load() {
        Ok(profiles) if profiles.is_empty() => Check::new(
            Status::NotConfigured,
            label,
            format!(
                "none in {}; run `bas auth login --help`. Never paste tokens into a chat.",
                profiles.path().display()
            ),
        ),
        Ok(profiles) => Check::new(
            Status::Ready,
            label,
            format!("{} in {}", profiles.len(), profiles.path().display()),
        ),
        Err(err) => Check::new(Status::Failed, label, err.to_string()),
    }
}

fn access_token_variable() -> Check {
    if env::var_os(ACCESS_TOKEN_VAR).is_some() {
        Check::new(
            Status::Ready,
            "machine token",
            format!(
                "{ACCESS_TOKEN_VAR} is set; value hidden. Only --from-env profiles read it, and \
                 child processes never inherit it"
            ),
        )
    } else {
        Check::new(
            Status::NotConfigured,
            "machine token",
            format!("{ACCESS_TOKEN_VAR} is not set; only profiles created with --from-env need it"),
        )
    }
}
