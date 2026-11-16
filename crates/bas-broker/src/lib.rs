//! The bas credential broker, which `bas broker` starts, and the client that the `bas`
//! commands use to reach it.
//!
//! The broker is the only process that holds the Bitwarden machine token and the raw
//! credentials. It serves an HTTP/1.1 and JSON API on a unix socket, where it identifies
//! each caller by the kernel's peer credentials; an HTTPS proxy on a loopback port that adds
//! a credential to requests for hosts named in the active policy; an ssh-agent that signs
//! with policy keys; and approval pages where a passkey approves changes. No
//! credential value ever leaves it. Each use, change, and refusal is recorded with
//! `BAS_AUDIT=1`: in the system journal on Linux, and in an append-only file on macOS.
//!
//! The crate builds on Linux and macOS. On other systems it is empty.

#![cfg(unix)]

mod approvals;
mod audit;
pub mod client;
mod config;
mod error;
mod files;
mod mint;
mod pages;
mod passkeys;
mod policy;
pub mod proposal;
pub mod protocol;
mod proxy;
mod server;
mod ssh_agent;
mod state;
mod summary;

pub use error::{Error, ErrorKind};
pub use server::{Options, serve};

/// Checks the text of a `broker.toml` that is about to be written to `path`, with the
/// rules the broker applies when it starts.
///
/// # Errors
///
/// Fails when a key is missing, unknown, or holds a value the broker refuses.
pub fn check_config(text: &str, path: &std::path::Path) -> Result<(), Error> {
    config::Config::parse(text, path).map(|_| ())
}

/// Makes ring the process-wide rustls crypto provider.
///
/// hudsucker turns on rustls's aws-lc-rs provider next to the ring provider the rest of
/// `bas` uses, and with two providers rustls cannot choose one by itself, so every TLS
/// client in the process, including the Secrets Manager SDK, would panic. Call this once at
/// the start of `main`.
pub fn install_crypto_provider() {
    // A provider installed earlier is just as usable, so that error is ignored.
    let _ = hudsucker::rustls::crypto::ring::default_provider().install_default();
}
