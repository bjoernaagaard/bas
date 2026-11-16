//! Terminal output built from explicit, nonsecret fields.

use std::fmt::{self, Display};
use std::io::{self, Write};
use std::process::ExitCode;

use bas_core::reference::SecretRef;
use serde::Serialize;

use crate::grant::{Grant, State};

/// Exit status for a failure inside `bas` itself.
pub const EXIT_FAILURE: u8 = 1;
/// Exit status for unusable command-line arguments.
pub const EXIT_USAGE: u8 = 2;
/// Exit status of `bas doctor` when a check warned and none failed.
pub const EXIT_WARNING: u8 = 2;
/// Exit status for a write the service accepted but `bas` could not verify.
pub const EXIT_WRITTEN_UNVERIFIED: u8 = 3;
/// Exit status for a write whose server-side result is unknown.
pub const EXIT_UNKNOWN_OUTCOME: u8 = 4;

/// Application error whose message is built only from `bas` text and nonsecret identifiers.
///
/// The only `From` conversion is from [`bas_core::Error`], whose messages follow the same
/// rule. Every other upstream failure is mapped to fixed wording at its call site, so
/// upstream bodies never reach the terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
    exit: u8,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit: EXIT_FAILURE,
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit: EXIT_USAGE,
        }
    }

    pub fn with_exit(message: impl Into<String>, exit: u8) -> Self {
        Self {
            message: message.into(),
            exit,
        }
    }

    /// The same failure, reported as the reason a program was not started.
    pub fn not_started(self) -> Self {
        Self {
            message: format!("not started: {}", self.message),
            ..self
        }
    }

    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.exit)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<bas_core::Error> for Error {
    fn from(err: bas_core::Error) -> Self {
        if err.is_usage() {
            Self::usage(err.to_string())
        } else {
            Self::new(err.to_string())
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Outcome of one diagnostic line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Status {
    /// The component works.
    #[serde(rename = "ready")]
    Ready,
    /// Setup is absent.
    #[serde(rename = "not configured")]
    NotConfigured,
    /// The evidence needed for a verdict could not be gathered.
    #[serde(rename = "warning")]
    Warning,
    /// The component was checked and does not work.
    #[serde(rename = "failed")]
    Failed,
}

impl Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Ready => "ready",
            Self::NotConfigured => "not configured",
            Self::Warning => "warning",
            Self::Failed => "failed",
        })
    }
}

/// One labelled diagnostic with a fixed or SDK-provided nonsecret detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub status: Status,
    #[serde(rename = "name")]
    pub label: &'static str,
    pub detail: String,
    /// Nonsecret facts behind the status, in the order they were gathered.
    pub evidence: Vec<String>,
    /// What the operator could do about this result. `bas` never applies it.
    pub fix: Option<String>,
}

impl Check {
    /// A check with no evidence and no fix.
    pub fn new(status: Status, label: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            label,
            detail: detail.into(),
            evidence: Vec::new(),
            fix: None,
        }
    }
}

/// The result of a whole diagnosis, which decides its exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No check failed or warned. Exit 0.
    Ready,
    /// Some check warned and none failed. Exit 2.
    Warning,
    /// Some check failed. Exit 1.
    Failed,
}

impl Verdict {
    pub fn of(checks: &[Check]) -> Self {
        if checks.iter().any(|check| check.status == Status::Failed) {
            Self::Failed
        } else if checks.iter().any(|check| check.status == Status::Warning) {
            Self::Warning
        } else {
            Self::Ready
        }
    }

    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(match self {
            Self::Ready => 0,
            Self::Failed => EXIT_FAILURE,
            Self::Warning => EXIT_WARNING,
        })
    }
}

/// JSON document printed by `bas doctor --json`.
#[derive(Debug, Serialize)]
pub struct DoctorReport<'a> {
    pub status: Verdict,
    pub checks: &'a [Check],
}

/// Writes one aligned line per check, with its evidence and fix indented beneath it.
///
/// # Errors
///
/// Returns an error when the writer fails.
pub fn write_checks(out: &mut impl Write, checks: &[Check]) -> io::Result<()> {
    let width = checks
        .iter()
        .map(|check| check.label.len())
        .max()
        .unwrap_or(0);
    let indent = " ".repeat(14 + 2 + width + 2);
    for Check {
        status,
        label,
        detail,
        evidence,
        fix,
    } in checks
    {
        writeln!(out, "{status:<14}  {label:<width$}  {detail}")?;
        for fact in evidence {
            writeln!(out, "{indent}{fact}")?;
        }
        if let Some(fix) = fix {
            writeln!(out, "{indent}fix: {fix}")?;
        }
    }
    Ok(())
}

/// Safe discovery result: a reference plus metadata explicitly allowed for selection.
///
/// Values and notes are excluded because people put secrets in notes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretSummary {
    pub reference: SecretRef,
    pub key: String,
    pub project_ids: Vec<uuid::Uuid>,
    /// Queries that matched this secret's key. Empty when no query was given.
    pub matched: Vec<String>,
    /// Another visible secret in the organization has the same key.
    pub duplicate_key: bool,
}

/// JSON document printed by `bas find --json`.
#[derive(Debug, Serialize)]
pub struct FindReport<'a> {
    pub matches: &'a [SecretSummary],
    pub unmatched: &'a [String],
}

/// Writes discovery results as aligned text lines.
///
/// # Errors
///
/// Returns an error when the writer fails.
pub fn write_summaries(out: &mut impl Write, summaries: &[SecretSummary]) -> io::Result<()> {
    for summary in summaries {
        let projects = summary
            .project_ids
            .iter()
            .map(uuid::Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let projects = if projects.is_empty() {
            "none".to_owned()
        } else {
            projects
        };
        let duplicate = if summary.duplicate_key {
            "  duplicate-key"
        } else {
            ""
        };
        writeln!(
            out,
            "{}  {}  project={projects}{duplicate}",
            summary.reference, summary.key
        )?;
    }
    Ok(())
}

/// Result of a create or update, as far as `bas` can establish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The service accepted the write and a read-back matched every written field.
    Verified,
    /// The service accepted the write, but the read-back failed or differed.
    WrittenUnverified,
    /// The service may or may not have applied the write.
    Unknown,
}

impl Outcome {
    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(match self {
            Self::Verified => 0,
            Self::WrittenUnverified => EXIT_WRITTEN_UNVERIFIED,
            Self::Unknown => EXIT_UNKNOWN_OUTCOME,
        })
    }
}

/// Write operation named in a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Create,
    Update,
}

/// Safe write receipt printed as one JSON line. It never holds the value or note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Receipt {
    pub outcome: Outcome,
    pub operation: Operation,
    /// The affected secret. `None` only for a create whose result is unknown.
    pub reference: Option<SecretRef>,
    pub key: String,
    pub project_id: Option<uuid::Uuid>,
    /// Why the outcome is not `verified`.
    pub reason: Option<&'static str>,
    /// Other secrets that already used the key before a create. Feedback, not a guarantee.
    pub duplicate_keys: Vec<SecretRef>,
}

/// JSON document printed by `bas grant list --json`.
#[derive(Debug, Serialize)]
pub struct GrantReport<'a> {
    pub grants: &'a [&'a Grant],
}

/// Writes one aligned text line per grant.
///
/// # Errors
///
/// Returns an error when the writer fails.
pub fn write_grants(out: &mut impl Write, grants: &[&Grant]) -> io::Result<()> {
    for grant in grants {
        let state = match grant.state {
            State::Active => "active",
            State::Revoked => "revoked",
        };
        let secrets = grant
            .secrets
            .iter()
            .map(uuid::Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",");
        writeln!(
            out,
            "{}  {state:<7}  profile={}  organization={}  device={}  secrets={secrets}",
            grant.id,
            grant.profile,
            grant.organization,
            grant.device.to_hex()
        )?;
    }
    Ok(())
}

/// Writes one value as a single JSON line.
///
/// # Errors
///
/// Returns an error when serialization or the writer fails.
pub fn write_json(out: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    writeln!(out)
}

/// Writes a short message to standard error.
///
/// Callers pass `bas` text. Upstream error bodies never reach this function.
pub fn write_error(message: &str) {
    // A failed write to stderr leaves nowhere else to report, so the result is dropped.
    drop(writeln!(io::stderr().lock(), "bas: {message}"));
}
