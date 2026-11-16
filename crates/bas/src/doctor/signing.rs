//! The Git signing check: signs a disposable commit through the effective Git settings
//! and asks `git verify-commit` whether this repository trusts it.
//!
//! Support is decided from the configuration before any signing program starts, because
//! a deadline cannot take back a hardware touch request or a passphrase prompt.

use std::env;
use std::fs::{self, DirBuilder, File};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use bas_broker::protocol::DEFAULT_SSH_AGENT_SOCKET;
use rustix::process::{Pid, Signal, kill_process_group};

use crate::output::{Check, Status};

const LABEL: &str = "git signing";
/// Longest time each Git subprocess may run before its whole process group is killed.
const DEADLINE: Duration = Duration::from_secs(10);
/// Where the broker install guide puts the signing shim.
const INSTALLED_SHIM: &str = "/usr/local/lib/bas/shims/ssh-keygen";
/// The shim this release ships for this system. A signing program with exactly these
/// bytes sends `ssh-keygen` to the broker's agent and nothing else.
#[cfg(target_os = "linux")]
const SHIPPED_SHIM: &[u8] = include_bytes!("../../../../contrib/linux/shims/ssh-keygen");
#[cfg(not(target_os = "linux"))]
const SHIPPED_SHIM: &[u8] = include_bytes!("../../../../contrib/macos/shims/ssh-keygen");
/// More than any shim or public key file, and little enough to read whole.
const MAX_READ: u64 = 64 * 1024;
const KEY_COMMAND: &str = "gpg.ssh.defaultKeyCommand";
/// Longest wait for a killed process group to be reaped.
const REAP: Duration = Duration::from_secs(1);

/// Signs a disposable commit with the effective Git settings of the current directory and
/// verifies it, without changing a ref, the index, hooks, or configuration.
pub fn git_signing() -> Check {
    let mut evidence = Vec::new();
    let plan = match inspect(&mut evidence) {
        Ok(plan) => plan,
        Err(unsupported) => {
            return Check {
                status: Status::Warning,
                label: LABEL,
                detail: unsupported.reason,
                evidence,
                fix: unsupported.fix,
            };
        }
    };
    let (status, detail, fix) = probe(&plan, &mut evidence);
    Check {
        status,
        label: LABEL,
        detail,
        evidence,
        fix,
    }
}

/// Why the noninteractive probe did not run.
struct Unsupported {
    reason: String,
    fix: Option<String>,
}

impl Unsupported {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            fix: None,
        }
    }

    fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// One Git setting as `git config --show-scope --show-origin --get` reports it.
struct Setting {
    value: String,
    scope: String,
    origin: String,
}

/// A configuration the probe supports.
struct Plan {
    program: PathBuf,
    allowed_signers: Option<Setting>,
}

/// How `user.signingkey` selects the key.
enum KeySelection {
    /// `key::TYPE BASE64` or the older literal `TYPE BASE64`.
    Literal { key_type: String },
    /// A file that holds an OpenSSH public key.
    PublicKeyFile { path: PathBuf, key_type: String },
    /// A path that does not exist. Signing fails with Git's own error.
    MissingFile { path: PathBuf },
}

fn inspect(evidence: &mut Vec<String>) -> Result<Plan, Unsupported> {
    let cwd = env::current_dir()
        .map(|dir| dir.display().to_string())
        .unwrap_or_else(|_| "an unknown directory".to_owned());
    let git_dir = match run(git(&["rev-parse", "--absolute-git-dir"])) {
        Ok(output) if output.status.success() => stdout_line(&output),
        Ok(_) => {
            return Err(Unsupported::new(format!(
                "no Git repository at {cwd}, so there is no effective signing configuration"
            ))
            .fix(
                "Run `bas doctor --broker` inside the repository whose signing you want checked.",
            ));
        }
        Err(stopped) => return Err(Unsupported::new(stopped.reason("git rev-parse"))),
    };
    evidence.push(format!("repository {git_dir}, working directory {cwd}"));

    let format = setting("gpg.format", evidence)?;
    let program = setting("gpg.ssh.program", evidence)?;
    let signing_key = setting("user.signingkey", evidence)?;
    let default_key_command = setting(KEY_COMMAND, evidence)?;
    let allowed_signers = setting("gpg.ssh.allowedSignersFile", evidence)?;

    match format.as_ref().map(|format| format.value.as_str()) {
        Some("ssh") => {}
        Some(other) => {
            return Err(Unsupported::new(format!(
                "gpg.format is {other}; the probe supports only ssh signing through the bas shim"
            )));
        }
        None => {
            return Err(Unsupported::new(
                "gpg.format is not set, so Git signs with OpenPGP; the probe supports only ssh",
            ));
        }
    }

    let program = signing_program(program.as_ref(), evidence)?;
    let selection = key_selection(signing_key.as_ref(), default_key_command.as_ref())?;
    evidence.push(match &selection {
        KeySelection::Literal { key_type } => {
            format!("user.signingkey is a literal {key_type} public key")
        }
        KeySelection::PublicKeyFile { path, key_type } => {
            format!("{} holds a public key of type {key_type}", path.display())
        }
        KeySelection::MissingFile { path } => format!("{} does not exist", path.display()),
    });
    Ok(Plan {
        program,
        allowed_signers,
    })
}

/// Reads one key of the effective configuration, recording where it came from.
fn setting(key: &'static str, evidence: &mut Vec<String>) -> Result<Option<Setting>, Unsupported> {
    let output = run(git(&[
        "config",
        "--show-scope",
        "--show-origin",
        "--get",
        key,
    ]))
    .map_err(|stopped| Unsupported::new(stopped.reason(&format!("git config {key}"))))?;
    match output.status.code() {
        Some(0) => {}
        Some(1) => {
            evidence.push(format!("{key} is not set"));
            return Ok(None);
        }
        _ => {
            return Err(Unsupported::new(format!(
                "git config could not read {key}: {}",
                stderr_line(&output)
            )));
        }
    }
    let line = String::from_utf8_lossy(&output.stdout);
    let line = line.strip_suffix('\n').unwrap_or(&line);
    let mut parts = line.splitn(3, '\t');
    let (Some(scope), Some(origin), Some(value)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(Unsupported::new(format!(
            "git config printed {key} in a form bas does not know"
        )));
    };
    let setting = Setting {
        value: value.to_owned(),
        scope: scope.to_owned(),
        origin: origin.to_owned(),
    };
    // A key command is free text that can hold a credential, so only its presence is shown.
    let shown = if key == KEY_COMMAND {
        "set, value not shown".to_owned()
    } else {
        shorten(&setting.value)
    };
    evidence.push(format!(
        "{key} = {shown} from {} ({} scope)",
        setting.origin, setting.scope
    ));
    Ok(Some(setting))
}

/// Finds the program Git runs to sign and requires it to be the shipped shim.
fn signing_program(
    program: Option<&Setting>,
    evidence: &mut Vec<String>,
) -> Result<PathBuf, Unsupported> {
    let wrong = |reason: String| {
        let place = program.map_or_else(
            || "for example in the system scope, as the broker install guide does".to_owned(),
            |setting| {
                format!(
                    "in {} ({} scope), which wins now",
                    setting.origin, setting.scope
                )
            },
        );
        Unsupported::new(reason).fix(format!(
            "Set gpg.ssh.program to the installed {INSTALLED_SHIM} {place}."
        ))
    };
    let name = program.map_or("ssh-keygen", |setting| setting.value.as_str());
    let path = if name.starts_with('/') {
        PathBuf::from(name)
    } else if name.contains('/') {
        return Err(wrong(format!(
            "gpg.ssh.program {name} is a relative path, which the probe does not inspect"
        )));
    } else {
        match search_path(name) {
            Some(path) => path,
            None => return Err(wrong(format!("Git finds no {name} on PATH to sign with"))),
        }
    };
    let contents = open_regular(&path).and_then(|file| {
        let mut contents = Vec::new();
        file.take(MAX_READ).read_to_end(&mut contents)?;
        Ok(contents)
    });
    match contents {
        Ok(contents) if contents == SHIPPED_SHIM => {
            evidence.push(format!(
                "{} is byte for byte the shim this bas release ships",
                path.display()
            ));
            Ok(path)
        }
        Ok(_) => Err(wrong(format!(
            "Git signs through {}, which is not the shim this bas release ships",
            path.display()
        ))),
        Err(_) => Err(wrong(format!(
            "Git would sign through {}, which bas cannot read",
            path.display()
        ))),
    }
}

/// The first executable file called `name` in `PATH`, as Git finds a program.
fn search_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| {
            fs::metadata(candidate)
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
}

/// Opens `path` only when it is a regular file, because opening a FIFO would wait for a
/// writer with no deadline.
fn open_regular(path: &Path) -> std::io::Result<File> {
    if fs::metadata(path)?.is_file() {
        File::open(path)
    } else {
        Err(std::io::ErrorKind::InvalidInput.into())
    }
}

/// Classifies `user.signingkey` without starting a program.
fn key_selection(
    signing_key: Option<&Setting>,
    default_key_command: Option<&Setting>,
) -> Result<KeySelection, Unsupported> {
    let key_fix = "Set user.signingkey to the public key file of the broker's signing key, \
                   such as ~/.ssh/git_signing.pub, or to its key:: public key. The comment \
                   bas:git_signing is not a key.";
    let Some(signing_key) = signing_key else {
        if default_key_command.is_some() {
            return Err(Unsupported::new(
                "user.signingkey is not set, so Git would run gpg.ssh.defaultKeyCommand, which \
                 the probe never runs because it could ask for input",
            ));
        }
        return Err(Unsupported::new(
            "neither user.signingkey nor gpg.ssh.defaultKeyCommand selects a signing key",
        )
        .fix(key_fix));
    };
    let value = signing_key.value.as_str();
    // Git reads `key::` and a leading `ssh-` as a literal public key, and anything else as
    // a path.
    if let Some(literal) = value.strip_prefix("key::") {
        return literal_key(literal);
    }
    if value.starts_with("ssh-") {
        return literal_key(value);
    }
    let path = expand_home(value).ok_or_else(|| {
        Unsupported::new(format!(
            "user.signingkey {value} names another user's home, which the probe does not inspect"
        ))
    })?;
    let file = match open_regular(&path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(KeySelection::MissingFile { path });
        }
        Err(_) => {
            return Err(Unsupported::new(format!(
                "user.signingkey names {}, which bas cannot read",
                path.display()
            )));
        }
    };
    // Only the first line is read, so a private key's body never enters memory.
    let mut first = String::new();
    if BufReader::new(file.take(MAX_READ))
        .read_line(&mut first)
        .is_err()
    {
        first.clear();
    }
    if first.starts_with("-----BEGIN") {
        return Err(Unsupported::new(format!(
            "user.signingkey names the private key file {}, which could ask for a passphrase",
            path.display()
        ))
        .fix(key_fix));
    }
    match public_key_type(&first) {
        Some(key_type) if key_type.starts_with("sk-") => Err(hardware(&key_type)),
        Some(key_type) => Ok(KeySelection::PublicKeyFile { path, key_type }),
        None => Err(Unsupported::new(format!(
            "user.signingkey names {}, which does not hold an OpenSSH public key",
            path.display()
        ))
        .fix(key_fix)),
    }
}

fn literal_key(literal: &str) -> Result<KeySelection, Unsupported> {
    match public_key_type(literal) {
        Some(key_type) if key_type.starts_with("sk-") => Err(hardware(&key_type)),
        Some(key_type) => Ok(KeySelection::Literal { key_type }),
        None => Err(Unsupported::new(
            "user.signingkey holds a literal key that is not an OpenSSH public key",
        )),
    }
}

fn hardware(key_type: &str) -> Unsupported {
    Unsupported::new(format!(
        "user.signingkey selects a {key_type} hardware key, which needs a touch; check it by hand"
    ))
}

/// The key type of an OpenSSH public key line, `TYPE BASE64 [COMMENT]`.
fn public_key_type(line: &str) -> Option<String> {
    let mut fields = line.split_whitespace();
    let key_type = fields.next()?;
    let body = fields.next()?;
    let known = key_type.starts_with("ssh-")
        || key_type.starts_with("ecdsa-sha2-")
        || key_type.starts_with("sk-");
    let base64 = body
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=');
    (known && base64).then(|| key_type.to_owned())
}

/// `~/` and a bare `~` become `$HOME`, as Git expands paths. `~user/` is `None`.
fn expand_home(value: &str) -> Option<PathBuf> {
    let home = || env::var_os("HOME").map(PathBuf::from);
    if value == "~" {
        return home();
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return home().map(|home| home.join(rest));
    }
    if value.starts_with('~') {
        return None;
    }
    Some(PathBuf::from(value))
}

/// Signs and verifies one disposable commit, and turns the first failing stage into a
/// verdict.
fn probe(plan: &Plan, evidence: &mut Vec<String>) -> (Status, String, Option<String>) {
    let objects = match Scratch::create() {
        Ok(objects) => objects,
        Err(_) => {
            return (
                Status::Warning,
                "could not create a disposable object directory".to_owned(),
                None,
            );
        }
    };
    let probe_git = |args: &[&str]| {
        let mut command = git(args);
        command
            .env("GIT_OBJECT_DIRECTORY", objects.path())
            .env("GIT_AUTHOR_NAME", "bas doctor")
            .env("GIT_AUTHOR_EMAIL", "bas-doctor@localhost")
            .env("GIT_COMMITTER_NAME", "bas doctor")
            .env("GIT_COMMITTER_EMAIL", "bas-doctor@localhost");
        command
    };

    let tree = match run(probe_git(&["mktree"])) {
        Ok(output) if output.status.success() => stdout_line(&output),
        Ok(output) => {
            evidence.push(format!("git mktree: {}", stderr_line(&output)));
            return (
                Status::Warning,
                "could not write the empty tree for the probe".to_owned(),
                None,
            );
        }
        Err(stopped) => return (Status::Warning, stopped.reason("git mktree"), None),
    };

    let signed = run(probe_git(&[
        "commit-tree",
        &tree,
        "-S",
        "-m",
        "bas doctor signing probe",
    ]));
    let commit = match signed {
        Ok(output) if output.status.success() => stdout_line(&output),
        Ok(output) => {
            evidence.push(format!("git commit-tree -S: {}", stderr_line(&output)));
            let agent = Path::new(DEFAULT_SSH_AGENT_SOCKET);
            let fix = if agent.exists() {
                "Set user.signingkey to the public key file of the broker's signing key, such \
                 as ~/.ssh/git_signing.pub, or to its key:: public key, and make sure the \
                 broker's policy holds that key with use = [\"sign-git\"]. The comment \
                 bas:git_signing is not a key."
                    .to_owned()
            } else {
                evidence.push(format!("{DEFAULT_SSH_AGENT_SOCKET} does not exist"));
                format!(
                    "Restore the broker's ssh-agent at {DEFAULT_SSH_AGENT_SOCKET}, which the shim \
                     uses, then rerun `bas doctor --broker`."
                )
            };
            return (
                Status::Failed,
                format!(
                    "signing failed: git commit-tree -S through {} exited with {}",
                    plan.program.display(),
                    exit_text(&output)
                ),
                Some(fix),
            );
        }
        Err(stopped) => {
            return (
                Status::Warning,
                stopped.reason("signing with git commit-tree -S"),
                None,
            );
        }
    };
    evidence.push(format!(
        "git commit-tree -S signed the disposable commit {commit} in a temporary object \
         directory; no ref, index, hook, or setting changed"
    ));

    match run(probe_git(&["verify-commit", &commit])) {
        Ok(output) if output.status.success() => {
            evidence.push(format!("git verify-commit: {}", stderr_line(&output)));
            (
                Status::Ready,
                "a disposable commit was signed through the bas shim and git verify-commit \
                 trusts it"
                    .to_owned(),
                None,
            )
        }
        Ok(output) => {
            evidence.push(format!("git verify-commit: {}", stderr_line(&output)));
            let file = plan
                .allowed_signers
                .as_ref()
                .map_or_else(|| "unset".to_owned(), |setting| setting.value.clone());
            (
                Status::Failed,
                format!(
                    "trust verification failed: git verify-commit exited with {}",
                    exit_text(&output)
                ),
                Some(format!(
                    "Correct gpg.ssh.allowedSignersFile (now {file}) and its trusted principal, \
                     namespace, validity, or revocation rule as the evidence shows. Do not remove \
                     revocation or trust checks to make the probe pass."
                )),
            )
        }
        Err(stopped) => (Status::Warning, stopped.reason("git verify-commit"), None),
    }
}

/// A private temporary directory, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn create() -> std::io::Result<Self> {
        let path = env::temp_dir().join(format!("bas-doctor-{}", uuid::Uuid::new_v4().simple()));
        DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Nothing else can be done when removal fails, and the directory holds no secret.
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Why a subprocess gave no exit status.
enum Stopped {
    NotStarted,
    TimedOut,
    Lost,
}

impl Stopped {
    fn reason(&self, what: &str) -> String {
        match self {
            Self::NotStarted => format!("{what} could not start; is git installed?"),
            Self::TimedOut => format!(
                "{what} did not finish within {} seconds and was stopped",
                DEADLINE.as_secs()
            ),
            Self::Lost => format!("{what} ended without a readable status"),
        }
    }
}

fn git(args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command.args(args);
    command
}

/// Runs a command with no terminal input in its own process group, and kills the whole
/// group at [`DEADLINE`].
fn run(mut command: Command) -> Result<Output, Stopped> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .process_group(0);
    let child = command.spawn().map_err(|_| Stopped::NotStarted)?;
    let group = Pid::from_child(&child);
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        // The receiver is gone only after a timeout, when the result no longer matters.
        let _ = sender.send(child.wait_with_output());
    });
    match receiver.recv_timeout(DEADLINE) {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => Err(Stopped::Lost),
        Err(RecvTimeoutError::Timeout) => {
            // The group may already be gone, which is the outcome the kill wants.
            let _ = kill_process_group(group, Signal::KILL);
            let _ = receiver.recv_timeout(REAP);
            Err(Stopped::TimedOut)
        }
    }
}

fn stdout_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// The last nonempty line of standard error, without control characters, for evidence.
fn stderr_line(output: &Output) -> String {
    let text = String::from_utf8_lossy(&output.stderr);
    let line = text
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .unwrap_or("no message");
    shorten(&line.chars().filter(|c| !c.is_control()).collect::<String>())
}

fn exit_text(output: &Output) -> String {
    output
        .status
        .code()
        .map_or_else(|| "a signal".to_owned(), |code| format!("status {code}"))
}

/// At most 120 characters, so a literal public key does not fill the screen.
fn shorten(text: &str) -> String {
    const LIMIT: usize = 120;
    if text.chars().count() <= LIMIT {
        text.to_owned()
    } else {
        let mut short: String = text.chars().take(LIMIT).collect();
        short.push_str("...");
        short
    }
}
