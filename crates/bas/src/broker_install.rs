//! `bas broker install`: puts the broker on a Linux machine with systemd, or brings an
//! install up to date.
//!
//! The plan is built by reading the machine, and only the steps that differ are applied,
//! so a second run changes nothing. The machine token goes from `systemd-ask-password`
//! straight into `systemd-creds`, and never through this process.

use std::env;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use bas_core::profile::{EndpointFlags, Endpoints, Region};

use crate::cli::BrokerInstallArgs;
use crate::output::{Error, Result};

const PROGRAM: &str = "/usr/local/bin/bas";
const UNIT_NAME: &str = "bas-broker.service";
const UNIT_PATH: &str = "/etc/systemd/system/bas-broker.service";
const UNIT: &[u8] = include_bytes!("../../../contrib/linux/bas-broker.service");
const CONFIG_DIR: &str = "/etc/bas";
const CONFIG: &str = "/etc/bas/broker.toml";
const TOKEN_DIR: &str = "/etc/credstore.encrypted";
const TOKEN: &str = "/etc/credstore.encrypted/bas-bws.cred";
const SHIMS_PARENT: &str = "/usr/local/lib/bas";
const SHIMS: &str = "/usr/local/lib/bas/shims";
const GH_SHIM: &[u8] = include_bytes!("../../../contrib/linux/shims/gh");
const SSH_KEYGEN_SHIM_PATH: &str = "/usr/local/lib/bas/shims/ssh-keygen";
const SSH_KEYGEN_SHIM: &[u8] = include_bytes!("../../../contrib/linux/shims/ssh-keygen");
const SSH_CONFIG: &str = "/etc/ssh/ssh_config.d/10-bas.conf";
const SSH_CONFIG_TEXT: &[u8] = include_bytes!("../../../contrib/linux/ssh_config.d/10-bas.conf");
const GIT_KEY: &str = "gpg.ssh.program";
const USER: &str = "bas";
const APPROVALS_LISTEN: &str = "127.0.0.1:793";
const GUIDE: &str = "https://bjoernaagaard.github.io/bas/broker/install.html";

/// What the machine holds for one step.
enum State {
    Ready,
    /// The step will run, for the reason given.
    Change(String),
    /// The step cannot be checked without root.
    Unknown(String),
    /// The step does not apply to this machine.
    Skipped(String),
}

enum Action {
    /// Write a file owned by root, after creating the listed directories.
    File {
        dirs: &'static [&'static str],
        content: Vec<u8>,
        mode: u32,
    },
    User,
    Token,
    GitProgram,
    Service,
}

struct Step {
    label: &'static str,
    target: String,
    state: State,
    action: Action,
}

/// Prints the plan, and applies it unless `--dry-run` is given.
pub fn install(args: BrokerInstallArgs) -> Result<ExitCode> {
    if !Path::new("/run/systemd/system").exists() {
        return Err(Error::new(
            "bas broker install needs a machine that systemd started",
        ));
    }
    let root = rustix::process::geteuid().is_root();
    let steps = plan(&args, root)?;
    for step in &steps {
        let (word, note) = match &step.state {
            State::Ready => ("ready", String::new()),
            State::Change(why) => ("change", format!(": {why}")),
            State::Unknown(why) => ("unknown", format!(": {why}")),
            State::Skipped(why) => ("skipped", format!(": {why}")),
        };
        println!("{word:<8} {:<16} {}{note}", step.label, step.target);
    }
    let pending = steps
        .iter()
        .filter(|step| matches!(step.state, State::Change(_) | State::Unknown(_)))
        .count();
    if args.dry_run {
        println!("Dry run. Nothing changed, and {pending} steps would run.");
        return Ok(ExitCode::SUCCESS);
    }
    if pending == 0 {
        println!("Nothing to change.");
        return Ok(ExitCode::SUCCESS);
    }
    if !root {
        let program = env::current_exe()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "bas".to_owned());
        return Err(Error::new(format!(
            "{pending} steps need root. Run: sudo {program} broker install, with the same options"
        )));
    }
    for step in &steps {
        if matches!(step.state, State::Change(_)) {
            apply(step)?;
            println!("done     {:<16} {}", step.label, step.target);
        }
    }
    println!(
        "The broker runs. What is left for you:\n\
         1. Publish the approval pages: forward the origin in {CONFIG} to http://{APPROVALS_LISTEN}.\n\
         2. Enroll a passkey: open the link that `sudo cat /var/lib/bas/enroll-url` prints.\n\
         3. Approve a first policy: bas policy edit\n\
         4. Put {SHIMS} first in PATH, and set your Git signing key.\n\
         The guide has each step: {GUIDE}"
    );
    Ok(ExitCode::SUCCESS)
}

fn plan(args: &BrokerInstallArgs, root: bool) -> Result<Vec<Step>> {
    let exe = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|err| Error::new(format!("could not find this program's file: {err}")))?;
    let (program, program_content) = if exe == Path::new(PROGRAM) {
        (State::Ready, Vec::new())
    } else {
        let content = fs::read(&exe)
            .map_err(|err| Error::new(format!("could not read {}: {err}", exe.display())))?;
        (file_state(PROGRAM, &content, 0o755)?, content)
    };
    let file = |label, path: &'static str, content: &[u8], mode, dirs| -> Result<Step> {
        Ok(Step {
            label,
            target: path.to_owned(),
            state: file_state(path, content, mode)?,
            action: Action::File {
                dirs,
                content: content.to_vec(),
                mode,
            },
        })
    };
    let config = if Path::new(CONFIG).exists() {
        Step {
            label: "settings",
            target: format!("{CONFIG}, kept as it is"),
            state: State::Ready,
            action: Action::File {
                dirs: &[],
                content: Vec::new(),
                mode: 0o644,
            },
        }
    } else {
        Step {
            label: "settings",
            target: CONFIG.to_owned(),
            state: State::Change("write it from the options".to_owned()),
            action: Action::File {
                dirs: &[CONFIG_DIR],
                content: render_config(args, root)?.into_bytes(),
                mode: 0o644,
            },
        }
    };
    let mut steps = vec![
        Step {
            label: "program",
            target: PROGRAM.to_owned(),
            state: program,
            action: Action::File {
                dirs: &[],
                content: program_content,
                mode: 0o755,
            },
        },
        Step {
            label: "system user",
            target: USER.to_owned(),
            state: user_state()?,
            action: Action::User,
        },
        Step {
            label: "machine token",
            target: TOKEN.to_owned(),
            state: token_state(root),
            action: Action::Token,
        },
        file("systemd unit", UNIT_PATH, UNIT, 0o644, &[])?,
        config,
    ];
    let restart = steps.iter().any(|step| !matches!(step.state, State::Ready));
    steps.push(Step {
        label: "service",
        target: UNIT_NAME.to_owned(),
        state: service_state(restart)?,
        action: Action::Service,
    });
    let shim_dirs: &[&str] = &[SHIMS_PARENT, SHIMS];
    steps.push(file(
        "gh shim",
        "/usr/local/lib/bas/shims/gh",
        GH_SHIM,
        0o755,
        shim_dirs,
    )?);
    steps.push(file(
        "ssh-keygen shim",
        SSH_KEYGEN_SHIM_PATH,
        SSH_KEYGEN_SHIM,
        0o755,
        shim_dirs,
    )?);
    steps.push(file("ssh config", SSH_CONFIG, SSH_CONFIG_TEXT, 0o644, &[])?);
    steps.push(Step {
        label: "git signing",
        target: format!("{GIT_KEY} in the system Git settings"),
        state: git_state()?,
        action: Action::GitProgram,
    });
    Ok(steps)
}

/// Compares a file with the bytes, the mode, and the root owner the install gives it.
fn file_state(path: &str, content: &[u8], mode: u32) -> Result<State> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(State::Change("create it".to_owned()));
        }
        Err(err) => return Err(Error::new(format!("could not check {path}: {err}"))),
    };
    let found =
        fs::read(path).map_err(|err| Error::new(format!("could not read {path}: {err}")))?;
    Ok(if found != content {
        State::Change("replace it, because its content differs".to_owned())
    } else if metadata.uid() != 0 || metadata.permissions().mode() & 0o7777 != mode {
        State::Change(format!("set the owner to root and the mode to {mode:o}"))
    } else {
        State::Ready
    })
}

fn user_state() -> Result<State> {
    let found = quiet("getent", &["passwd", USER])?;
    Ok(if found {
        State::Ready
    } else {
        State::Change("create it with useradd, with no login shell".to_owned())
    })
}

/// Only root can look inside the directory that holds the sealed token.
fn token_state(root: bool) -> State {
    if Path::new(TOKEN).exists() {
        State::Ready
    } else if root {
        State::Change("ask for the token and seal it with systemd-creds".to_owned())
    } else {
        State::Unknown("only root can see whether the token is sealed".to_owned())
    }
}

fn service_state(restart: bool) -> Result<State> {
    Ok(if restart {
        State::Change("enable it, and start it again with the changes above".to_owned())
    } else if !quiet("systemctl", &["is-enabled", "--quiet", UNIT_NAME])? {
        State::Change("enable it and start it".to_owned())
    } else if !quiet("systemctl", &["is-active", "--quiet", UNIT_NAME])? {
        State::Change("start it".to_owned())
    } else {
        State::Ready
    })
}

fn git_state() -> Result<State> {
    let output = match Command::new("git")
        .args(["config", "--system", "--get", GIT_KEY])
        .stderr(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(State::Skipped("git is not installed".to_owned()));
        }
        Err(err) => return Err(Error::new(format!("could not run git: {err}"))),
    };
    Ok(
        if String::from_utf8_lossy(&output.stdout).trim_end() == SSH_KEYGEN_SHIM_PATH {
            State::Ready
        } else {
            State::Change(format!("set it to {SSH_KEYGEN_SHIM_PATH}"))
        },
    )
}

/// The text of a new `broker.toml`, checked with the rules the broker applies at start.
fn render_config(args: &BrokerInstallArgs, root: bool) -> Result<String> {
    let (Some(organization), Some(origin)) = (&args.organization, &args.origin) else {
        return Err(Error::usage(format!(
            "{CONFIG} does not exist yet, so pass --organization and --origin"
        )));
    };
    let mut flags = EndpointFlags::from(args.endpoint.clone());
    if flags == EndpointFlags::default() {
        flags.region = Some(Region::Us);
    }
    let endpoints = Endpoints::from_flags(&flags).map_err(|err| Error::usage(err.to_string()))?;
    let mut profile = toml::Table::new();
    profile.insert("name".to_owned(), args.profile.clone().into());
    profile.insert("organization".to_owned(), organization.clone().into());
    profile.insert("api-url".to_owned(), endpoints.api().into());
    profile.insert("identity-url".to_owned(), endpoints.identity().into());
    if let Some(project) = &args.project {
        profile.insert("project".to_owned(), project.clone().into());
    }
    let mut approvals = toml::Table::new();
    approvals.insert("listen".to_owned(), APPROVALS_LISTEN.into());
    approvals.insert("origin".to_owned(), origin.clone().into());
    let uids: Vec<toml::Value> = allow_uids(args, root)?
        .into_iter()
        .map(|uid| toml::Value::Integer(uid.into()))
        .collect();
    let mut settings = toml::Table::new();
    settings.insert("allow-uids".to_owned(), uids.into());
    settings.insert("profile".to_owned(), profile.into());
    settings.insert("approvals".to_owned(), approvals.into());
    let body = toml::to_string(&settings)
        .map_err(|err| Error::new(format!("could not write the settings: {err}")))?;
    let text = format!(
        "# Written by `bas broker install`. Settings for this machine only.\n\
         # The install guide lists every key: {GUIDE}\n{body}"
    );
    // An option may hold a pasted secret, so the refusal repeats no value.
    bas_broker::check_config(&text, Path::new(CONFIG)).map_err(|_| {
        Error::usage(
            "the broker would refuse these options: --organization and --project take IDs, \
             --origin looks like https://bas.example.com with no path, and --profile takes a \
             profile name",
        )
    })?;
    Ok(text)
}

/// The users who may use the broker: the ones named, else the user who ran sudo.
fn allow_uids(args: &BrokerInstallArgs, root: bool) -> Result<Vec<u32>> {
    if !args.allow_uids.is_empty() {
        return Ok(args.allow_uids.clone());
    }
    let own = if root {
        env::var("SUDO_UID")
            .ok()
            .and_then(|uid| uid.parse().ok())
            .filter(|uid| *uid != 0)
    } else {
        Some(rustix::process::getuid().as_raw())
    };
    own.map(|uid| vec![uid]).ok_or_else(|| {
        Error::usage("pass --allow-uid with your own user ID, because sudo did not say who ran it")
    })
}

fn apply(step: &Step) -> Result<()> {
    match &step.action {
        Action::File {
            dirs,
            content,
            mode,
        } => {
            for dir in *dirs {
                ensure_dir(dir, 0o755)?;
            }
            write_file(&step.target, content, *mode)
        }
        Action::User => run(
            "useradd",
            &[
                "--system",
                "--home-dir",
                "/var/lib/bas",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                USER,
            ],
        ),
        Action::Token => seal_token(),
        Action::GitProgram => run(
            "git",
            &["config", "--system", GIT_KEY, SSH_KEYGEN_SHIM_PATH],
        ),
        Action::Service => {
            run("systemctl", &["daemon-reload"])?;
            run("systemctl", &["enable", UNIT_NAME])?;
            run("systemctl", &["restart", UNIT_NAME]).map_err(|_| {
                Error::new(format!(
                    "{UNIT_NAME} did not start. `journalctl -u bas-broker -e` shows why, for \
                     example a token that Secrets Manager refused. To seal another token, \
                     remove {TOKEN} and run the install again."
                ))
            })
        }
    }
}

/// Pipes the hidden prompt into the encryption, so the token is never in this process,
/// in an argument, or in a file as plain text.
fn seal_token() -> Result<()> {
    ensure_dir(TOKEN_DIR, 0o700)?;
    let sealed = PathBuf::from(format!("{TOKEN}.new"));
    let mut ask = Command::new("systemd-ask-password")
        .args(["-n", "Machine token for the bas broker:"])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| Error::new(format!("could not run systemd-ask-password: {err}")))?;
    let prompt = ask
        .stdout
        .take()
        .ok_or_else(|| Error::new("could not read from systemd-ask-password"))?;
    let encrypted = Command::new("systemd-creds")
        .args(["encrypt", "--name=bws", "-"])
        .arg(&sealed)
        .stdin(Stdio::from(prompt))
        .status()
        .map_err(|err| Error::new(format!("could not run systemd-creds: {err}")));
    let asked = ask
        .wait()
        .map_err(|err| Error::new(format!("could not wait for systemd-ask-password: {err}")));
    let result = match (asked, encrypted) {
        (Ok(asked), Ok(encrypted)) if asked.success() && encrypted.success() => {
            fs::set_permissions(&sealed, fs::Permissions::from_mode(0o600))
                .and_then(|()| fs::rename(&sealed, TOKEN))
                .map_err(|err| Error::new(format!("could not save {TOKEN}: {err}")))
        }
        (Err(err), _) | (_, Err(err)) => Err(err),
        _ => Err(Error::new("the machine token was not sealed")),
    };
    if result.is_err() {
        let _ = fs::remove_file(&sealed);
    }
    result
}

fn ensure_dir(path: &str, mode: u32) -> Result<()> {
    let failed = |err: io::Error| Error::new(format!("could not prepare {path}: {err}"));
    match DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(failed(err)),
    }
    // The mode given to mkdir is cut by the umask that sudo passes on.
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(failed)
}

/// Writes beside the target and renames, which also replaces a program that is running.
fn write_file(path: &str, content: &[u8], mode: u32) -> Result<()> {
    let new = format!("{path}.new");
    let written = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&new)
        .and_then(|mut file| {
            file.write_all(content)?;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&new, path));
    written.map_err(|err| {
        let _ = fs::remove_file(&new);
        Error::new(format!("could not write {path}: {err}"))
    })
}

/// Whether a command that prints nothing useful exits with success.
fn quiet(program: &str, args: &[&str]) -> Result<bool> {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|err| Error::new(format!("could not run {program}: {err}")))
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|err| Error::new(format!("could not run {program}: {err}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::new(format!("{program} {} failed", args.join(" "))))
    }
}
