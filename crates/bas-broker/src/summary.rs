//! What each entry of a policy text lets a machine use, in plain words. The broker sends
//! these summaries with `GET /v1/policy`, so a client shows a newer broker's entries
//! without reading its policy text. A client that talks to an older broker builds them
//! itself from the text.

use serde::{Deserialize, Serialize};

use crate::policy::{GithubFile, PolicyFile, SecretFile, TailscaleFile};

/// What kind of entry a policy table is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// `[secret.NAME]`: a stored value the proxy adds for one host.
    Secret,
    /// `[helper.NAME]`: a stored value that `bas get` prints, for credential helpers.
    Helper,
    /// `[ssh.NAME]`: a key the ssh-agent signs with.
    Ssh,
    /// `[github]`: a GitHub App that mints repository tokens.
    Github,
    /// `[tailscale]`: an OAuth client that mints API tokens.
    Tailscale,
    /// A kind that a newer broker knows and this client does not.
    #[serde(other)]
    Other,
}

impl EntryKind {
    /// Whether `POST /v1/secrets/NAME/rotate` accepts the entry: a stored value is replaced
    /// after an approval, and minted tokens are dropped at once.
    #[must_use]
    pub fn rotatable(self) -> bool {
        matches!(self, Self::Secret | Self::Github | Self::Tailscale)
    }

    /// The kind as it is sent, such as `secret`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Helper => "helper",
            Self::Ssh => "ssh",
            Self::Github => "github",
            Self::Tailscale => "tailscale",
            Self::Other => "other",
        }
    }
}

/// One entry of a policy, for display. It names where values live, never a value.
///
/// Every field but `kind` and `name` has a default, so a client reads summaries from a
/// broker that sends fewer or more fields than it knows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrySummary {
    /// What kind of table it is.
    pub kind: EntryKind,
    /// The policy name: the `NAME` of `[secret.NAME]` or `[ssh.NAME]`, else `github` or
    /// `tailscale`, which is also what `bas rotate` takes.
    pub name: String,
    /// A few words for a list row, such as the host an API key is sent to.
    #[serde(default)]
    pub hint: String,
    /// Sentences that say what the entry lets a program do.
    #[serde(default)]
    pub about: Vec<String>,
    /// The rules of the entry in plain words, such as `Allowed: GET and POST /v1/*`.
    #[serde(default)]
    pub facts: Vec<Detail>,
    /// How a program uses the entry, such as `bas run --with NAME -- CMD`.
    #[serde(default, rename = "use")]
    pub usage: String,
    /// The `bas://` references of the stored values, labelled when there are several.
    #[serde(default)]
    pub references: Vec<Detail>,
    /// The table's settings by their policy keys, in the order the table lists them. A
    /// key such as `repo` repeats.
    #[serde(default)]
    pub details: Vec<Detail>,
}

/// A label and a text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detail {
    /// What the text is, such as `host`.
    pub label: String,
    /// The text. A list is joined with `, `.
    pub value: String,
}

impl Detail {
    fn new(label: &str, value: impl Into<String>) -> Self {
        Self {
            label: label.to_owned(),
            value: value.into(),
        }
    }
}

impl EntrySummary {
    /// The text of the first setting with the policy key `label`.
    #[must_use]
    pub fn detail(&self, label: &str) -> Option<&str> {
        self.details
            .iter()
            .find(|detail| detail.label == label)
            .map(|detail| detail.value.as_str())
    }
}

/// Lists the entries of a policy text in the order the broker reads them: secrets,
/// helpers, ssh keys, then `[github]` and `[tailscale]`. Checks only the shape of the text,
/// not its references or rules.
///
/// # Errors
///
/// Fails with the TOML parser's message when the text is not a policy.
pub fn summarize(text: &str) -> Result<Vec<EntrySummary>, String> {
    let file: PolicyFile = toml::from_str(text).map_err(|err| err.message().to_owned())?;
    let mut entries = Vec::new();
    for (name, secret) in file.secret {
        entries.push(secret_entry(name, secret));
    }
    for (name, helper) in file.helper {
        entries.push(EntrySummary {
            kind: EntryKind::Helper,
            hint: "read with bas get".to_owned(),
            about: vec![
                "bas get prints this value, so a config file can run a command to read it \
                 instead of holding it."
                    .to_owned(),
            ],
            facts: Vec::new(),
            usage: format!("bas get {}", helper.reference),
            references: vec![Detail::new("", helper.reference.clone())],
            details: vec![Detail::new("ref", helper.reference)],
            name,
        });
    }
    for (name, ssh) in file.ssh {
        let tasks: Vec<&str> = ssh
            .uses
            .iter()
            .map(|task| match task.as_str() {
                "sign-git" => "signs git commits",
                "auth" => "logs in to SSH servers",
                other => other,
            })
            .collect();
        let tasks = and_list(&tasks);
        entries.push(EntrySummary {
            kind: EntryKind::Ssh,
            about: vec![
                format!("The broker's SSH agent {tasks} with this key."),
                "The key never leaves the broker.".to_owned(),
            ],
            hint: tasks,
            facts: Vec::new(),
            usage: "ssh and git through the broker's ssh-agent".to_owned(),
            references: vec![Detail::new("", ssh.reference.clone())],
            details: vec![
                Detail::new("ref", ssh.reference),
                Detail::new("use", ssh.uses.join(", ")),
            ],
            name,
        });
    }
    if let Some(github) = file.github {
        entries.push(github_entry(github));
    }
    if let Some(tailscale) = file.tailscale {
        entries.push(tailscale_entry(tailscale));
    }
    Ok(entries)
}

fn secret_entry(name: String, secret: SecretFile) -> EntrySummary {
    let host = secret.host.clone().unwrap_or_default();
    let target = match secret.header.as_deref() {
        None | Some("Authorization") => format!("requests to {host}"),
        Some(header) => format!("the {header} header of requests to {host}"),
    };
    let mut facts: Vec<Detail> = allowed(secret.allow.as_deref().unwrap_or_default())
        .into_iter()
        .map(|rule| Detail::new("Allowed", rule))
        .collect();
    if facts.is_empty() {
        facts.push(Detail::new("Allowed", "nothing yet"));
    }
    let mut details = vec![Detail::new("ref", secret.reference.clone())];
    let optional = [
        ("host", secret.host),
        ("header", secret.header),
        ("value", secret.value),
        ("allow", secret.allow.map(|allow| allow.join(", "))),
    ];
    details.extend(
        optional
            .into_iter()
            .filter_map(|(label, value)| value.map(|value| Detail::new(label, value))),
    );
    EntrySummary {
        kind: EntryKind::Secret,
        about: vec![
            format!("The broker adds this key to {target}."),
            "It refuses every other request, and the program never sees the key.".to_owned(),
        ],
        hint: host,
        facts,
        usage: format!("bas run --with {name} -- CMD"),
        references: vec![Detail::new("", secret.reference)],
        details,
        name,
    }
}

/// `METHOD /path` rules with the methods of one path joined, such as `GET and POST /v1/*`.
fn allowed(rules: &[String]) -> Vec<String> {
    let mut paths: Vec<(&str, Vec<&str>)> = Vec::new();
    for rule in rules {
        let (method, path) = rule.split_once(' ').unwrap_or(("", rule.as_str()));
        match paths.iter_mut().find(|(known, _)| *known == path) {
            Some((_, methods)) => methods.push(method),
            None => paths.push((path, vec![method])),
        }
    }
    paths
        .into_iter()
        .map(|(path, methods)| format!("{} {path}", and_list(&methods)))
        .collect()
}

/// `A`, `A and B`, or `A, B and C`.
fn and_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [only] => (*only).to_owned(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn github_entry(github: GithubFile) -> EntrySummary {
    let count = github.repo.len();
    let mut about = vec![if count == 0 {
        "The broker makes short-lived GitHub tokens for gh and git, but no repository is \
         listed yet."
            .to_owned()
    } else {
        "The broker makes short-lived GitHub tokens for gh and git, only for the \
         repositories below."
            .to_owned()
    }];
    about.push(if github.user_token.is_some() {
        "Requests that name no repository use your user token.".to_owned()
    } else {
        "Requests that name no repository are refused.".to_owned()
    });
    let mut facts = vec![Detail::new("GitHub App", github.app_id.to_string())];
    let mut references = vec![Detail::new("app private key", github.private_key.clone())];
    let mut details = vec![
        Detail::new("app_id", github.app_id.to_string()),
        Detail::new("private_key", github.private_key),
    ];
    if let Some(user_token) = github.user_token {
        references.push(Detail::new("user token", user_token.clone()));
        details.push(Detail::new("user_token", user_token));
    }
    // Repositories with the same permissions share one pair of lines, so a long list
    // stays short.
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for repo in github.repo {
        let plain: Vec<String> = repo
            .permissions
            .iter()
            .map(|(scope, level)| format!("{} {level}", scope.replace('_', " ")))
            .collect();
        let plain = plain.join(", ");
        match groups.iter_mut().find(|(known, _)| *known == plain) {
            Some((_, names)) => names.push(repo.name.clone()),
            None => groups.push((plain, vec![repo.name.clone()])),
        }
        let raw: Vec<String> = repo
            .permissions
            .iter()
            .map(|(scope, level)| format!("{scope}={level}"))
            .collect();
        details.push(Detail::new(
            "repo",
            format!("{} ({})", repo.name, raw.join(", ")),
        ));
    }
    for (permissions, names) in groups {
        facts.push(Detail::new("Repositories", names.join(", ")));
        let permissions = if permissions.is_empty() {
            "nothing".to_owned()
        } else {
            permissions
        };
        facts.push(Detail::new("They allow", permissions));
    }
    EntrySummary {
        kind: EntryKind::Github,
        name: "github".to_owned(),
        hint: if count == 1 {
            "1 repository".to_owned()
        } else {
            format!("{count} repositories")
        },
        about,
        facts,
        usage: "gh and git for the listed repositories".to_owned(),
        references,
        details,
    }
}

fn tailscale_entry(tailscale: TailscaleFile) -> EntrySummary {
    let count = tailscale.api_allow.len();
    let mut facts: Vec<Detail> = allowed(&tailscale.api_allow)
        .into_iter()
        .map(|rule| Detail::new("Allowed", rule))
        .collect();
    facts.push(Detail::new("Token scopes", tailscale.scopes.join(", ")));
    EntrySummary {
        kind: EntryKind::Tailscale,
        name: "tailscale".to_owned(),
        hint: if count == 1 {
            "1 API call".to_owned()
        } else {
            format!("{count} API calls")
        },
        about: vec![
            "The broker makes short-lived Tailscale API tokens and allows only the calls \
             below."
                .to_owned(),
        ],
        facts,
        usage: "bas run --with tailscale -- CMD".to_owned(),
        references: vec![
            Detail::new("client ID", tailscale.client_id.clone()),
            Detail::new("client secret", tailscale.client_secret.clone()),
        ],
        details: vec![
            Detail::new("client_id", tailscale.client_id),
            Detail::new("client_secret", tailscale.client_secret),
            Detail::new("scopes", tailscale.scopes.join(", ")),
            Detail::new("api_allow", tailscale.api_allow.join(", ")),
        ],
    }
}
