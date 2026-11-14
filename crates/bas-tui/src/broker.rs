//! Broker mode: manages the policy of a bas broker through its socket, without a machine
//! token and without ever seeing a value.
//!
//! The app lists the active policy's entries, and starts the same requests as `bas add`,
//! `bas rotate`, `bas policy edit`, and `bas passkey add`. An enrolled passkey approves
//! each of them on the broker's approval page, and a new value is typed only there. The
//! requests panel shows every request this app started and every one the broker reports as
//! pending, as sending, pending, approved, done, denied, expired, refused, or failed.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use arboard::Clipboard;
use bas_broker::client::{Client, Outcome};
use bas_broker::protocol::{
    self, ActivePolicy, AddSecret, ApprovalState, EntryKind, EntrySummary, PolicyProposal,
    SecretEntry, summarize_policy,
};
use bas_broker::{ErrorKind, proposal};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

use crate::app::is_typing;
use crate::event::{AppEvent, Event, EventHandler};
use crate::ui::Status;

/// How long each approval wait lasts before the app asks again.
const WAIT_SECONDS: u32 = 25;
/// Ticks between status refreshes. Ticks come four times a second.
const REFRESH_TICKS: u32 = 20;

/// A broker call that starts a request.
type Call =
    Pin<Box<dyn Future<Output = Result<Outcome<serde_json::Value>, bas_broker::Error>> + Send>>;

/// A broker call that finished.
#[derive(Debug)]
pub enum Update {
    /// `GET /v1/status` answered.
    Status(Result<protocol::Status, bas_broker::Error>),
    /// `GET /v1/policy` answered. `sync` asks to rewrite the proposal file from it.
    Policy {
        result: Result<ActivePolicy, bas_broker::Error>,
        sync: bool,
    },
    /// The request numbered `key` was sent.
    Sent {
        key: u64,
        result: Result<Outcome<serde_json::Value>, bas_broker::Error>,
    },
    /// The approval of request `key` answered.
    State {
        key: u64,
        result: Result<ApprovalState, bas_broker::Error>,
    },
}

/// Which list the arrow keys move in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Entries,
    Requests,
}

/// What the broker said about the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Connection {
    Connecting,
    Connected {
        version: String,
        policy_hash: String,
    },
    Failed(String),
}

/// One request, started here or seen pending on the broker.
#[derive(Debug, Clone)]
pub struct Request {
    /// Local number, which ties broker answers to the request.
    pub key: u64,
    /// What it asks for, such as `rotate JINA_API_KEY`.
    pub action: String,
    /// What kind of request it is, for what happens after approval.
    pub kind: RequestKind,
    /// Approval ID, once the broker opened one.
    pub id: Option<String>,
    /// The approval page to open.
    pub url: Option<String>,
    /// The diff of a policy change.
    pub diff: Option<String>,
    /// Whether this app started it.
    pub mine: bool,
    pub state: RequestState,
}

/// What a request is, for the follow-up after it is approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Add,
    Rotate,
    Policy,
    Passkey,
    /// Started by another client.
    Other,
}

/// Where a request stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestState {
    /// On its way to the broker.
    Sending,
    /// Waiting for an approval.
    Pending,
    /// Approved on the approval page and applied, with what the broker reported.
    Approved(String),
    /// Finished without an approval, such as dropped minted tokens.
    Done(String),
    /// Denied on the approval page.
    Denied,
    /// Nobody answered in time.
    Expired,
    /// The broker refused it, so nothing changed.
    Refused(String),
    /// The broker could not be reached, or it could not apply an approved change.
    Failed(String),
}

impl RequestState {
    fn from_approval(state: &ApprovalState) -> Self {
        match state.state.as_str() {
            "pending" => Self::Pending,
            "approved" => Self::Approved(describe_result(state.result.as_ref())),
            "denied" => Self::Denied,
            "expired" => Self::Expired,
            "failed" => Self::Failed(format!(
                "approved, but the broker could not apply it: {}",
                state.error.clone().unwrap_or_default()
            )),
            other => Self::Failed(format!("the broker reported an unknown state: {other}")),
        }
    }

    /// Whether the request can still change.
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Sending | Self::Pending)
    }
}

/// A field of the add form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddField {
    Name,
    Host,
    Header,
    Value,
    Allow,
}

impl AddField {
    pub const ALL: [Self; 5] = [
        Self::Name,
        Self::Host,
        Self::Header,
        Self::Value,
        Self::Allow,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "Name (environment variable name, also the Bitwarden key)",
            Self::Host => "Host the proxy adds the credential for",
            Self::Header => "Header",
            Self::Value => "Header value, with {secret} where the value goes",
            Self::Allow => "Allowed requests, METHOD /path/glob, separated by commas",
        }
    }
}

/// The add form. It never holds a value: the value is typed on the approval page.
#[derive(Debug, Clone)]
pub struct AddForm {
    pub focus: AddField,
    pub name: String,
    pub host: String,
    pub header: String,
    pub value: String,
    pub allow: String,
}

impl AddForm {
    fn new() -> Self {
        Self {
            focus: AddField::Name,
            name: String::new(),
            host: String::new(),
            header: "Authorization".to_owned(),
            value: "Bearer {secret}".to_owned(),
            allow: String::new(),
        }
    }

    pub fn text(&self, field: AddField) -> &str {
        match field {
            AddField::Name => &self.name,
            AddField::Host => &self.host,
            AddField::Header => &self.header,
            AddField::Value => &self.value,
            AddField::Allow => &self.allow,
        }
    }

    fn text_mut(&mut self) -> &mut String {
        match self.focus {
            AddField::Name => &mut self.name,
            AddField::Host => &mut self.host,
            AddField::Header => &mut self.header,
            AddField::Value => &mut self.value,
            AddField::Allow => &mut self.allow,
        }
    }

    fn step(&mut self, forward: bool) {
        let index = AddField::ALL
            .iter()
            .position(|field| *field == self.focus)
            .unwrap_or_default();
        let next = if forward {
            (index + 1) % AddField::ALL.len()
        } else {
            (index + AddField::ALL.len() - 1) % AddField::ALL.len()
        };
        self.focus = AddField::ALL[next];
    }

    fn request(&self) -> AddSecret {
        AddSecret {
            name: self.name.trim().to_owned(),
            entry: SecretEntry {
                reference: String::new(),
                delivery: "proxy".to_owned(),
                host: Some(self.host.trim().to_owned()),
                header: Some(self.header.trim().to_owned()),
                value: Some(self.value.trim().to_owned()),
                allow: Some(
                    self.allow
                        .split(',')
                        .map(str::trim)
                        .filter(|allow| !allow.is_empty())
                        .map(str::to_owned)
                        .collect(),
                ),
            },
        }
    }
}

/// A popup over the screen.
#[derive(Debug, Clone)]
pub enum Modal {
    Help,
    Add(AddForm),
    /// Asks before a request that opens an approval or drops tokens.
    Confirm(Confirm),
    /// Shows one request in full.
    Details(u64),
}

/// A request that waits for `y`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirm {
    Rotate { name: String, minted: bool },
    Passkey,
}

/// Broker mode state.
pub struct BrokerApp {
    running: bool,
    events: EventHandler,
    client: Arc<Client>,
    pub connection: Connection,
    /// The active policy's entries, once read.
    pub entries: Option<Vec<EntrySummary>>,
    /// Why the active policy could not be listed.
    pub policy_error: Option<String>,
    pub selected: usize,
    pub requests: Vec<Request>,
    pub request_selected: usize,
    pub focus: Focus,
    pub modal: Option<Modal>,
    pub message: Status,
    clipboard: Option<Clipboard>,
    next_key: u64,
    ticks: u32,
    status_in_flight: bool,
    /// Set by `e`. The loop opens the editor after drawing, because the editor needs the
    /// terminal.
    edit_requested: bool,
}

impl BrokerApp {
    /// Builds the app for the broker at `socket` and asks for its status and policy.
    pub fn new(socket: &Path, events: EventHandler) -> Self {
        let app = Self {
            running: true,
            events,
            client: Arc::new(Client::new(socket)),
            connection: Connection::Connecting,
            entries: None,
            policy_error: None,
            selected: 0,
            requests: Vec::new(),
            request_selected: 0,
            focus: Focus::Entries,
            modal: None,
            message: Status::Info(format!("Connecting to the broker at {}", socket.display())),
            clipboard: Clipboard::new().ok(),
            next_key: 0,
            ticks: 0,
            status_in_flight: false,
            edit_requested: false,
        };
        app.load_policy(false);
        app
    }

    /// The broker socket.
    pub fn socket(&self) -> &Path {
        self.client.socket()
    }

    /// Runs the main loop until the user quits.
    ///
    /// # Errors
    ///
    /// Fails when drawing fails or the event task dies.
    pub async fn run(mut self, terminal: &mut DefaultTerminal) -> color_eyre::Result<()> {
        self.refresh_status();
        while self.running {
            terminal.draw(|frame| frame.render_widget(&self, frame.area()))?;
            if self.edit_requested {
                self.edit_requested = false;
                self.edit_policy(terminal).await?;
                continue;
            }
            match self.events.next().await? {
                Event::Tick => self.tick(),
                Event::Crossterm(crossterm::event::Event::Key(key))
                    if key.kind == KeyEventKind::Press =>
                {
                    self.handle_key(key);
                }
                Event::Crossterm(_) => {}
                Event::App(AppEvent::Broker(update)) => self.handle_update(*update),
                Event::App(AppEvent::Quit) => self.running = false,
                Event::App(_) => {}
            }
        }
        Ok(())
    }

    fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks.is_multiple_of(REFRESH_TICKS) {
            self.refresh_status();
        }
    }

    fn key(&mut self) -> u64 {
        self.next_key += 1;
        self.next_key
    }

    fn refresh_status(&mut self) {
        if self.status_in_flight {
            return;
        }
        self.status_in_flight = true;
        let client = Arc::clone(&self.client);
        self.events.spawn(async move {
            AppEvent::Broker(Box::new(Update::Status(client.status().await)))
        });
    }

    fn load_policy(&self, sync: bool) {
        let client = Arc::clone(&self.client);
        self.events.spawn(async move {
            AppEvent::Broker(Box::new(Update::Policy {
                result: client.policy().await,
                sync,
            }))
        });
    }

    /// Asks the broker for the state of approval `id`, waiting while it is pending.
    fn watch(&self, key: u64, id: String) {
        let client = Arc::clone(&self.client);
        self.events.spawn(async move {
            AppEvent::Broker(Box::new(Update::State {
                key,
                result: client.approval(&id, WAIT_SECONDS).await,
            }))
        });
    }

    fn handle_update(&mut self, update: Update) {
        match update {
            Update::Status(result) => self.on_status(result),
            Update::Policy { result, sync } => self.on_policy(result, sync),
            Update::Sent { key, result } => self.on_sent(key, result),
            Update::State { key, result } => self.on_state(key, result),
        }
    }

    fn on_status(&mut self, result: Result<protocol::Status, bas_broker::Error>) {
        self.status_in_flight = false;
        let status = match result {
            Ok(status) => status,
            Err(err) => {
                self.connection = Connection::Failed(err.to_string());
                return;
            }
        };
        let policy_changed = match &self.connection {
            Connection::Connected { policy_hash, .. } => *policy_hash != status.policy_hash,
            _ => {
                self.message = Status::Info("Connected to the broker".to_owned());
                true
            }
        };
        self.connection = Connection::Connected {
            version: status.version.clone(),
            policy_hash: status.policy_hash.clone(),
        };
        if policy_changed {
            self.load_policy(false);
        }
        for pending in status.requests {
            let known = self
                .requests
                .iter()
                .any(|request| request.id.as_deref() == Some(pending.id.as_str()));
            if known {
                continue;
            }
            let key = self.key();
            let subject = if pending.subject.is_empty() {
                String::new()
            } else {
                format!(" {}", pending.subject)
            };
            self.requests.push(Request {
                key,
                action: format!("{}{subject} (uid {})", pending.kind, pending.peer_uid),
                kind: RequestKind::Other,
                id: Some(pending.id.clone()),
                url: Some(pending.url),
                diff: None,
                mine: false,
                state: RequestState::Pending,
            });
            self.watch(key, pending.id);
        }
    }

    fn on_policy(&mut self, result: Result<ActivePolicy, bas_broker::Error>, sync: bool) {
        let policy = match result {
            Ok(policy) => policy,
            Err(err) => {
                self.policy_error = Some(err.to_string());
                return;
            }
        };
        match summarize_policy(&policy.toml) {
            Ok(entries) => {
                self.selected = self.selected.min(entries.len().saturating_sub(1));
                self.entries = Some(entries);
                self.policy_error = None;
            }
            Err(err) => self.policy_error = Some(format!("the active policy is unreadable: {err}")),
        }
        if sync {
            let synced = proposal::path().and_then(|path| {
                proposal::write(&path, &policy.toml)?;
                Ok(path)
            });
            self.message = match synced {
                Ok(path) => {
                    Status::Info(format!("Rewrote {} from the active policy", path.display()))
                }
                Err(err) => Status::Error(err.to_string()),
            };
        }
    }

    fn on_sent(&mut self, key: u64, result: Result<Outcome<serde_json::Value>, bas_broker::Error>) {
        if let Ok(Outcome::Waiting(accepted)) = &result {
            // A status poll can list this approval before this reply names it as ours.
            self.drop_other(&accepted.approval.id);
        }
        let Some(request) = self.requests.iter_mut().find(|request| request.key == key) else {
            return;
        };
        match result {
            Ok(Outcome::Waiting(accepted)) => {
                request.id = Some(accepted.approval.id.clone());
                request.url = Some(accepted.approval.url.clone());
                request.diff = accepted.diff;
                request.state = RequestState::Pending;
                self.message = Status::Info(format!(
                    "Approve {} with your passkey: {}",
                    request.action, accepted.approval.url
                ));
                self.watch(key, accepted.approval.id);
            }
            Ok(Outcome::Done(result)) => {
                let text = match (request.kind, &result) {
                    (RequestKind::Rotate, _) => {
                        "dropped the cached tokens; the next request mints new ones".to_owned()
                    }
                    (RequestKind::Policy, _) => {
                        "the proposal matches the active policy; nothing to approve".to_owned()
                    }
                    _ => describe_result(Some(&result)),
                };
                self.message = Status::Info(format!("{}: {text}", request.action));
                request.state = RequestState::Done(text);
            }
            Err(err) => {
                let text = err.to_string();
                self.message = Status::Error(format!("{}: {text}", request.action));
                request.state = if err.kind() == ErrorKind::Refused {
                    RequestState::Refused(text)
                } else {
                    RequestState::Failed(text)
                };
            }
        }
    }

    /// Removes the row another client's request got for approval `id`, keeping the
    /// selection on the same row.
    fn drop_other(&mut self, id: &str) {
        let Some(index) = self
            .requests
            .iter()
            .position(|request| !request.mine && request.id.as_deref() == Some(id))
        else {
            return;
        };
        self.requests.remove(index);
        if self.request_selected > index {
            self.request_selected -= 1;
        }
        self.request_selected = self
            .request_selected
            .min(self.requests.len().saturating_sub(1));
    }

    fn on_state(&mut self, key: u64, result: Result<ApprovalState, bas_broker::Error>) {
        let Some(request) = self.requests.iter_mut().find(|request| request.key == key) else {
            return;
        };
        let state = match result {
            Ok(state) => RequestState::from_approval(&state),
            Err(err) => RequestState::Failed(format!(
                "lost track of the approval: {err}. Press g to look again"
            )),
        };
        if state == RequestState::Pending {
            if let Some(id) = request.id.clone() {
                self.watch(key, id);
            }
            return;
        }
        let approved = matches!(state, RequestState::Approved(_));
        let kind = request.kind;
        let action = request.action.clone();
        self.message = match &state {
            RequestState::Approved(text) => Status::Info(format!("{action}: approved, {text}")),
            RequestState::Denied => Status::Error(format!("{action}: denied on the approval page")),
            RequestState::Expired => Status::Error(format!("{action}: expired")),
            RequestState::Failed(text) => Status::Error(format!("{action}: {text}")),
            _ => self.message.clone(),
        };
        request.state = state;
        if approved {
            // The policy changed for every kind but rotate and passkey; a mine add or
            // policy change also rewrites the proposal file, as the commands do.
            let mine_change =
                request.mine && matches!(kind, RequestKind::Add | RequestKind::Policy);
            self.load_policy(mine_change);
            self.refresh_status();
        }
    }

    /// Records a new request of this app and sends it.
    fn send(&mut self, action: String, kind: RequestKind, call: impl FnOnce(Arc<Client>) -> Call) {
        let key = self.key();
        self.requests.push(Request {
            key,
            action: action.clone(),
            kind,
            id: None,
            url: None,
            diff: None,
            mine: true,
            state: RequestState::Sending,
        });
        self.request_selected = self.requests.len() - 1;
        self.message = Status::Info(format!("Sending {action}"));
        let future = call(Arc::clone(&self.client));
        self.events.spawn(async move {
            AppEvent::Broker(Box::new(Update::Sent {
                key,
                result: future.await,
            }))
        });
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            self.running = false;
            return;
        }
        if let Some(modal) = self.modal.take() {
            self.modal = self.handle_modal_key(modal, key);
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.running = false,
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Entries => Focus::Requests,
                    Focus::Requests => Focus::Entries,
                };
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(true),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(false),
            KeyCode::Char('g') => {
                self.refresh_status();
                self.load_policy(false);
                for request in &self.requests {
                    if let (RequestState::Failed(_), Some(id)) = (&request.state, &request.id) {
                        self.watch(request.key, id.clone());
                    }
                }
                self.message = Status::Info("Refreshing".to_owned());
            }
            KeyCode::Char('a') => self.modal = Some(Modal::Add(AddForm::new())),
            KeyCode::Char('r') => self.ask_rotate(),
            KeyCode::Char('e') => self.edit_requested = true,
            KeyCode::Char('p') => self.modal = Some(Modal::Confirm(Confirm::Passkey)),
            KeyCode::Enter if self.focus == Focus::Requests => {
                if let Some(request) = self.requests.get(self.request_selected) {
                    self.modal = Some(Modal::Details(request.key));
                }
            }
            KeyCode::Char('c') if self.focus == Focus::Requests => self.copy_url(),
            _ => {}
        }
    }

    fn move_selection(&mut self, down: bool) {
        let (selected, len) = match self.focus {
            Focus::Entries => (
                &mut self.selected,
                self.entries.as_ref().map_or(0, Vec::len),
            ),
            Focus::Requests => (&mut self.request_selected, self.requests.len()),
        };
        if len == 0 {
            return;
        }
        *selected = if down {
            (*selected + 1).min(len - 1)
        } else {
            selected.saturating_sub(1)
        };
    }

    /// The selected policy entry.
    pub fn selected_entry(&self) -> Option<&EntrySummary> {
        self.entries.as_ref()?.get(self.selected)
    }

    fn ask_rotate(&mut self) {
        let Some(entry) = self.selected_entry() else {
            self.message = Status::Error("Select a policy entry to rotate".to_owned());
            return;
        };
        if !entry.kind.rotatable() {
            let fix = match entry.kind {
                EntryKind::Helper => "is a helper value; remove it with a policy change (e)",
                _ => "is an ssh key; replace it with a policy change (e)",
            };
            self.message = Status::Error(format!("{} {fix}", entry.name));
            return;
        }
        let minted = matches!(entry.kind, EntryKind::Github | EntryKind::Tailscale);
        self.modal = Some(Modal::Confirm(Confirm::Rotate {
            name: entry.name.clone(),
            minted,
        }));
    }

    fn copy_url(&mut self) {
        let Some(url) = self
            .requests
            .get(self.request_selected)
            .and_then(|request| request.url.clone())
        else {
            self.message = Status::Error("The selected request has no approval page".to_owned());
            return;
        };
        let Some(clipboard) = self.clipboard.as_mut() else {
            self.message = Status::Error("No clipboard is available here".to_owned());
            return;
        };
        self.message = match clipboard.set_text(url) {
            Ok(()) => Status::Info("Copied the approval page address".to_owned()),
            Err(_) => Status::Error("Could not write the clipboard".to_owned()),
        };
    }

    fn handle_modal_key(&mut self, modal: Modal, key: KeyEvent) -> Option<Modal> {
        match modal {
            Modal::Help | Modal::Details(_) => None,
            Modal::Confirm(confirm) => match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    self.confirm(confirm);
                    None
                }
                KeyCode::Char('n') | KeyCode::Esc => None,
                _ => Some(Modal::Confirm(confirm)),
            },
            Modal::Add(form) => self.handle_add_key(form, key),
        }
    }

    fn confirm(&mut self, confirm: Confirm) {
        match confirm {
            Confirm::Rotate { name, .. } => {
                let target = name.clone();
                self.send(
                    format!("rotate {name}"),
                    RequestKind::Rotate,
                    move |client| Box::pin(async move { client.rotate(&target).await }),
                );
            }
            Confirm::Passkey => {
                self.send(
                    "passkey enrollment".to_owned(),
                    RequestKind::Passkey,
                    |client| Box::pin(async move { client.add_passkey(false).await }),
                );
            }
        }
    }

    fn handle_add_key(&mut self, mut form: AddForm, key: KeyEvent) -> Option<Modal> {
        let save = (key.code == KeyCode::Char('s') && key.modifiers == KeyModifiers::CONTROL)
            || (key.code == KeyCode::Enter && form.focus == AddField::Allow);
        if save {
            let request = form.request();
            let action = format!("add {}", request.name);
            self.send(action, RequestKind::Add, move |client| {
                Box::pin(async move { client.add_secret(&request).await })
            });
            return None;
        }
        match key.code {
            KeyCode::Esc => return None,
            KeyCode::Tab | KeyCode::Down | KeyCode::Enter => form.step(true),
            KeyCode::BackTab | KeyCode::Up => form.step(false),
            KeyCode::Backspace => {
                form.text_mut().pop();
            }
            KeyCode::Char(c) if is_typing(key) => {
                form.text_mut().push(c);
            }
            _ => {}
        }
        Some(Modal::Add(form))
    }

    /// Opens the proposal in the editor, then sends it. The proposal starts from the
    /// active policy when it does not exist.
    async fn edit_policy(&mut self, terminal: &mut DefaultTerminal) -> color_eyre::Result<()> {
        let path = match proposal::path() {
            Ok(path) => path,
            Err(err) => {
                self.message = Status::Error(err.to_string());
                return Ok(());
            }
        };
        if !path.exists() {
            let started = match self.client.policy().await {
                Ok(active) => proposal::write(&path, &active.toml),
                Err(err) => Err(err),
            };
            if let Err(err) = started {
                self.message = Status::Error(err.to_string());
                return Ok(());
            }
        }
        self.events.pause().await;
        crossterm::terminal::disable_raw_mode()?;
        crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen)?;
        let edited = tokio::task::block_in_place(|| proposal::editor(&path).status());
        crossterm::terminal::enable_raw_mode()?;
        crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
        // The editor left its text on the screen. Resizing to the same area clears the
        // screen and the back buffer, as Terminal::clear does, without asking the terminal
        // for the cursor position.
        let area = terminal.size()?.into();
        terminal.resize(area)?;
        self.events.resume();
        match edited {
            Ok(status) if status.success() => {}
            Ok(_) => {
                self.message = Status::Error("The editor failed; nothing was sent".to_owned());
                return Ok(());
            }
            Err(err) => {
                self.message = Status::Error(format!("Could not start the editor: {err}"));
                return Ok(());
            }
        }
        let toml = match proposal::read(&path) {
            Ok(toml) => toml,
            Err(err) => {
                self.message = Status::Error(err.to_string());
                return Ok(());
            }
        };
        self.send(
            "policy change".to_owned(),
            RequestKind::Policy,
            move |client| {
                Box::pin(async move { client.propose_policy(&PolicyProposal { toml }).await })
            },
        );
        Ok(())
    }

    /// The request shown in a details popup.
    pub fn request(&self, key: u64) -> Option<&Request> {
        self.requests.iter().find(|request| request.key == key)
    }
}

/// What an approved or finished request produced, from the broker's `result` object.
fn describe_result(result: Option<&serde_json::Value>) -> String {
    let Some(result) = result.and_then(serde_json::Value::as_object) else {
        return "done".to_owned();
    };
    let parts: Vec<String> = result
        .iter()
        .map(|(key, value)| match value.as_str() {
            Some(text) => format!("{key} {text}"),
            None => format!("{key} {value}"),
        })
        .collect();
    if parts.is_empty() {
        "done".to_owned()
    } else {
        parts.join(", ")
    }
}
