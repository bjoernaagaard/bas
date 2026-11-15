use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arboard::Clipboard;
use bas_core::credential::SecretText;
use bas_core::profile::Profile;
use bas_core::secrets::{Failure, Identifier, Project, Secret, Session, WriteRequest};
use bas_core::{Uuid, Zeroizing};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

use crate::event::{AppEvent, Event, EventHandler, WriteOutcome};
use crate::ui::Status;

/// How long a copied value stays on the clipboard before it is cleared.
pub const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

/// Application state.
pub struct App {
    pub running: bool,
    pub events: EventHandler,
    /// Web vault origin, such as `https://vault.bitwarden.com`.
    pub vault_base: String,
    pub organization: Uuid,
    /// The session, once login has finished.
    pub session: Option<Session>,
    /// Projects the machine account can read, sorted by name.
    pub projects: Vec<Project>,
    /// Open screens. The first is always [`Screen::Projects`]; the last is shown.
    pub screens: Vec<Screen>,
    pub modal: Option<Modal>,
    pub status: Status,
    /// `None` when the system offers no clipboard.
    pub clipboard: Option<Clipboard>,
    /// The value this app last copied, until it is cleared.
    pub copied: Option<Copied>,
    /// Source of request numbers, which tie each network result to the screen that asked.
    next_request: u64,
    /// Numbers each listing request as it starts, so a reply that started earlier than the
    /// data on screen cannot replace it.
    list_clock: Arc<AtomicU64>,
    /// Start number of the project listing on screen.
    projects_started: u64,
    /// Start number of the secrets listing on screen, per project or `None` for all.
    secrets_started: HashMap<Option<Uuid>, u64>,
}

/// One screen of the stack.
pub enum Screen {
    /// Row 0 is "all secrets"; row `i + 1` is `projects[i]`.
    Projects {
        selected: usize,
    },
    Secrets(SecretsScreen),
    Secret(SecretScreen),
    Form(SecretForm),
    WebVault,
}

/// Secrets of one project, or of every project the machine account can read.
pub struct SecretsScreen {
    pub project: Option<Uuid>,
    /// `None` until the first listing arrives.
    pub items: Option<Vec<Identifier>>,
    /// Index into [`SecretsScreen::visible`].
    pub selected: usize,
    pub filter: String,
    pub filtering: bool,
    /// Secrets marked for a bulk delete. A mark stays while the filter hides its row.
    pub marked: BTreeSet<Uuid>,
}

impl SecretsScreen {
    /// The marked secrets with their keys, in list order.
    fn marked_items(&self) -> Vec<(Uuid, String)> {
        self.items
            .iter()
            .flatten()
            .filter(|item| self.marked.contains(&item.id()))
            .map(|item| (item.id(), item.key().to_owned()))
            .collect()
    }

    /// Listings whose key contains the filter, ignoring case.
    pub fn visible(&self) -> Vec<&Identifier> {
        let needle = self.filter.to_lowercase();
        self.items
            .iter()
            .flatten()
            .filter(|item| item.key().to_lowercase().contains(&needle))
            .collect()
    }

    fn selected_item(&self) -> Option<&Identifier> {
        self.visible().get(self.selected).copied()
    }
}

/// One secret, value and note hidden until revealed.
pub struct SecretScreen {
    /// The read this screen waits for. Results of any other read are ignored.
    pub request: u64,
    /// `None` while the read is in flight.
    pub detail: Option<Secret>,
    pub revealed: bool,
    /// Open the edit form as soon as the read arrives.
    pub edit_on_load: bool,
}

impl fmt::Debug for SecretScreen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretScreen")
            .field("secret", &self.detail.as_ref().map(Secret::id))
            .field("revealed", &self.revealed)
            .finish_non_exhaustive()
    }
}

/// Fields of the secret form, in tab order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Key,
    Value,
    Note,
    Project,
}

impl Field {
    const ORDER: [Self; 4] = [Self::Key, Self::Value, Self::Note, Self::Project];

    fn step(self, forward: Direction) -> Self {
        let index = Self::ORDER
            .iter()
            .position(|field| *field == self)
            .unwrap_or(0);
        let next = match forward {
            Direction::Next => (index + 1) % Self::ORDER.len(),
            Direction::Previous => (index + Self::ORDER.len() - 1) % Self::ORDER.len(),
        };
        Self::ORDER[next]
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Next,
    Previous,
}

/// A move of the selected row in a list.
#[derive(Clone, Copy)]
enum Motion {
    Next,
    Previous,
    First,
    Last,
}

/// Create or edit form for one secret.
pub struct SecretForm {
    /// The secret being edited, or `None` for a new one.
    pub editing: Option<Uuid>,
    pub key: String,
    pub value: SecretText,
    pub note: SecretText,
    /// The project the secret will be in. Starts as the secret's own project, which may be
    /// missing from [`App::projects`] when access comes from a policy on the secret itself.
    pub project: Option<Uuid>,
    /// The secret's project when the form opened. While `project` still equals it, a save
    /// keeps every project the secret belongs to, not only the first.
    pub original_project: Option<Uuid>,
    pub focus: Field,
    /// Keys type into the focused field. Otherwise keys move, reveal, and save.
    pub typing: bool,
    pub revealed: bool,
    /// The save in flight, if any. Its result applies only to this form.
    pub saving: Option<u64>,
}

impl fmt::Debug for SecretForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretForm")
            .field("editing", &self.editing)
            .field("key", &self.key)
            .field("project", &self.project)
            .field("focus", &self.focus)
            .finish_non_exhaustive()
    }
}

/// A dialog drawn over the current screen.
pub enum Modal {
    Help,
    /// Name input for a new project, or for renaming the project with this ID.
    ProjectName {
        renaming: Option<Uuid>,
        input: String,
    },
    Delete {
        target: DeleteTarget,
        typed: String,
    },
}

/// What a delete confirmation would remove.
#[derive(Clone)]
pub enum DeleteTarget {
    /// `listing` is the project filter of the secrets list to refresh afterwards.
    Secret {
        id: Uuid,
        key: String,
        listing: Option<Uuid>,
    },
    /// The marked secrets of one list, each with its key. `count` is how many there are,
    /// as the text to type.
    Secrets {
        secrets: Vec<(Uuid, String)>,
        count: String,
        listing: Option<Uuid>,
    },
    Project {
        id: Uuid,
        name: String,
    },
}

impl DeleteTarget {
    /// The text the owner must type to enable the delete.
    pub fn name(&self) -> &str {
        match self {
            Self::Secret { key, .. } => key,
            Self::Secrets { count, .. } => count,
            Self::Project { name, .. } => name,
        }
    }
}

/// A value this app put on the clipboard.
pub struct Copied {
    pub text: Zeroizing<String>,
    pub deadline: Instant,
}

impl Drop for App {
    /// Best effort: also clears the clipboard when a panic unwinds through the app.
    fn drop(&mut self) {
        self.clear_clipboard();
    }
}

impl fmt::Debug for Copied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Copied")
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl App {
    /// Builds the app for `profile`. `events` delivers the sign-in result as
    /// [`AppEvent::Connected`].
    pub fn new(profile: &Profile, events: EventHandler) -> Self {
        Self {
            running: true,
            events,
            vault_base: profile.endpoints.web_vault().to_owned(),
            organization: profile.organization,
            session: None,
            projects: Vec::new(),
            screens: vec![Screen::Projects { selected: 0 }],
            modal: None,
            status: Status::Info("Connecting to Secrets Manager".to_owned()),
            clipboard: Clipboard::new().ok(),
            copied: None,
            next_request: 0,
            list_clock: Arc::new(AtomicU64::new(1)),
            projects_started: 0,
            secrets_started: HashMap::new(),
        }
    }

    /// Runs the main loop. Dropping the app afterwards clears the clipboard if it still holds a
    /// copied value.
    ///
    /// # Errors
    ///
    /// Fails when drawing fails, the event task dies, or login fails.
    pub async fn run(mut self, terminal: &mut DefaultTerminal) -> color_eyre::Result<()> {
        self.event_loop(terminal).await
    }

    async fn event_loop(&mut self, terminal: &mut DefaultTerminal) -> color_eyre::Result<()> {
        while self.running {
            terminal.draw(|frame| frame.render_widget(&*self, frame.area()))?;
            match self.events.next().await? {
                Event::Tick => self.tick(),
                Event::Crossterm(crossterm::event::Event::Key(key))
                    if key.kind == KeyEventKind::Press =>
                {
                    self.handle_key_event(key);
                }
                Event::Crossterm(_) => {}
                Event::App(app_event) => self.handle_app_event(app_event)?,
            }
        }
        Ok(())
    }

    fn handle_app_event(&mut self, event: AppEvent) -> color_eyre::Result<()> {
        match event {
            AppEvent::Connected(result) => self.on_connected(*result)?,
            AppEvent::Projects {
                listed,
                select,
                done,
            } => self.on_projects(listed, select, done),
            AppEvent::Secrets {
                project,
                listed,
                done,
            } => self.on_secrets(project, listed, done),
            AppEvent::Secret { request, result } => self.on_secret(request, result),
            AppEvent::SecretSaved { form, result } => self.on_secret_saved(form, result),
            AppEvent::WriteFailed {
                action,
                error,
                outcome,
                form,
            } => self.on_write_failed(&action, &error, outcome, form),
            AppEvent::Quit => self.running = false,
            AppEvent::SignedIn(_) => {}
            #[cfg(unix)]
            AppEvent::Broker(_) => {}
        }
        Ok(())
    }

    /// Whether the top screen is the form that started save `request`.
    fn is_saving_form(&self, request: Option<u64>) -> bool {
        matches!(self.screens.last(), Some(Screen::Form(form)) if request.is_some() && form.saving == request)
    }

    fn request(&mut self) -> u64 {
        self.next_request += 1;
        self.next_request
    }

    fn on_write_failed(
        &mut self,
        action: &str,
        error: &color_eyre::Report,
        outcome: WriteOutcome,
        form: Option<u64>,
    ) {
        let from_top_form = self.is_saving_form(form);
        match outcome {
            WriteOutcome::Refused => {
                if from_top_form && let Some(Screen::Form(form)) = self.screens.last_mut() {
                    form.saving = None;
                }
                self.status = Status::Error(format!("Could not {action}: {error}"));
            }
            WriteOutcome::Unknown => {
                // The server may have applied the write, so a retry could repeat it. Show
                // what the server holds now instead of offering the same form again.
                if from_top_form {
                    self.screens.pop();
                }
                self.status = Status::Error(format!(
                    "Unknown whether the server did {action}: {error}. Lists were re-read from \
                     the server; check them before trying again"
                ));
                self.reload_all();
            }
        }
    }

    /// Re-reads the projects and every open secrets list from the server.
    fn reload_all(&self) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let listings: Vec<Option<Uuid>> = self
            .screens
            .iter()
            .filter_map(|screen| match screen {
                Screen::Secrets(list) => Some(list.project),
                _ => None,
            })
            .collect();
        self.load_projects(session);
        for project in listings {
            self.load_secrets(session, project, None);
        }
    }

    fn on_connected(&mut self, result: color_eyre::Result<Session>) -> color_eyre::Result<()> {
        let session = result.map_err(|err| err.wrap_err("could not connect to Secrets Manager"))?;
        self.status = Status::Info("Connected. Loading projects".to_owned());
        self.load_projects(&session);
        self.session = Some(session);
        Ok(())
    }

    fn on_projects(&mut self, listed: Listed<Project>, select: Option<Uuid>, done: Option<String>) {
        if listed.started < self.projects_started {
            if let Some(done) = done {
                self.status = Status::Info(done);
            }
            return;
        }
        let projects = match listed.result {
            Ok(projects) => projects,
            Err(err) => {
                self.status = Status::Error(match done {
                    Some(done) => format!("{done}, but re-reading the projects failed: {err}"),
                    None => format!("Could not list projects: {err}"),
                });
                return;
            }
        };
        self.projects_started = listed.started;
        if done.is_some() || !matches!(self.status, Status::Error(_)) {
            self.status = Status::Info(done.unwrap_or_else(|| match projects.len() {
                1 => "1 project".to_owned(),
                count => format!("{count} projects"),
            }));
        }
        let row_count = projects.len() + 1;
        let selected_row = select
            .and_then(|id| projects.iter().position(|project| project.id() == id))
            .map(|index| index + 1);
        self.projects = projects;
        if let Some(Screen::Projects { selected }) = self.screens.first_mut() {
            *selected = selected_row.unwrap_or(*selected).min(row_count - 1);
        }
    }

    fn on_secrets(
        &mut self,
        project: Option<Uuid>,
        listed: Listed<Identifier>,
        done: Option<Status>,
    ) {
        if listed.started
            < self
                .secrets_started
                .get(&project)
                .copied()
                .unwrap_or_default()
        {
            if let Some(done) = done {
                self.status = done;
            }
            return;
        }
        let items = match listed.result {
            Ok(items) => items,
            Err(err) => {
                self.status = Status::Error(match done {
                    Some(Status::Info(done) | Status::Error(done)) => {
                        format!("{done}, but re-reading the secrets failed: {err}")
                    }
                    None => format!("Could not list secrets: {err}"),
                });
                return;
            }
        };
        self.secrets_started.insert(project, listed.started);
        if done.is_some() || !matches!(self.status, Status::Error(_)) {
            self.status = done.unwrap_or_else(|| Status::Info(secret_count(items.len())));
        }
        for screen in &mut self.screens {
            if let Screen::Secrets(list) = screen
                && list.project == project
            {
                list.marked
                    .retain(|id| items.iter().any(|item| item.id() == *id));
                list.items = Some(items.clone());
                let visible = list.visible().len();
                list.selected = list.selected.min(visible.saturating_sub(1));
            }
        }
    }

    fn on_secret(&mut self, request: u64, result: color_eyre::Result<Secret>) {
        let Some(index) = self.screens.iter().rposition(
            |screen| matches!(screen, Screen::Secret(screen) if screen.request == request),
        ) else {
            return;
        };
        let on_top = index + 1 == self.screens.len();
        match result {
            Ok(detail) => {
                let Screen::Secret(screen) = &mut self.screens[index] else {
                    return;
                };
                let edit = on_top && screen.edit_on_load;
                screen.edit_on_load = false;
                self.status = Status::Info(format!("Read {}", detail.key()));
                let form = edit.then(|| edit_form(&detail));
                screen.detail = Some(detail);
                if let Some(form) = form {
                    self.screens.push(Screen::Form(form));
                }
            }
            Err(err) => {
                self.screens.remove(index);
                self.status = Status::Error(format!("Could not read the secret: {err}"));
            }
        }
    }

    fn on_secret_saved(&mut self, form: u64, result: color_eyre::Result<Secret>) {
        if !self.is_saving_form(Some(form)) {
            return;
        }
        self.screens.pop();
        let detail = match result {
            Ok(detail) => detail,
            Err(err) => {
                self.status =
                    Status::Error(format!("Saved, but could not read the secret back: {err}"));
                return;
            }
        };
        let saved = format!("Saved {}. Showing what the server returned", detail.key());
        self.status = Status::Info(saved.clone());
        let request = self.request();
        match self.screens.last_mut() {
            Some(Screen::Secret(screen)) => {
                screen.request = request;
                screen.detail = Some(detail);
                screen.revealed = false;
            }
            _ => self.screens.push(Screen::Secret(SecretScreen {
                request,
                detail: Some(detail),
                revealed: false,
                edit_on_load: false,
            })),
        }
        if let Some(session) = self.session.clone() {
            for screen in &self.screens {
                if let Screen::Secrets(list) = screen {
                    self.load_secrets(&session, list.project, Some(saved.clone()));
                }
            }
        }
    }

    /// Handles a key press. Ctrl-C always quits.
    pub fn handle_key_event(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            self.events.send(AppEvent::Quit);
            return;
        }
        if let Some(modal) = self.modal.take() {
            self.modal = self.handle_modal_key(modal, key);
            return;
        }
        match self.screens.last() {
            Some(Screen::Form(_)) => self.handle_form_key(key),
            Some(Screen::Secrets(list)) if list.filtering => self.handle_filter_key(key),
            _ => self.handle_screen_key(key),
        }
    }

    fn handle_screen_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc if self.clear_marks() => {}
            KeyCode::Char('q') | KeyCode::Esc => self.back(),
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Char('w') => {
                if !matches!(self.screens.last(), Some(Screen::WebVault)) {
                    self.screens.push(Screen::WebVault);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(Motion::Previous),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(Motion::Next),
            KeyCode::Char('g') => self.move_selection(Motion::First),
            KeyCode::Char('G') => self.move_selection(Motion::Last),
            _ => match self.screens.last() {
                Some(Screen::Projects { .. }) => self.handle_projects_key(key),
                Some(Screen::Secrets(_)) => self.handle_secrets_key(key),
                Some(Screen::Secret(_)) => self.handle_secret_key(key),
                _ => {}
            },
        }
    }

    fn back(&mut self) {
        if self.screens.len() > 1 {
            self.screens.pop();
        } else {
            self.events.send(AppEvent::Quit);
        }
    }

    /// Removes every mark from the secrets list on top. False when it had none.
    fn clear_marks(&mut self) -> bool {
        let Some(Screen::Secrets(list)) = self.screens.last_mut() else {
            return false;
        };
        let had_marks = !list.marked.is_empty();
        list.marked.clear();
        had_marks
    }

    fn move_selection(&mut self, motion: Motion) {
        let project_rows = self.projects.len() + 1;
        let (selected, rows) = match self.screens.last_mut() {
            Some(Screen::Projects { selected }) => (selected, project_rows),
            Some(Screen::Secrets(list)) => {
                let rows = list.visible().len();
                (&mut list.selected, rows)
            }
            _ => return,
        };
        let last = rows.saturating_sub(1);
        *selected = match motion {
            Motion::Next => (*selected + 1).min(last),
            Motion::Previous => selected.saturating_sub(1),
            Motion::First => 0,
            Motion::Last => last,
        };
    }

    fn selected_project(&self) -> Option<&Project> {
        match self.screens.first() {
            Some(Screen::Projects { selected }) => {
                selected.checked_sub(1).and_then(|i| self.projects.get(i))
            }
            _ => None,
        }
    }

    /// The project filter of the innermost open secrets list, if a list is open.
    fn open_listing(&self) -> Option<Option<Uuid>> {
        self.screens.iter().rev().find_map(|screen| match screen {
            Screen::Secrets(list) => Some(list.project),
            _ => None,
        })
    }

    /// The project in view: the open secrets list's project, else the highlighted project.
    pub fn context_project(&self) -> Option<&Project> {
        match self.open_listing() {
            Some(Some(id)) => self.projects.iter().find(|project| project.id() == id),
            Some(None) => None,
            None => self.selected_project(),
        }
    }

    fn connected(&mut self) -> Option<Session> {
        if self.session.is_none() {
            self.status = Status::Info("Still connecting to Secrets Manager".to_owned());
        }
        self.session.clone()
    }

    fn handle_projects_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                let Some(session) = self.connected() else {
                    return;
                };
                let project = self.selected_project().map(Project::id);
                self.screens.push(Screen::Secrets(SecretsScreen {
                    project,
                    items: None,
                    selected: 0,
                    filter: String::new(),
                    filtering: false,
                    marked: BTreeSet::new(),
                }));
                self.load_secrets(&session, project, None);
            }
            KeyCode::Char('n') => {
                self.modal = Some(Modal::ProjectName {
                    renaming: None,
                    input: String::new(),
                });
            }
            KeyCode::Char('e') => {
                if let Some(project) = self.selected_project() {
                    self.modal = Some(Modal::ProjectName {
                        renaming: Some(project.id()),
                        input: project.name().to_owned(),
                    });
                }
            }
            KeyCode::Char('d') => {
                if let Some(project) = self.selected_project() {
                    self.modal = Some(Modal::Delete {
                        target: DeleteTarget::Project {
                            id: project.id(),
                            name: project.name().to_owned(),
                        },
                        typed: String::new(),
                    });
                }
            }
            _ => {}
        }
    }

    fn handle_secrets_key(&mut self, key: KeyEvent) {
        let Some(Screen::Secrets(list)) = self.screens.last_mut() else {
            return;
        };
        let listing = list.project;
        let selected = list
            .selected_item()
            .map(|item| (item.id(), item.key().to_owned()));
        match key.code {
            KeyCode::Char('/') => list.filtering = true,
            KeyCode::Enter => {
                if let Some((id, _)) = selected {
                    self.open_secret(id, false);
                }
            }
            KeyCode::Char('e') => {
                if let Some((id, _)) = selected {
                    self.open_secret(id, true);
                }
            }
            KeyCode::Char('n') => self.open_new_form(),
            KeyCode::Char(' ') => {
                if let Some((id, _)) = selected {
                    if !list.marked.remove(&id) {
                        list.marked.insert(id);
                    }
                    self.move_selection(Motion::Next);
                }
            }
            KeyCode::Char('d') => {
                let secrets = list.marked_items();
                let target = if secrets.is_empty() {
                    selected.map(|(id, key)| DeleteTarget::Secret { id, key, listing })
                } else {
                    Some(DeleteTarget::Secrets {
                        count: secrets.len().to_string(),
                        secrets,
                        listing,
                    })
                };
                if let Some(target) = target {
                    self.modal = Some(Modal::Delete {
                        target,
                        typed: String::new(),
                    });
                }
            }
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        let Some(Screen::Secrets(list)) = self.screens.last_mut() else {
            return;
        };
        match key.code {
            KeyCode::Enter => list.filtering = false,
            KeyCode::Esc => {
                list.filtering = false;
                list.filter.clear();
            }
            KeyCode::Backspace => {
                list.filter.pop();
            }
            KeyCode::Char(ch) if is_typing(key) => list.filter.push(ch),
            _ => {}
        }
        list.selected = 0;
    }

    fn handle_secret_key(&mut self, key: KeyEvent) {
        let listing = self.open_listing().flatten();
        let Some(Screen::Secret(screen)) = self.screens.last_mut() else {
            return;
        };
        let Some(detail) = &screen.detail else {
            return;
        };
        match key.code {
            KeyCode::Char('r') => screen.revealed = !screen.revealed,
            KeyCode::Char('c') => {
                let key_name = detail.key().to_owned();
                let text = Zeroizing::new(detail.value().expose().to_owned());
                self.copy(&key_name, text);
            }
            KeyCode::Char('e') => {
                let form = edit_form(detail);
                self.screens.push(Screen::Form(form));
            }
            KeyCode::Char('d') => {
                let target = DeleteTarget::Secret {
                    id: detail.id(),
                    key: detail.key().to_owned(),
                    listing,
                };
                self.modal = Some(Modal::Delete {
                    target,
                    typed: String::new(),
                });
            }
            _ => {}
        }
    }

    fn open_secret(&mut self, id: Uuid, edit_on_load: bool) {
        let Some(session) = self.connected() else {
            return;
        };
        let request = self.request();
        self.screens.push(Screen::Secret(SecretScreen {
            request,
            detail: None,
            revealed: false,
            edit_on_load,
        }));
        self.status = Status::Info("Reading the secret".to_owned());
        self.events.spawn(async move {
            AppEvent::Secret {
                request,
                result: read_secret(&session, id).await,
            }
        });
    }

    fn open_new_form(&mut self) {
        if self.projects.is_empty() {
            self.status = Status::Error(
                "A machine account must put each secret in a project. Create a project first"
                    .to_owned(),
            );
            return;
        }
        let project = self
            .context_project()
            .or_else(|| self.projects.first())
            .map(Project::id);
        self.screens.push(Screen::Form(SecretForm {
            editing: None,
            key: String::new(),
            value: SecretText::default(),
            note: SecretText::default(),
            project,
            original_project: None,
            focus: Field::Key,
            typing: true,
            revealed: false,
            saving: None,
        }));
    }

    fn handle_form_key(&mut self, key: KeyEvent) {
        let project_count = self.projects.len();
        let Some(Screen::Form(form)) = self.screens.last_mut() else {
            return;
        };
        if form.saving.is_some() {
            return;
        }
        let ctrl = key.modifiers == KeyModifiers::CONTROL;
        if form.typing {
            match key.code {
                KeyCode::Char('s') if ctrl => self.save_form(),
                KeyCode::Esc | KeyCode::Enter => form.typing = false,
                KeyCode::Tab => {
                    form.typing = false;
                    form.focus = form.focus.step(Direction::Next);
                }
                KeyCode::Backspace => match form.focus {
                    Field::Key => {
                        form.key.pop();
                    }
                    Field::Value => form.value.pop(),
                    Field::Note => form.note.pop(),
                    Field::Project => {}
                },
                KeyCode::Char(ch) if is_typing(key) => match form.focus {
                    Field::Key => form.key.push(ch),
                    Field::Value => form.value.push(ch),
                    Field::Note => form.note.push(ch),
                    Field::Project => {}
                },
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Esc => {
                self.screens.pop();
            }
            KeyCode::Char('r') => form.revealed = !form.revealed,
            KeyCode::Char('s') if ctrl => self.save_form(),
            KeyCode::Enter if form.focus == Field::Project => self.save_form(),
            KeyCode::Enter => form.typing = true,
            KeyCode::Tab | KeyCode::Down | KeyCode::Char('j') => {
                form.focus = form.focus.step(Direction::Next);
            }
            KeyCode::BackTab | KeyCode::Up | KeyCode::Char('k') => {
                form.focus = form.focus.step(Direction::Previous);
            }
            KeyCode::Left | KeyCode::Char('h')
                if form.focus == Field::Project && project_count > 0 =>
            {
                form.project = step_project(&self.projects, form.project, Direction::Previous);
            }
            KeyCode::Right | KeyCode::Char('l')
                if form.focus == Field::Project && project_count > 0 =>
            {
                form.project = step_project(&self.projects, form.project, Direction::Next);
            }
            _ => {}
        }
    }

    fn save_form(&mut self) {
        let Some(session) = self.connected() else {
            return;
        };
        let request = self.request();
        let Some(Screen::Form(form)) = self.screens.last_mut() else {
            return;
        };
        let Some(project) = form.project else {
            self.status = Status::Error(
                "Pick a project with Left or Right. A machine account must put each secret in one"
                    .to_owned(),
            );
            return;
        };
        let key = form.key.trim().to_owned();
        // The form keeps its text so a refused save can be corrected and retried.
        let value = SecretText::new(form.value.expose().to_owned());
        let note = SecretText::new(form.note.expose().to_owned());
        let keep_projects = form.original_project == Some(project);
        form.saving = Some(request);
        self.status = Status::Info(format!("Saving {key}"));
        let editing = form.editing;
        self.events.spawn(async move {
            let action = format!("save {key}");
            let project_ids = match editing {
                Some(id) if keep_projects => match current_project_ids(&session, id).await {
                    Ok(ids) => ids,
                    Err(error) => {
                        return AppEvent::WriteFailed {
                            action,
                            error,
                            outcome: WriteOutcome::Refused,
                            form: Some(request),
                        };
                    }
                },
                _ => vec![project],
            };
            let write = WriteRequest {
                key: &key,
                value: &value,
                note: &note,
                project_ids: &project_ids,
            };
            let written = match editing {
                Some(id) => session.update(id, &write).await,
                None => session.create(&write).await,
            };
            match written {
                Ok(stored) => AppEvent::SecretSaved {
                    form: request,
                    result: read_secret(&session, stored.id()).await,
                },
                Err(failure) => write_failed(action, failure, Some(request)),
            }
        });
    }

    fn handle_modal_key(&mut self, modal: Modal, key: KeyEvent) -> Option<Modal> {
        match modal {
            Modal::Help => None,
            Modal::ProjectName {
                renaming,
                mut input,
            } => match key.code {
                KeyCode::Esc => None,
                KeyCode::Enter => {
                    let name = input.trim().to_owned();
                    if name.is_empty() {
                        return Some(Modal::ProjectName { renaming, input });
                    }
                    self.write_project(renaming, name);
                    None
                }
                KeyCode::Backspace => {
                    input.pop();
                    Some(Modal::ProjectName { renaming, input })
                }
                KeyCode::Char(ch) if is_typing(key) => {
                    input.push(ch);
                    Some(Modal::ProjectName { renaming, input })
                }
                _ => Some(Modal::ProjectName { renaming, input }),
            },
            Modal::Delete { target, mut typed } => match key.code {
                KeyCode::Esc => None,
                KeyCode::Enter if typed == target.name() => {
                    self.delete(target);
                    None
                }
                KeyCode::Backspace => {
                    typed.pop();
                    Some(Modal::Delete { target, typed })
                }
                KeyCode::Char(ch) if is_typing(key) => {
                    typed.push(ch);
                    Some(Modal::Delete { target, typed })
                }
                _ => Some(Modal::Delete { target, typed }),
            },
        }
    }

    fn write_project(&mut self, renaming: Option<Uuid>, name: String) {
        let Some(session) = self.connected() else {
            return;
        };
        self.status = Status::Info(format!("Saving project {name}"));
        let clock = Arc::clone(&self.list_clock);
        self.events.spawn(async move {
            let (action, written) = match renaming {
                Some(id) => (
                    format!("rename the project to {name}"),
                    session.rename_project(id, &name).await,
                ),
                None => (
                    format!("create project {name}"),
                    session.create_project(&name).await,
                ),
            };
            match written {
                Ok(stored) => AppEvent::Projects {
                    listed: list_projects(&session, &clock).await,
                    select: Some(stored.id()),
                    done: Some(format!(
                        "Server saved project {}. List re-read from the server",
                        stored.name()
                    )),
                },
                Err(failure) => write_failed(action, failure, None),
            }
        });
    }

    fn delete(&mut self, target: DeleteTarget) {
        let Some(session) = self.connected() else {
            return;
        };
        match target {
            DeleteTarget::Secret { id, key, listing } => {
                if matches!(self.screens.last(), Some(Screen::Secret(_))) {
                    self.screens.pop();
                }
                self.status = Status::Info(format!("Deleting {key}"));
                let trash = self.trash_url();
                let clock = Arc::clone(&self.list_clock);
                self.events.spawn(async move {
                    match session.delete(id).await {
                        Ok(()) => AppEvent::Secrets {
                            project: listing,
                            listed: list_secrets(&session, &clock, listing).await,
                            done: Some(Status::Info(format!(
                                "Moved {key} to trash. Restore it at {trash}"
                            ))),
                        },
                        Err(failure) => write_failed(format!("delete {key}"), failure, None),
                    }
                });
            }
            DeleteTarget::Secrets {
                secrets, listing, ..
            } => {
                let total = secret_count(secrets.len());
                self.status = Status::Info(format!("Deleting {total}"));
                let trash = self.trash_url();
                let clock = Arc::clone(&self.list_clock);
                self.events.spawn(async move {
                    let ids: Vec<Uuid> = secrets.iter().map(|(id, _)| *id).collect();
                    match session.delete_many(&ids).await {
                        Ok(deleted) => AppEvent::Secrets {
                            project: listing,
                            listed: list_secrets(&session, &clock, listing).await,
                            done: Some(bulk_delete_status(&secrets, &deleted, &trash)),
                        },
                        Err(failure) => write_failed(format!("delete {total}"), failure, None),
                    }
                });
            }
            DeleteTarget::Project { id, name } => {
                self.status = Status::Info(format!("Deleting project {name}"));
                let clock = Arc::clone(&self.list_clock);
                self.events.spawn(async move {
                    match session.delete_project(id).await {
                        Ok(()) => AppEvent::Projects {
                            listed: list_projects(&session, &clock).await,
                            select: None,
                            done: Some(format!("Deleted project {name}")),
                        },
                        Err(failure) => {
                            write_failed(format!("delete project {name}"), failure, None)
                        }
                    }
                });
            }
        }
    }

    fn load_projects(&self, session: &Session) {
        let session = session.clone();
        let clock = Arc::clone(&self.list_clock);
        self.events.spawn(async move {
            AppEvent::Projects {
                listed: list_projects(&session, &clock).await,
                select: None,
                done: None,
            }
        });
    }

    /// Re-reads one secrets list. `done` replaces the count on the status line.
    fn load_secrets(&self, session: &Session, project: Option<Uuid>, done: Option<String>) {
        let session = session.clone();
        let clock = Arc::clone(&self.list_clock);
        self.events.spawn(async move {
            AppEvent::Secrets {
                project,
                listed: list_secrets(&session, &clock, project).await,
                done: done.map(Status::Info),
            }
        });
    }

    /// The trash page, where deleted secrets can be restored.
    pub fn trash_url(&self) -> String {
        format!("{}/#/sm/{}/trash", self.vault_base, self.organization)
    }

    fn copy(&mut self, key_name: &str, text: Zeroizing<String>) {
        let Some(clipboard) = self.clipboard.as_mut() else {
            self.status = Status::Error("No clipboard is available here".to_owned());
            return;
        };
        match clipboard.set_text(text.as_str()) {
            Ok(()) => {
                self.copied = Some(Copied {
                    text,
                    deadline: Instant::now() + CLIPBOARD_CLEAR_AFTER,
                });
                self.status = Status::Info(format!("Copied the value of {key_name}"));
            }
            Err(_) => self.status = Status::Error("Could not write the clipboard".to_owned()),
        }
    }

    /// Clears the clipboard once the copied value's time is up.
    pub fn tick(&mut self) {
        if self
            .copied
            .as_ref()
            .is_some_and(|copied| Instant::now() >= copied.deadline)
        {
            self.clear_clipboard();
        }
    }

    /// Clears the clipboard only if it still holds the value this app copied.
    ///
    /// When the clipboard cannot be read or cleared, the copied value stays tracked so the
    /// next tick tries again.
    fn clear_clipboard(&mut self) {
        let (Some(copied), Some(clipboard)) = (self.copied.take(), self.clipboard.as_mut()) else {
            return;
        };
        let ours = match clipboard.get_text().map(Zeroizing::new) {
            Ok(text) => text.as_str() == copied.text.as_str(),
            Err(arboard::Error::ContentNotAvailable) => false,
            Err(_) => {
                self.copied = Some(copied);
                self.status = Status::Error("Could not read the clipboard to clear it".to_owned());
                return;
            }
        };
        self.status = if !ours {
            Status::Info("The clipboard changed since the copy, so it was left alone".to_owned())
        } else if clipboard.clear().is_ok() {
            Status::Info("Cleared the copied value from the clipboard".to_owned())
        } else {
            self.copied = Some(copied);
            Status::Error("Could not clear the clipboard".to_owned())
        };
    }
}

/// A listing and the number its request took from the list clock as it started.
#[derive(Debug)]
pub struct Listed<T> {
    /// The clock value taken when the request started.
    pub started: u64,
    /// The sorted listing, or why it failed.
    pub result: color_eyre::Result<Vec<T>>,
}

/// Projects the machine account can read, sorted by name.
async fn list_projects(session: &Session, clock: &AtomicU64) -> Listed<Project> {
    let started = clock.fetch_add(1, Ordering::Relaxed);
    let result = session.list_projects().await.map(|mut projects| {
        projects.sort_by(|a, b| a.name().cmp(b.name()));
        projects
    });
    Listed {
        started,
        result: result.map_err(color_eyre::Report::new),
    }
}

/// Secrets the machine account can read, in one project or all of them, sorted by key.
async fn list_secrets(
    session: &Session,
    clock: &AtomicU64,
    project: Option<Uuid>,
) -> Listed<Identifier> {
    let started = clock.fetch_add(1, Ordering::Relaxed);
    let result = session.list_identifiers(project).await.map(|mut secrets| {
        secrets.sort_by(|a, b| a.key().cmp(b.key()));
        secrets
    });
    Listed {
        started,
        result: result.map_err(color_eyre::Report::new),
    }
}

/// Every project a secret belongs to. A secret read returns only the first one, while the
/// identifier listing keeps them all.
async fn current_project_ids(session: &Session, id: Uuid) -> color_eyre::Result<Vec<Uuid>> {
    session
        .list_identifiers(None)
        .await?
        .into_iter()
        .find(|identifier| identifier.id() == id)
        .map(|identifier| identifier.project_ids().to_vec())
        .ok_or_else(|| color_eyre::eyre::eyre!("could not confirm the secret's current projects"))
}

/// The status line after a bulk delete of `secrets`, of which the server deleted `deleted`.
/// Secrets the server kept are named, and they stay marked in the list.
fn bulk_delete_status(secrets: &[(Uuid, String)], deleted: &BTreeSet<Uuid>, trash: &str) -> Status {
    let kept: Vec<&str> = secrets
        .iter()
        .filter(|(id, _)| !deleted.contains(id))
        .map(|(_, key)| key.as_str())
        .collect();
    let total = secret_count(secrets.len());
    if kept.is_empty() {
        Status::Info(format!("Moved {total} to trash. Restore at {trash}"))
    } else {
        Status::Error(format!(
            "Moved {} of {total} to trash. Secrets Manager did not delete {}",
            secrets.len() - kept.len(),
            kept.join(", ")
        ))
    }
}

/// A count of secrets as words, such as "1 secret" or "3 secrets".
pub(crate) fn secret_count(count: usize) -> String {
    match count {
        1 => "1 secret".to_owned(),
        count => format!("{count} secrets"),
    }
}

/// The event for a failed write. Only a refusal is known to have changed nothing. `form` is
/// the save request of the secret form that started the write.
fn write_failed(action: String, failure: Failure, form: Option<u64>) -> AppEvent {
    let outcome = if failure.is_rejection() {
        WriteOutcome::Refused
    } else {
        WriteOutcome::Unknown
    };
    AppEvent::WriteFailed {
        action,
        error: failure.into(),
        outcome,
        form,
    }
}

async fn read_secret(session: &Session, id: Uuid) -> color_eyre::Result<Secret> {
    Ok(session.get(id).await?)
}

/// A form prefilled from a secret the server returned.
fn edit_form(detail: &Secret) -> SecretForm {
    let project = detail.project_id();
    SecretForm {
        original_project: project,
        editing: Some(detail.id()),
        key: detail.key().to_owned(),
        value: SecretText::new(detail.value().expose().to_owned()),
        note: SecretText::new(detail.note().expose().to_owned()),
        project,
        focus: Field::Key,
        typing: false,
        revealed: false,
        saving: None,
    }
}

/// The project before or after `current` in `projects`, wrapping around. A project missing
/// from the list steps to the first or last one.
fn step_project(projects: &[Project], current: Option<Uuid>, direction: Direction) -> Option<Uuid> {
    let count = projects.len();
    let index = current.and_then(|id| projects.iter().position(|p| p.id() == id));
    let next = match (index, direction) {
        (_, _) if count == 0 => return current,
        (Some(i), Direction::Next) => (i + 1) % count,
        (Some(i), Direction::Previous) => (i + count - 1) % count,
        (None, Direction::Next) => 0,
        (None, Direction::Previous) => count - 1,
    };
    projects.get(next).map(Project::id)
}

/// A key that types its character: no modifier other than Shift.
pub(crate) fn is_typing(key: KeyEvent) -> bool {
    key.modifiers.difference(KeyModifiers::SHIFT).is_empty()
}
