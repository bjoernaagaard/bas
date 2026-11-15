use std::time::Instant;

use bas_core::Uuid;
use bas_core::credential::SecretText;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Clear, List, ListItem, ListState, Paragraph, StatefulWidget, Widget, Wrap,
};

use crate::app::{
    App, DeleteTarget, Field, Modal, Screen, SecretForm, SecretScreen, SecretsScreen, secret_count,
};

/// The status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Info(String),
    Error(String),
}

/// How many keys the bulk delete dialog names before it counts the rest, so the dialog
/// fits a 24-row terminal.
const MAX_KEYS_IN_DIALOG: usize = 10;

/// Shown in place of a hidden value. Fixed width, so it does not reveal the length.
pub(crate) const HIDDEN: &str = "••••••••";

impl Widget for &App {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let [header, body, status, keys] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);
        Line::from(vec![
            " bas-tui ".bold().reversed(),
            Span::raw(format!(
                " {} | organization {}",
                self.title(),
                self.organization
            )),
        ])
        .render(header, buf);
        match self.screens.last() {
            Some(Screen::Projects { selected }) => self.render_projects(*selected, body, buf),
            Some(Screen::Secrets(list)) => self.render_secrets(list, body, buf),
            Some(Screen::Secret(screen)) => self.render_secret(screen, body, buf),
            Some(Screen::Form(form)) => self.render_form(form, body, buf),
            Some(Screen::WebVault) | None => self.render_web_vault(body, buf),
        }
        self.render_status(status, buf);
        Line::from(self.key_hints()).dim().render(keys, buf);
        if let Some(modal) = &self.modal {
            self.render_modal(modal, area, buf);
        }
    }
}

impl App {
    fn title(&self) -> String {
        match self.screens.last() {
            Some(Screen::Projects { .. }) => "Projects".to_owned(),
            Some(Screen::Secrets(list)) => self.secrets_title(list),
            Some(Screen::Secret(_)) => "Secret".to_owned(),
            Some(Screen::Form(form)) if form.editing.is_some() => "Edit secret".to_owned(),
            Some(Screen::Form(_)) => "New secret".to_owned(),
            Some(Screen::WebVault) | None => "Web vault pages".to_owned(),
        }
    }

    fn project_name(&self, id: Uuid) -> String {
        self.projects
            .iter()
            .find(|project| project.id() == id)
            .map_or_else(|| id.to_string(), |project| project.name().to_owned())
    }

    fn secrets_title(&self, list: &SecretsScreen) -> String {
        let title = list.project.map_or_else(
            || "All secrets".to_owned(),
            |id| format!("Secrets in {}", self.project_name(id)),
        );
        match list.marked.len() {
            0 => title,
            marked => format!("{title}, {marked} marked"),
        }
    }

    fn render_projects(&self, selected: usize, area: Rect, buf: &mut Buffer) {
        let block = panel("Projects");
        if self.session.is_none() {
            Paragraph::new("Connecting to Secrets Manager")
                .block(block)
                .render(area, buf);
            return;
        }
        let rows = std::iter::once(ListItem::new("All secrets".italic())).chain(
            self.projects
                .iter()
                .map(|project| ListItem::new(project.name())),
        );
        render_list(rows, selected, block, area, buf);
    }

    fn render_secrets(&self, list: &SecretsScreen, area: Rect, buf: &mut Buffer) {
        let block = panel(&self.secrets_title(list));
        let inner = block.inner(area);
        block.render(area, buf);
        let [filter_area, list_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(inner);
        if list.filtering || !list.filter.is_empty() {
            let cursor = if list.filtering { "_" } else { "" };
            Line::from(format!("/{}{cursor}", list.filter)).render(filter_area, buf);
        }
        if list.items.is_none() {
            Paragraph::new("Loading").render(list_area, buf);
            return;
        }
        let visible = list.visible();
        if visible.is_empty() {
            Paragraph::new("No secrets").render(list_area, buf);
            return;
        }
        let rows = visible.into_iter().map(|item| {
            let projects: Vec<String> = item
                .project_ids()
                .iter()
                .map(|id| self.project_name(*id))
                .collect();
            let mark = if list.marked.contains(&item.id()) {
                "* "
            } else {
                "  "
            };
            ListItem::new(Line::from(vec![
                Span::raw(mark).fg(Color::Yellow).bold(),
                Span::raw(item.key().to_owned()),
                Span::raw(format!("  {}", projects.join(", "))).dim(),
            ]))
        });
        render_list(rows, list.selected, Block::new(), list_area, buf);
    }

    fn render_secret<'a>(&self, screen: &'a SecretScreen, area: Rect, buf: &mut Buffer) {
        let block = panel("Secret");
        let Some(detail) = &screen.detail else {
            Paragraph::new("Reading the secret")
                .block(block)
                .render(area, buf);
            return;
        };
        let shown = |value: &'a SecretText| {
            if screen.revealed {
                value.expose()
            } else {
                HIDDEN
            }
        };
        let project = detail
            .project_id()
            .map_or_else(|| "none".to_owned(), |id| self.project_name(id));
        let mut lines = vec![
            field_line("Key", detail.key()),
            field_line("ID", &detail.id().to_string()),
            field_line("Project", &project),
            Line::default(),
            "Value".bold().into(),
        ];
        lines.extend(Text::from(shown(detail.value())).lines);
        lines.push(Line::default());
        lines.push("Note".bold().into());
        lines.extend(Text::from(shown(detail.note())).lines);
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .render(area, buf);
    }

    fn render_form<'a>(&self, form: &'a SecretForm, area: Rect, buf: &mut Buffer) {
        let title = if form.saving.is_some() {
            format!("{} (saving)", self.title())
        } else {
            self.title()
        };
        let masked = |value: &'a SecretText| {
            if form.revealed {
                value.expose()
            } else if value.is_empty() {
                ""
            } else {
                HIDDEN
            }
        };
        let project = form
            .project
            .map_or_else(|| "pick a project".to_owned(), |id| self.project_name(id));
        let project = format!("< {project} >");
        let fields = [
            (Field::Key, "Key", form.key.as_str()),
            (Field::Value, "Value", masked(&form.value)),
            (Field::Note, "Note", masked(&form.note)),
            (Field::Project, "Project", project.as_str()),
        ];
        let lines: Vec<Line> = fields
            .into_iter()
            .flat_map(|(field, label, text)| {
                let focused = field == form.focus;
                let marker = if focused { "> " } else { "  " };
                let cursor = if focused && form.typing { "_" } else { "" };
                let style = if focused {
                    Style::new().fg(Color::Yellow)
                } else {
                    Style::new()
                };
                [
                    Line::styled(
                        format!("{marker}{label}"),
                        style.add_modifier(Modifier::BOLD),
                    ),
                    Line::from_iter(
                        std::iter::once("  ")
                            .chain(text.lines())
                            .chain(std::iter::once(cursor)),
                    )
                    .style(style),
                    Line::default(),
                ]
            })
            .collect();
        Paragraph::new(lines)
            .block(panel(&title))
            .wrap(Wrap { trim: false })
            .render(area, buf);
    }

    fn render_web_vault(&self, area: Rect, buf: &mut Buffer) {
        let mut lines = vec![
            Line::from(
                "A machine account token cannot do these. Open the page in a browser signed in to Bitwarden.",
            ),
            Line::default(),
        ];
        for (label, url) in self.web_vault_rows() {
            lines.push(label.bold().into());
            lines.push(Line::from(format!("  {url}")).fg(Color::Cyan));
        }
        Paragraph::new(lines)
            .block(panel("Web vault pages"))
            .wrap(Wrap { trim: false })
            .render(area, buf);
    }

    /// Every user-session operation, with its web vault page filled in.
    fn web_vault_rows(&self) -> Vec<(String, String)> {
        let sm = format!("{}/#/sm/{}", self.vault_base, self.organization);
        let machine_accounts = format!("{sm}/machine-accounts");
        let (project_label, project_path) = match self.context_project() {
            Some(project) => (
                project.name().to_owned(),
                format!("{sm}/projects/{}", project.id()),
            ),
            None => (
                "no project selected; pick one on the Projects screen".to_owned(),
                format!("{sm}/projects/<projectId>"),
            ),
        };
        vec![
            (
                "Secret access policies, value history, or create with access policies: open the secret".to_owned(),
                format!("{sm}/secrets"),
            ),
            ("Trash: list, restore, or empty".to_owned(), self.trash_url()),
            (
                format!("People with project access ({project_label})"),
                format!("{project_path}/people"),
            ),
            (
                format!("Machine accounts with project access ({project_label})"),
                format!("{project_path}/machine-accounts"),
            ),
            (
                "Machine accounts: list, create, read, rename, delete".to_owned(),
                machine_accounts.clone(),
            ),
            (
                "Access tokens of a machine account: open it, then the Access tokens tab".to_owned(),
                machine_accounts.clone(),
            ),
            (
                "People or projects of a machine account: open it, then the People or Projects tab"
                    .to_owned(),
                machine_accounts.clone(),
            ),
            (
                "Machine account event log: open it, then the Event logs tab".to_owned(),
                machine_accounts,
            ),
            ("Item counts overview".to_owned(), sm.clone()),
            (
                "Ask admins for Secrets Manager access".to_owned(),
                format!("{}/#/request-sm-access", self.vault_base),
            ),
            ("Import".to_owned(), format!("{sm}/settings/import")),
            ("Export".to_owned(), format!("{sm}/settings/export")),
            (
                "Organization event log, including secret and project events".to_owned(),
                format!(
                    "{}/#/organizations/{}/reporting/events",
                    self.vault_base, self.organization
                ),
            ),
        ]
    }

    fn render_status(&self, area: Rect, buf: &mut Buffer) {
        let countdown = self.copied.as_ref().map(|copied| {
            let left = copied.deadline.saturating_duration_since(Instant::now());
            format!(" Clipboard clears in {}s ", left.as_millis().div_ceil(1000))
        });
        let width = countdown.as_ref().map_or(0, |text| text.chars().count());
        let [message_area, countdown_area] = Layout::horizontal([
            Constraint::Min(1),
            Constraint::Length(u16::try_from(width).unwrap_or(u16::MAX)),
        ])
        .areas(area);
        status_line(&self.status).render(message_area, buf);
        if let Some(countdown) = countdown {
            Line::from(countdown).reversed().render(countdown_area, buf);
        }
    }

    fn key_hints(&self) -> String {
        let hints = match self.screens.last() {
            Some(Screen::Projects { .. }) => {
                "Enter secrets  n new  e rename  d delete  w web vault  ? keys  q quit"
            }
            Some(Screen::Secrets(list)) if list.filtering => {
                "type to filter  Enter keep  Esc clear"
            }
            Some(Screen::Secrets(list)) if !list.marked.is_empty() => {
                "Space mark  d delete marked  Esc clear marks  / filter  ? keys"
            }
            Some(Screen::Secrets(_)) => {
                "Enter view  Space mark  n new  e edit  d delete  / filter  ? keys  Esc back"
            }
            Some(Screen::Secret(_)) => {
                "r reveal  c copy  e edit  d delete  w web vault  ? keys  Esc back"
            }
            Some(Screen::Form(form)) if form.typing => {
                "typing  Enter or Esc done  Tab next field  Ctrl-S save"
            }
            Some(Screen::Form(_)) => {
                "Enter type in field  Tab next  Left/Right project  r reveal  Ctrl-S save  Esc cancel"
            }
            Some(Screen::WebVault) | None => "? keys  Esc back",
        };
        format!(" {hints}")
    }

    fn render_modal(&self, modal: &Modal, area: Rect, buf: &mut Buffer) {
        let (title, lines): (&str, Vec<Line>) = match modal {
            Modal::Help => ("Keys", help_lines()),
            Modal::ProjectName { renaming, input } => (
                if renaming.is_some() {
                    "Rename project"
                } else {
                    "New project"
                },
                vec![
                    Line::from(format!("Name: {input}_")),
                    Line::default(),
                    Line::from("Enter save  Esc cancel").dim(),
                ],
            ),
            Modal::Delete { target, typed } => ("Delete", self.delete_lines(target, typed)),
        };
        let height = u16::try_from(lines.len() + 2).unwrap_or(u16::MAX);
        // A line wider than the dialog wraps and pushes the last line out of it.
        let widest = lines.iter().map(Line::width).max().unwrap_or(0);
        let width = u16::try_from(widest + 2).unwrap_or(u16::MAX).max(72);
        let popup = centered(area, width, height);
        Clear.render(popup, buf);
        Paragraph::new(lines)
            .block(panel(title))
            .wrap(Wrap { trim: false })
            .render(popup, buf);
    }

    fn delete_lines(&self, target: &DeleteTarget, typed: &str) -> Vec<Line<'static>> {
        let mut lines = match target {
            DeleteTarget::Secret { key, .. } => vec![
                Line::from(format!("Delete secret {key}?")).bold(),
                Line::from("It moves to the organization trash. An admin can restore it at:"),
                Line::from(self.trash_url()).fg(Color::Cyan),
                Line::default(),
                Line::from("Type the secret key to confirm:"),
            ],
            DeleteTarget::Secrets { secrets, count, .. } => {
                let mut lines =
                    vec![Line::from(format!("Delete {}?", secret_count(secrets.len()))).bold()];
                let shown = secrets.len().min(MAX_KEYS_IN_DIALOG);
                lines.extend(
                    secrets[..shown]
                        .iter()
                        .map(|(_, key)| Line::from(format!("  {key}"))),
                );
                if secrets.len() > shown {
                    lines.push(Line::from(format!("  and {} more", secrets.len() - shown)).dim());
                }
                lines.extend([
                    Line::from(
                        "The organization trash keeps what you delete. An admin can restore it at:",
                    ),
                    Line::from(self.trash_url()).fg(Color::Cyan),
                    Line::default(),
                    Line::from(format!("Type {count} to confirm:")),
                ]);
                lines
            }
            DeleteTarget::Project { name, .. } => vec![
                Line::from(format!("Delete project {name}?")).bold(),
                Line::from("The project itself is deleted. Projects do not go to the trash."),
                Line::default(),
                Line::from("Type the project name to confirm:"),
            ],
        };
        lines.push(Line::from(format!("{typed}_")).fg(Color::Yellow));
        lines.push(Line::default());
        lines.push(if typed == target.name() {
            Line::from("Enter delete  Esc cancel").fg(Color::Red).bold()
        } else {
            Line::from("Delete stays disabled until the text matches.  Esc cancel").dim()
        });
        lines
    }
}

fn help_lines() -> Vec<Line<'static>> {
    [
        "Everywhere: ? keys, w web vault pages, q or Esc back or quit, Ctrl-C quit",
        "Lists: Up/Down or k/j move, g top, G bottom",
        "Projects: Enter open secrets, n new, e rename, d delete",
        "Secrets: Enter view, n new, e edit, d delete, / filter by key,",
        "         Space mark or unmark, Esc clear marks, d delete the marked secrets",
        "Secret: r reveal or hide, c copy value (clipboard clears after 30 s), e edit, d delete",
        "Form: Enter types in the field, Enter or Esc stops typing, Tab next field,",
        "      Up/Down field, Left/Right project, r reveal, Ctrl-S save,",
        "      Enter on Project saves, Esc cancels",
        "Delete: type the exact key or name, or the count of marked secrets, then Enter",
        "",
        "Press any key to close",
    ]
    .into_iter()
    .map(Line::from)
    .collect()
}

pub(crate) fn status_line(status: &Status) -> Line<'_> {
    match status {
        Status::Info(text) => Line::from(format!(" {text}")),
        Status::Error(text) => Line::from(format!(" {text}")).fg(Color::Red).bold(),
    }
}

pub(crate) fn panel(title: &str) -> Block<'static> {
    Block::bordered()
        .title(format!(" {title} "))
        .border_type(BorderType::Rounded)
}

pub(crate) fn field_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("{label}: ")).bold(),
        Span::raw(value.to_owned()),
    ])
}

pub(crate) fn render_list<'a>(
    rows: impl Iterator<Item = ListItem<'a>>,
    selected: usize,
    block: Block<'a>,
    area: Rect,
    buf: &mut Buffer,
) {
    let list = List::new(rows)
        .block(block)
        .highlight_style(Style::new().reversed())
        .highlight_symbol("> ");
    let mut state = ListState::default().with_selected(Some(selected));
    StatefulWidget::render(list, area, buf, &mut state);
}

pub(crate) fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [row] = Layout::vertical([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(area);
    let [popup] = Layout::horizontal([Constraint::Length(width)])
        .flex(Flex::Center)
        .areas(row);
    popup
}
