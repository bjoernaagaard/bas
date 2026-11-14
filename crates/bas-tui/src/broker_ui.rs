//! Drawing for broker mode.

use bas_broker::protocol::{EntryKind, EntrySummary};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, ListItem, Paragraph, Widget, Wrap};

use crate::broker::{
    AddField, AddForm, BrokerApp, Confirm, Connection, Focus, Modal, Request, RequestState,
    SECTIONS, section,
};
use crate::ui::{centered, field_line, panel, render_list, status_line};

/// Most request rows the requests panel shows before it scrolls.
const REQUEST_ROWS: usize = 8;

impl Widget for &BrokerApp {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let rows = self.requests.len().clamp(1, REQUEST_ROWS);
        let [header, body, requests, status, keys] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(u16::try_from(rows + 2).unwrap_or(u16::MAX)),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);
        self.render_header(header, buf);
        let [list, detail] =
            Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
                .areas(body);
        self.render_entries(list, buf);
        self.render_detail(detail, buf);
        self.render_requests(requests, buf);
        status_line(&self.message).render(status, buf);
        Line::from(self.key_hints()).dim().render(keys, buf);
        if let Some(modal) = &self.modal {
            self.render_modal(modal, area, buf);
        }
    }
}

impl BrokerApp {
    fn render_header(&self, area: Rect, buf: &mut Buffer) {
        let state = match &self.connection {
            Connection::Connecting => "connecting to the broker".to_owned(),
            Connection::Connected { version, .. } => format!("broker {version}"),
            Connection::Failed(_) => "the broker does not answer".to_owned(),
        };
        let approvers = match self.approvers.as_deref() {
            None => String::new(),
            Some([]) => " | no passkey enrolled yet".to_owned(),
            Some(labels) => format!(" | approvers: {}", labels.join(", ")),
        };
        Line::from(vec![
            " bas-tui ".bold().reversed(),
            Span::raw(format!(" {} | {state}{approvers}", self.hostname)),
        ])
        .render(area, buf);
    }

    fn focused_panel(&self, title: &str, focus: Focus) -> Block<'static> {
        let block = panel(title);
        if self.focus == focus {
            block.border_style(Style::new().fg(Color::Yellow))
        } else {
            block
        }
    }

    fn render_entries(&self, area: Rect, buf: &mut Buffer) {
        let mut block = self.focused_panel("What this machine can use", Focus::Entries);
        if let Connection::Connected { policy_hash, .. } = &self.connection {
            block = block.title_bottom(
                Line::from(format!(
                    " policy {} ",
                    policy_hash.get(..8).unwrap_or(policy_hash)
                ))
                .dim(),
            );
        }
        if let Connection::Failed(error) = &self.connection {
            Paragraph::new(vec![
                Line::from("The broker did not answer.").bold(),
                Line::from(error.clone()).fg(Color::Red),
                Line::default(),
                Line::from("Press g to try again."),
            ])
            .block(block)
            .wrap(Wrap { trim: false })
            .render(area, buf);
            return;
        }
        if let Some(error) = &self.policy_error {
            Paragraph::new(Line::from(error.clone()).fg(Color::Red))
                .block(block)
                .wrap(Wrap { trim: false })
                .render(area, buf);
            return;
        }
        let Some(entries) = &self.entries else {
            Paragraph::new("Reading the active policy")
                .block(block)
                .render(area, buf);
            return;
        };
        if entries.is_empty() {
            Paragraph::new(vec![
                Line::from("Nothing yet. This machine can use no stored keys."),
                Line::default(),
                Line::from("Press a to add an API key, or e to write the policy in your editor."),
            ])
            .block(block)
            .wrap(Wrap { trim: false })
            .render(area, buf);
            return;
        }
        // Room for a row's text inside the borders and the "> " marker.
        let room = usize::from(area.width.saturating_sub(4));
        let mut rows = Vec::new();
        let mut position = 0;
        let mut last_section = None;
        for (index, entry) in entries.iter().enumerate() {
            let section = section(entry.kind);
            if last_section != Some(section) {
                if last_section.is_some() {
                    rows.push(ListItem::new(""));
                }
                let title = SECTIONS.get(section).map_or("Other", |(_, title)| title);
                rows.push(ListItem::new(Line::from(title.to_owned()).bold()));
                last_section = Some(section);
            }
            if index == self.selected {
                position = rows.len();
            }
            rows.push(entry_row(entry, room));
        }
        render_list(rows.into_iter(), position, block, area, buf);
    }

    fn render_detail(&self, area: Rect, buf: &mut Buffer) {
        let Some(entry) = self.selected_entry() else {
            Paragraph::new("").block(panel("Entry")).render(area, buf);
            return;
        };
        let mut lines: Vec<Line> = entry
            .about
            .iter()
            .map(|text| Line::from(text.clone()))
            .collect();
        if !entry.usage.is_empty() {
            lines.push(Line::default());
            lines.push(Line::from("How to use it").bold());
            lines.push(Line::from(format!("  {}", entry.usage)).fg(Color::Cyan));
        }
        if !entry.facts.is_empty() {
            lines.push(Line::default());
            lines.extend(
                entry
                    .facts
                    .iter()
                    .map(|fact| field_line(&fact.label, &fact.value)),
            );
        }
        lines.push(Line::default());
        lines.push(Line::from(change_hint(entry.kind)));
        if !entry.references.is_empty() {
            lines.push(Line::default());
        }
        for reference in &entry.references {
            let text = if reference.label.is_empty() {
                format!("Stored in Bitwarden as {}", reference.value)
            } else {
                format!(
                    "Stored in Bitwarden as {} ({})",
                    reference.value, reference.label
                )
            };
            lines.push(Line::from(text).dim());
        }
        Paragraph::new(lines)
            .block(panel(&entry.name))
            .wrap(Wrap { trim: false })
            .render(area, buf);
    }

    fn render_requests(&self, area: Rect, buf: &mut Buffer) {
        let block = self.focused_panel("Requests", Focus::Requests);
        if self.requests.is_empty() {
            Paragraph::new(
                "No requests yet. Your requests and pending ones from other clients show here.",
            )
            .block(block)
            .wrap(Wrap { trim: false })
            .render(area, buf);
            return;
        }
        let rows = self.requests.iter().map(request_row);
        render_list(rows, self.request_selected, block, area, buf);
    }

    fn key_hints(&self) -> String {
        let hints = match (&self.modal, self.focus) {
            (Some(Modal::Add(_)), _) => {
                "type  Tab or Enter next field  Shift-Tab back  Ctrl-S or Enter on last field send  Esc cancel"
            }
            (Some(Modal::Confirm(_)), _) => "y or Enter send  n or Esc cancel",
            (Some(_), _) => "any key closes",
            (None, Focus::Entries) => {
                "a add key  r replace  e edit  p passkey  g refresh  Tab requests  ? help  q quit"
            }
            (None, Focus::Requests) => {
                "Enter details  c copy approval page  g refresh  Tab entries  ? help  q quit"
            }
        };
        format!(" {hints}")
    }

    fn render_modal(&self, modal: &Modal, area: Rect, buf: &mut Buffer) {
        let (title, lines): (&str, Vec<Line>) = match modal {
            Modal::Help => ("Keys", help_lines()),
            Modal::Add(form) => ("Add an API key", add_lines(form)),
            Modal::Confirm(confirm) => ("Confirm", confirm_lines(confirm)),
            Modal::Details(key) => (
                "Request",
                self.request(*key).map_or_else(Vec::new, details_lines),
            ),
        };
        let height = u16::try_from(lines.len() + 2)
            .unwrap_or(u16::MAX)
            .min(area.height);
        let popup = centered(area, 90.min(area.width), height);
        Clear.render(popup, buf);
        Paragraph::new(lines)
            .block(panel(title))
            .wrap(Wrap { trim: false })
            .render(popup, buf);
    }
}

/// A list row: the name and its hint on one line when they fit in `room` columns, else
/// the hint on a second line.
fn entry_row(entry: &EntrySummary, room: usize) -> ListItem<'static> {
    let name = Span::raw(entry.name.clone());
    if entry.hint.is_empty() {
        return ListItem::new(Line::from(name));
    }
    let one_line = Line::from(vec![
        name.clone(),
        Span::raw(format!("  {}", entry.hint)).dim(),
    ]);
    if one_line.width() <= room {
        return ListItem::new(one_line);
    }
    ListItem::new(vec![
        Line::from(name),
        Line::from(format!("  {}", entry.hint)).dim(),
    ])
}

/// What the keys of broker mode do to an entry of `kind`.
fn change_hint(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Secret => {
            "Press r to replace the key. You type the new value on the approval page, never here."
        }
        EntryKind::Github | EntryKind::Tailscale => {
            "Press r to throw away the current tokens. The next request makes new ones."
        }
        EntryKind::Helper | EntryKind::Ssh => {
            "Press e to change or remove it in the policy. A passkey approves the change."
        }
        EntryKind::Other => "This bas is older than the broker. Update bas to change it here.",
    }
}

fn state_span(state: &RequestState) -> Span<'static> {
    let (text, color) = match state {
        RequestState::Sending => ("sending ", Color::Yellow),
        RequestState::Pending => ("pending ", Color::Yellow),
        RequestState::Approved(_) => ("approved", Color::Green),
        RequestState::Done(_) => ("done    ", Color::Green),
        RequestState::Denied => ("denied  ", Color::Red),
        RequestState::Expired => ("expired ", Color::Red),
        RequestState::Refused(_) => ("refused ", Color::Red),
        RequestState::Failed(_) => ("failed  ", Color::Red),
    };
    Span::styled(text, Style::new().fg(color).add_modifier(Modifier::BOLD))
}

fn request_row(request: &Request) -> ListItem<'static> {
    let note = match &request.state {
        RequestState::Pending => request
            .url
            .as_ref()
            .map(|url| format!("approve at {url}"))
            .unwrap_or_default(),
        RequestState::Approved(text)
        | RequestState::Done(text)
        | RequestState::Refused(text)
        | RequestState::Failed(text) => text.clone(),
        RequestState::Sending | RequestState::Denied | RequestState::Expired => String::new(),
    };
    ListItem::new(Line::from(vec![
        state_span(&request.state),
        Span::raw(format!("  {}", request.action)),
        Span::raw(format!("  {note}")).dim(),
    ]))
}

fn details_lines(request: &Request) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::raw("State: ").bold(),
            state_span(&request.state),
        ]),
        field_line("Request", &request.action),
        field_line(
            "Started by",
            if request.mine {
                "this app"
            } else {
                "another client"
            },
        ),
    ];
    if let Some(id) = &request.id {
        lines.push(field_line("Approval", id));
    }
    if let Some(url) = &request.url {
        lines.push(field_line("Approval page", url));
    }
    match &request.state {
        RequestState::Approved(text) | RequestState::Done(text) => {
            lines.push(field_line("Result", text));
        }
        RequestState::Refused(text) => {
            lines.push(field_line("Refused, nothing changed", text));
        }
        RequestState::Failed(text) => lines.push(field_line("Failed", text)),
        _ => {}
    }
    if let Some(diff) = &request.diff {
        lines.push(Line::default());
        lines.push("Diff from the active policy".bold().into());
        for line in diff.lines() {
            let style = if line.starts_with('+') && !line.starts_with("+++") {
                Style::new().fg(Color::Green)
            } else if line.starts_with('-') && !line.starts_with("---") {
                Style::new().fg(Color::Red)
            } else {
                Style::new()
            };
            lines.push(Line::styled(line.to_owned(), style));
        }
    }
    lines.push(Line::default());
    lines.push(Line::from("Press any key to close").dim());
    lines
}

fn add_lines(form: &AddForm) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(
            "The broker opens an approval. You type the value on the approval page, never here.",
        )
        .dim(),
        Line::default(),
    ];
    for field in AddField::ALL {
        let focused = field == form.focus;
        let style = if focused {
            Style::new().fg(Color::Yellow)
        } else {
            Style::new()
        };
        let marker = if focused { "> " } else { "  " };
        let cursor = if focused { "_" } else { "" };
        lines.push(Line::styled(
            format!("{marker}{}", field.label()),
            style.add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::styled(
            format!("  {}{cursor}", form.text(field)),
            style,
        ));
    }
    lines
}

fn confirm_lines(confirm: &Confirm) -> Vec<Line<'static>> {
    let text = match confirm {
        Confirm::Rotate { name, minted: true } => vec![
            format!("Rotate {name}?"),
            "The broker drops its cached tokens at once. No approval is needed.".to_owned(),
        ],
        Confirm::Rotate {
            name,
            minted: false,
        } => vec![
            format!("Rotate {name}?"),
            "The broker opens an approval. You type the new value on the approval page.".to_owned(),
        ],
        Confirm::Passkey => vec![
            "Enroll one more passkey?".to_owned(),
            "An enrolled passkey approves it, and the approval page shows a one-time link."
                .to_owned(),
        ],
    };
    let mut lines: Vec<Line> = text.into_iter().map(Line::from).collect();
    lines.push(Line::default());
    lines.push(Line::from("y or Enter send  n or Esc cancel").dim());
    lines
}

fn help_lines() -> Vec<Line<'static>> {
    [
        "This screen shows what the broker lets this machine use. Keys and other values",
        "stay in the broker and never reach this app.",
        "",
        "Up and Down, or k and j, move in a list. Tab switches between the lists.",
        "g reads everything again. ? shows this help. q, Esc, or Ctrl-C quits.",
        "",
        "a adds an API key. r replaces the selected key or throws away its tokens.",
        "e opens the policy in $VISUAL or $EDITOR. p enrolls one more passkey.",
        "In the requests list, Enter shows a request and c copies its approval page.",
        "",
        "Every change waits until a passkey approves it on the approval page.",
        "",
        "Press any key to close",
    ]
    .into_iter()
    .map(Line::from)
    .collect()
}
