//! `sudo meshvpn ssh`: a small full-screen editor for who may log in here without a password.
//!
//! Rows are who connects (a whole node, or one of its users that publishes a key), columns
//! are the local accounts they may log in as.

use anyhow::{Result, bail};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, TableState};
use ratatui::{DefaultTerminal, Frame};
use std::collections::HashSet;
use std::path::Path;

use crate::config::SshAllow;
use crate::control::{self, Request, Response};
use crate::keys::NodeId;
use crate::node::SshOverview;

struct Source {
    node: NodeId,
    name: String,
    from_user: Option<String>,
    online: bool,
    known: bool,
    /// The "every node of the network" row.
    everyone: bool,
}

impl Source {
    fn label(&self) -> String {
        if self.everyone {
            return "everyone (all nodes)".into();
        }
        match &self.from_user {
            None => format!("{} (any user)", self.name),
            Some(u) => format!("  {u}@{}", self.name),
        }
    }
}

struct App {
    hostname: String,
    rows: Vec<Source>,
    cols: Vec<String>,
    checked: HashSet<(usize, usize)>,
    saved: HashSet<(usize, usize)>,
    table: TableState,
    message: String,
    confirm_quit: bool,
}

/// Accounts people log in with: root and regular users with a real shell.
fn local_accounts() -> Vec<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let mut users = vec![];
    let mut root = false;
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        let (Some(name), Some(uid), Some(shell)) = (f.first(), f.get(2), f.get(6)) else {
            continue;
        };
        let Ok(uid) = uid.parse::<u32>() else { continue };
        if shell.ends_with("nologin") || shell.ends_with("false") || !crate::proto::valid_user(name) {
            continue;
        }
        if uid == 0 {
            root = true;
        } else if (1000..65534).contains(&uid) {
            users.push(name.to_string());
        }
    }
    users.sort();
    if root {
        users.push("root".into());
    }
    users
}

impl App {
    fn new(ov: SshOverview) -> Self {
        let mut rows = vec![Source {
            node: NodeId::default(),
            name: String::new(),
            from_user: None,
            online: true,
            known: true,
            everyone: true,
        }];
        for n in &ov.nodes {
            rows.push(Source {
                node: n.id,
                name: n.name.clone(),
                from_user: None,
                online: n.online,
                known: true,
                everyone: false,
            });
            for u in &n.users {
                rows.push(Source {
                    node: n.id,
                    name: n.name.clone(),
                    from_user: Some(u.clone()),
                    online: n.online,
                    known: true,
                    everyone: false,
                });
            }
        }
        let mut cols = local_accounts();
        for r in &ov.rules {
            if !rows.iter().any(|s| s.node == r.node && s.from_user == r.from_user) {
                rows.push(Source {
                    node: r.node,
                    name: r.name.clone(),
                    from_user: r.from_user.clone(),
                    online: false,
                    known: false,
                    everyone: false,
                });
            }
            for u in &r.users {
                if !cols.contains(u) {
                    cols.push(u.clone());
                }
            }
        }
        for u in &ov.allow_all {
            if !cols.contains(u) {
                cols.push(u.clone());
            }
        }
        let mut checked = HashSet::new();
        for u in &ov.allow_all {
            if let Some(col) = cols.iter().position(|c| c == u) {
                checked.insert((0, col));
            }
        }
        for r in &ov.rules {
            let Some(row) = rows.iter().position(|s| s.node == r.node && s.from_user == r.from_user) else {
                continue;
            };
            for u in &r.users {
                if let Some(col) = cols.iter().position(|c| c == u) {
                    checked.insert((row, col));
                }
            }
        }
        let mut table = TableState::default();
        table.select(Some(0));
        table.select_column(Some(1));
        App {
            hostname: ov.hostname,
            rows,
            cols,
            saved: checked.clone(),
            checked,
            table,
            message: String::new(),
            confirm_quit: false,
        }
    }

    fn cursor(&self) -> (usize, usize) {
        let row = self.table.selected().unwrap_or(0);
        let col = self.table.selected_column().unwrap_or(1).saturating_sub(1);
        (row, col)
    }

    fn dirty(&self) -> bool {
        self.checked != self.saved
    }

    fn rules(&self) -> Vec<SshAllow> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.everyone)
            .filter_map(|(i, s)| {
                let users: Vec<String> = (0..self.cols.len())
                    .filter(|c| self.checked.contains(&(i, *c)))
                    .map(|c| self.cols[c].clone())
                    .collect();
                (!users.is_empty()).then(|| SshAllow {
                    node: s.node,
                    name: s.name.clone(),
                    from_user: s.from_user.clone(),
                    users,
                })
            })
            .collect()
    }

    /// Accounts checked in the "everyone" row.
    fn allow_all(&self) -> Vec<String> {
        (0..self.cols.len())
            .filter(|c| self.checked.contains(&(0, *c)))
            .map(|c| self.cols[c].clone())
            .collect()
    }

    fn save(&mut self, rt: &tokio::runtime::Runtime, dir: &Path) -> Result<()> {
        let rules = self.rules();
        let allow_all = self.allow_all();
        if !rules.is_empty() || !allow_all.is_empty() {
            crate::sshd::enable()?;
        }
        rt.block_on(control::request(dir, &Request::SshSetRules { rules, allow_all }))?;
        self.saved = self.checked.clone();
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame) {
        let [title, body, help] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(3), Constraint::Length(2)]).areas(f.area());

        f.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    "Who may log in to ".into(),
                    self.hostname.clone().bold(),
                    " over SSH without a password".into(),
                ]),
                Line::from(
                    "rows: who connects (a node, or one of its users) · columns: account on this machine".dark_gray(),
                ),
            ]),
            title,
        );

        if self.rows.is_empty() || self.cols.is_empty() {
            let text = if self.rows.is_empty() {
                "No other nodes known yet - they appear here once they are online."
            } else {
                "No login accounts found on this machine."
            };
            f.render_widget(Paragraph::new(text).block(Block::bordered()), body);
        } else {
            let label_width = self
                .rows
                .iter()
                .map(|s| s.label().len() + 2)
                .max()
                .unwrap_or(10)
                .max(12) as u16;
            let mut widths = vec![Constraint::Length(label_width)];
            widths.extend(self.cols.iter().map(|c| Constraint::Length(c.len().max(5) as u16)));
            let header = Row::new(
                std::iter::once(Cell::from("from \\ as"))
                    .chain(self.cols.iter().map(|c| Cell::from(c.clone())))
                    .collect::<Vec<_>>(),
            )
            .style(Style::new().bold())
            .bottom_margin(1);
            let rows: Vec<Row> = self
                .rows
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let dot = match (s.known, s.online) {
                        _ if s.everyone => Span::styled("★ ", Style::new().fg(Color::Cyan)),
                        (false, _) => Span::styled("? ", Style::new().fg(Color::Yellow)),
                        (true, true) => Span::styled("● ", Style::new().fg(Color::Green)),
                        (true, false) => Span::styled("○ ", Style::new().fg(Color::DarkGray)),
                    };
                    let mut label = Line::from(vec![dot, Span::raw(s.label())]);
                    if s.from_user.is_none() || s.everyone {
                        label = label.bold();
                    }
                    let mut cells = vec![Cell::from(label)];
                    for c in 0..self.cols.len() {
                        let on = self.checked.contains(&(i, c));
                        let changed = on != self.saved.contains(&(i, c));
                        let mut style = if on {
                            Style::new().fg(Color::Green)
                        } else {
                            Style::new()
                        };
                        if changed {
                            style = style.add_modifier(Modifier::ITALIC).fg(Color::Yellow);
                        }
                        cells.push(Cell::from(if on { " [x]" } else { " [ ]" }).style(style));
                    }
                    Row::new(cells)
                })
                .collect();
            let table = Table::new(rows, widths)
                .header(header)
                .block(Block::bordered())
                .column_spacing(2)
                .cell_highlight_style(Style::new().reversed());
            f.render_stateful_widget(table, body, &mut self.table);
        }

        let status = if self.message.is_empty() && self.dirty() {
            "unsaved changes".yellow()
        } else {
            self.message.clone().into()
        };
        f.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    "↑↓←→".bold(),
                    " move   ".into(),
                    "space".bold(),
                    " allow/deny   ".into(),
                    "s".bold(),
                    " save   ".into(),
                    "q".bold(),
                    " quit".into(),
                ]),
                Line::from(status),
            ]),
            help,
        );
    }

    fn run(mut self, term: &mut DefaultTerminal, rt: &tokio::runtime::Runtime, dir: &Path) -> Result<Option<String>> {
        loop {
            term.draw(|f| self.draw(f))?;
            let Event::Key(key) = event::read()? else { continue };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let (row, col) = self.cursor();
            let quit_pending = std::mem::take(&mut self.confirm_quit);
            self.message.clear();
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.table.select(Some(row.saturating_sub(1))),
                KeyCode::Down | KeyCode::Char('j') => self
                    .table
                    .select(Some((row + 1).min(self.rows.len().saturating_sub(1)))),
                KeyCode::Left | KeyCode::Char('h') => self.table.select_column(Some(col.saturating_sub(1) + 1)),
                KeyCode::Right | KeyCode::Char('l') => self
                    .table
                    .select_column(Some((col + 1).min(self.cols.len().saturating_sub(1)) + 1)),
                KeyCode::Char(' ') | KeyCode::Enter if !self.rows.is_empty() && !self.cols.is_empty() => {
                    if !self.checked.remove(&(row, col)) {
                        self.checked.insert((row, col));
                    }
                }
                KeyCode::Char('s') => match self.save(rt, dir) {
                    Ok(()) => {
                        self.message =
                            "saved - applies right away to new SSH logins (sessions already open stay open)".into()
                    }
                    Err(e) => self.message = format!("error: {e:#}"),
                },
                KeyCode::Char('q') | KeyCode::Esc => {
                    if !self.dirty() || quit_pending {
                        return Ok(None);
                    }
                    self.confirm_quit = true;
                    self.message = "unsaved changes - press q again to discard them, or s to save".into();
                }
                _ => {}
            }
        }
    }
}

pub fn run(dir: &Path) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let Response::SshOverview(ov) = rt.block_on(control::request(dir, &Request::SshOverview))? else {
        bail!("unexpected answer from meshvpn");
    };
    let app = App::new(*ov);
    let mut term = ratatui::init();
    let res = app.run(&mut term, &rt, dir);
    ratatui::restore();
    if let Some(msg) = res? {
        println!("{msg}");
    }
    Ok(())
}
