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
    /// The node publishes at least one SSH key (a user's ~/.ssh/id_*).
    keys: bool,
    /// The "every node of the network" row.
    everyone: bool,
}

impl Source {
    fn label(&self) -> String {
        if self.everyone {
            return "everyone (all nodes)".into();
        }
        match &self.from_user {
            None if self.known && !self.keys => format!("{} (any user) - no SSH key", self.name),
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
#[cfg(not(target_os = "linux"))]
fn local_accounts() -> Vec<String> {
    // macOS keeps people's accounts in Directory Services, not in /etc/passwd.
    let mut users: Vec<String> = crate::sys::login_users()
        .into_iter()
        .map(|(name, _)| name)
        .filter(|n| n != "root" && crate::proto::valid_user(n))
        .collect();
    users.sort();
    users.push("root".into());
    me_first(users)
}

/// Whoever opened this: the account behind sudo, else this process's own.
fn me() -> Option<String> {
    std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty() && u != "root")
        .or_else(crate::sys::user_name)
        .filter(|n| crate::proto::valid_user(n))
}

/// The person who opened this comes first (and is there even without an /etc/passwd line,
/// e.g. an LDAP account).
fn me_first(mut users: Vec<String>) -> Vec<String> {
    if let Some(me) = me() {
        users.retain(|u| *u != me);
        users.insert(0, me);
    }
    users
}

/// Accounts people log in with: root and regular users with a real shell.
#[cfg(target_os = "linux")]
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
        } else if crate::sys::person_uid(uid) {
            users.push(name.to_string());
        }
    }
    // A rootless install logs people in only as its own user: just that one.
    if crate::config::rootless()
        && let Some(me) = me()
    {
        return vec![me];
    }
    users.sort();
    if root {
        users.push("root".into());
    }
    me_first(users)
}

impl App {
    fn new(ov: SshOverview) -> Self {
        let mut rows = vec![Source {
            node: NodeId::default(),
            name: String::new(),
            from_user: None,
            online: true,
            known: true,
            keys: true,
            everyone: true,
        }];
        for n in &ov.nodes {
            rows.push(Source {
                node: n.id,
                name: n.name.clone(),
                from_user: None,
                online: n.online,
                known: true,
                keys: !n.users.is_empty(),
                everyone: false,
            });
            for u in &n.users {
                rows.push(Source {
                    node: n.id,
                    name: n.name.clone(),
                    from_user: Some(u.clone()),
                    online: n.online,
                    known: true,
                    keys: true,
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
                    keys: true,
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

    /// What to do when someone who should get access has no SSH key yet.
    fn key_hint(&self) -> Option<String> {
        let s = self.rows.get(self.cursor().0)?;
        if s.everyone || !s.known {
            return None;
        }
        let name = &s.name;
        Some(match &s.from_user {
            None if !s.keys => format!(
                "no SSH key on {name} yet: whoever logs in from there runs `ssh-keygen -t ed25519`, then reopen this"
            ),
            None => format!(
                "someone on {name} missing? Only users with an SSH key are listed: they run `ssh-keygen -t ed25519`"
            ),
            Some(_) => return None,
        })
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
        // The rules count for the built-in server and once sshd is set up: saved either way.
        let sshd = if !rules.is_empty() || !allow_all.is_empty() {
            crate::sshd::enable_if_installed().err()
        } else {
            None
        };
        rt.block_on(control::request(dir, &Request::SshSetRules { rules, allow_all }))?;
        self.saved = self.checked.clone();
        match sshd {
            Some(e) => Err(e.context("saved, but sshd doesn't use the rules yet")),
            None => Ok(()),
        }
    }

    fn draw(&mut self, f: &mut Frame) {
        let [title, body, help] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(3), Constraint::Length(3)]).areas(f.area());

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
                Line::from(self.key_hint().unwrap_or_default().dark_gray()),
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

#[cfg(test)]
mod account_tests {
    #[test]
    fn the_current_user_comes_first() {
        let me = super::me().unwrap();
        let users = super::me_first(vec!["alice".into(), me.clone(), "root".into()]);
        assert_eq!(users[0], me);
        assert_eq!(users.iter().filter(|u| **u == me).count(), 1);
        assert_eq!(super::me_first(vec!["root".into()])[0], me);
    }
}

#[cfg(test)]
mod hint_tests {
    use super::*;

    fn screen(app: &mut App) -> String {
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(140, 12)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .chunks(140)
            .map(|l| l.iter().map(|c| c.symbol()).collect::<String>() + "\n")
            .collect()
    }

    #[test]
    fn a_node_without_a_key_says_how_to_make_one() {
        let ov = SshOverview {
            hostname: "here".into(),
            nodes: vec![
                crate::node::SshSource {
                    id: crate::keys::Key32([1; 32]),
                    name: "nokey".into(),
                    online: true,
                    users: vec![],
                },
                crate::node::SshSource {
                    id: crate::keys::Key32([2; 32]),
                    name: "withkey".into(),
                    online: true,
                    users: vec!["ann".into()],
                },
            ],
            rules: vec![],
            allow_all: vec![],
        };
        let mut app = App::new(ov);
        assert!(!screen(&mut app).contains("ssh-keygen"), "not on the everyone row");
        app.table.select(Some(1));
        let s = screen(&mut app);
        assert!(s.contains("nokey (any user) - no SSH key"), "{s}");
        assert!(s.contains("no SSH key on nokey yet"), "{s}");
        app.table.select(Some(2));
        let s = screen(&mut app);
        assert!(s.contains("someone on withkey missing?"), "{s}");
        assert!(!s.contains("withkey (any user) - no SSH key"), "{s}");
    }
}
