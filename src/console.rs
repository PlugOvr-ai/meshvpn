//! `meshvpn console` (also plain `meshvpn` in a terminal): a desktop for the terminal. The
//! nodes of the mesh, and shells on them as tabs - for when all you have is an SSH login.
//!
//! Tab 0 lists the nodes; Enter opens a shell on one (ssh, or a local shell for this
//! machine) in a new tab. Shells run in pseudo-terminals, rendered with the vt100 crate.
//! Switching: Alt+0..9 / Alt+←→, or Ctrl+B then 0..9, n, p, w (close), d (desktop link).

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{DefaultTerminal, Frame};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::agent::{self, NodeView, Remote};

struct Shell {
    title: String,
    parser: Arc<Mutex<vt100::Parser>>,
    master: OwnedFd,
    writer: std::fs::File,
    child: std::process::Child,
    exited: Arc<AtomicBool>,
    size: (u16, u16),
    scroll: usize,
}

impl Shell {
    fn spawn(
        title: String,
        mut cmd: std::process::Command,
        rows: u16,
        cols: u16,
        dirty: Arc<AtomicBool>,
    ) -> Result<Self> {
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;
        let (master, slave) = crate::sshserver::openpty(cols, rows)?;
        cmd.stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave))
            .env("TERM", "xterm-256color");
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY, 0);
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        drop(cmd);
        let parser = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, 5000)));
        let exited = Arc::new(AtomicBool::new(false));
        let mut reader = std::fs::File::from(master.try_clone()?);
        let (p, ex) = (parser.clone(), exited.clone());
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        p.lock().unwrap().process(&buf[..n]);
                        dirty.store(true, Ordering::Relaxed);
                    }
                }
            }
            ex.store(true, Ordering::Relaxed);
            dirty.store(true, Ordering::Relaxed);
        });
        let writer = std::fs::File::from(master.try_clone()?);
        Ok(Shell {
            title,
            parser,
            master,
            writer,
            child,
            exited,
            size: (rows, cols),
            scroll: 0,
        })
    }

    fn resize(&mut self, rows: u16, cols: u16) {
        if (rows, cols) != self.size && rows > 0 && cols > 0 {
            self.size = (rows, cols);
            self.parser.lock().unwrap().screen_mut().set_size(rows, cols);
            crate::sshserver::set_winsize(self.master.as_raw_fd(), cols, rows);
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        if self.scroll > 0 {
            self.scroll = 0;
            self.parser.lock().unwrap().screen_mut().set_scrollback(0);
        }
        let _ = self.writer.write_all(bytes);
    }

    fn done(&mut self) -> bool {
        self.exited.load(Ordering::Relaxed) || matches!(self.child.try_wait(), Ok(Some(_)))
    }
}

impl Drop for Shell {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct App {
    dir: PathBuf,
    /// `-u`: the account for shells; None: what plain `ssh` uses.
    user: Option<String>,
    socks: bool,
    nodes: Vec<NodeView>,
    network: String,
    table: TableState,
    shells: Vec<Shell>,
    /// 0: the node list, n: shell n-1
    tab: usize,
    prefix: bool,
    popup: Option<Vec<String>>,
    prompt: Option<(String, String)>,
    status: String,
    last_refresh: Instant,
    dirty: Arc<AtomicBool>,
    body: Rect,
    quit: bool,
    viewers: Vec<crate::desktop::client::Viewer>,
}

pub fn run(dir: &Path, user: Option<String>) -> Result<()> {
    let mut app = App {
        dir: dir.to_path_buf(),
        user,
        socks: false,
        nodes: vec![],
        network: String::new(),
        table: TableState::default().with_selected(Some(0)),
        shells: vec![],
        tab: 0,
        prefix: false,
        popup: None,
        prompt: None,
        status: String::new(),
        last_refresh: Instant::now() - Duration::from_secs(60),
        dirty: Arc::new(AtomicBool::new(true)),
        body: Rect::default(),
        quit: false,
        viewers: vec![],
    };
    app.refresh();
    let mut terminal = ratatui::init();
    let r = app.run(&mut terminal);
    ratatui::restore();
    r
}

impl App {
    fn refresh(&mut self) {
        self.last_refresh = Instant::now();
        match agent::status(&self.dir) {
            Ok(st) => {
                self.socks = st.socks.is_some();
                self.network = st.network.clone();
                let mut nodes = agent::nodes(&st);
                nodes.sort_by_key(|n| (!n.is_self, !n.online, n.name.clone()));
                self.nodes = nodes;
            }
            Err(e) => self.status = format!("{e:#}"),
        }
        let max = self.nodes.len().saturating_sub(1);
        if self.table.selected().unwrap_or(0) > max {
            self.table.select(Some(max));
        }
    }

    fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        while !self.quit {
            if self.last_refresh.elapsed() > Duration::from_secs(3) {
                self.refresh();
                self.dirty.store(true, Ordering::Relaxed);
            }
            for s in &mut self.shells {
                if s.done() && !s.title.ends_with(" (ended)") {
                    s.title.push_str(" (ended)");
                    self.dirty.store(true, Ordering::Relaxed);
                }
            }
            if self.dirty.swap(false, Ordering::Relaxed) {
                terminal.draw(|f| self.draw(f))?;
                let (rows, cols) = (self.body.height, self.body.width);
                for s in &mut self.shells {
                    s.resize(rows, cols);
                }
            }
            if event::poll(Duration::from_millis(30))? {
                match event::read()? {
                    Event::Key(k) if k.kind != KeyEventKind::Release => self.key(k),
                    Event::Paste(text) => self.paste(&text),
                    _ => {}
                }
                self.dirty.store(true, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------ input

    fn key(&mut self, k: KeyEvent) {
        if let Some((label, mut input)) = self.prompt.take() {
            match k.code {
                KeyCode::Enter => self.prompt_done(&label, input.trim()),
                KeyCode::Esc => {}
                KeyCode::Backspace => {
                    input.pop();
                    self.prompt = Some((label, input));
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    self.prompt = Some((label, input));
                }
                _ => self.prompt = Some((label, input)),
            }
            return;
        }
        if self.popup.is_some() {
            self.popup = None;
            return;
        }
        let alt = k.modifiers.contains(KeyModifiers::ALT);
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        // Switching tabs: Alt+digit/arrows, or Ctrl+B and a key.
        if self.prefix {
            self.prefix = false;
            if self.command(k.code) {
                return;
            }
            if let Some(s) = self.current() {
                s.send(&[2]); // Ctrl+B Ctrl+B: a literal Ctrl+B
            }
            return;
        }
        if ctrl && k.code == KeyCode::Char('b') {
            self.prefix = true;
            return;
        }
        if alt && matches!(k.code, KeyCode::Char('0'..='9') | KeyCode::Left | KeyCode::Right) && self.command(k.code) {
            return;
        }
        if self.tab == 0 {
            self.nodes_key(k);
        } else if let Some(s) = self.shells.get_mut(self.tab - 1) {
            if s.done() {
                if k.code == KeyCode::Enter {
                    self.close_tab();
                }
                return;
            }
            let shift = k.modifiers.contains(KeyModifiers::SHIFT);
            match k.code {
                KeyCode::PageUp if shift => s.scroll_by(s.size.0 as isize / 2),
                KeyCode::PageDown if shift => s.scroll_by(-(s.size.0 as isize / 2)),
                _ => {
                    let app_cursor = s.parser.lock().unwrap().screen().application_cursor();
                    if let Some(bytes) = encode_key(&k, app_cursor) {
                        s.send(&bytes);
                    }
                }
            }
        }
    }

    /// A tab command; false if `code` isn't one.
    fn command(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char(c @ '0'..='9') => {
                let n = c as usize - '0' as usize;
                if n <= self.shells.len() {
                    self.tab = n;
                }
            }
            KeyCode::Char('n') | KeyCode::Right => self.tab = (self.tab + 1) % (self.shells.len() + 1),
            KeyCode::Char('p') | KeyCode::Left => {
                self.tab = (self.tab + self.shells.len()) % (self.shells.len() + 1);
            }
            KeyCode::Char('w') | KeyCode::Char('x') => self.close_tab(),
            KeyCode::Char('d') => {
                let name = self.tab_node();
                if let Some(n) = name {
                    self.desktop(&n);
                }
            }
            KeyCode::Char('?') => self.help(),
            _ => return false,
        }
        true
    }

    fn nodes_key(&mut self, k: KeyEvent) {
        let sel = self.table.selected().unwrap_or(0);
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.table.select(Some(sel.saturating_sub(1))),
            KeyCode::Down | KeyCode::Char('j') => {
                self.table
                    .select(Some((sel + 1).min(self.nodes.len().saturating_sub(1))));
            }
            KeyCode::Enter | KeyCode::Char('s') => {
                if let Some(n) = self.nodes.get(sel).cloned() {
                    self.open_shell(&n, self.user.clone());
                }
            }
            KeyCode::Char('u') => {
                let default = self
                    .nodes
                    .get(sel)
                    .map(|n| self.login_user(&n.name))
                    .unwrap_or_default();
                self.prompt = Some(("Log in as user".into(), default));
            }
            KeyCode::Char('d') => {
                if let Some(n) = self.nodes.get(sel).map(|n| n.name.clone()) {
                    self.desktop(&n);
                }
            }
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char('?') | KeyCode::F(1) => self.help(),
            KeyCode::Char('q') => {
                if self.shells.iter_mut().all(|s| s.done()) {
                    self.quit = true;
                } else {
                    self.prompt = Some(("Close all shells and quit? (y/n)".into(), String::new()));
                }
            }
            _ => {}
        }
    }

    fn prompt_done(&mut self, label: &str, input: &str) {
        if label.starts_with("Close all") {
            if input.eq_ignore_ascii_case("y") {
                self.quit = true;
            }
        } else if label.starts_with("Log in as") && crate::proto::valid_user(input) {
            let sel = self.table.selected().unwrap_or(0);
            if let Some(n) = self.nodes.get(sel).cloned() {
                self.open_shell(&n, Some(input.to_string()));
            }
        }
    }

    fn paste(&mut self, text: &str) {
        if let Some((label, mut input)) = self.prompt.take() {
            input.push_str(text);
            self.prompt = Some((label, input));
            return;
        }
        if let Some(s) = self.current() {
            let bracketed = s.parser.lock().unwrap().screen().bracketed_paste();
            let mut b = vec![];
            if bracketed {
                b.extend_from_slice(b"\x1b[200~");
            }
            b.extend_from_slice(text.replace("\r\n", "\r").replace('\n', "\r").as_bytes());
            if bracketed {
                b.extend_from_slice(b"\x1b[201~");
            }
            s.send(&b);
        }
    }

    fn current(&mut self) -> Option<&mut Shell> {
        if self.tab == 0 {
            None
        } else {
            self.shells.get_mut(self.tab - 1)
        }
    }

    fn tab_node(&self) -> Option<String> {
        if self.tab == 0 {
            let sel = self.table.selected().unwrap_or(0);
            return self.nodes.get(sel).map(|n| n.name.clone());
        }
        let t = &self.shells.get(self.tab - 1)?.title;
        Some(t.split('@').nth(1)?.split(' ').next()?.to_string())
    }

    /// Who a shell on `node` logs in as.
    fn login_user(&self, node: &str) -> String {
        self.user.clone().unwrap_or_else(|| Remote::ssh_config_user(node))
    }

    fn open_shell(&mut self, node: &NodeView, user: Option<String>) {
        let remote = Remote {
            // Empty: ssh picks the user like a plain `ssh node.mesh` does.
            user: user.clone().unwrap_or_default(),
            socks: self.socks,
            timeout: Duration::from_secs(10),
        };
        let cmd = remote.shell(node);
        let title = if node.is_self {
            format!("{}@{} (here)", Remote::default_user(), node.name)
        } else {
            let user = user.unwrap_or_else(|| self.login_user(&node.name));
            format!("{user}@{}", node.name)
        };
        let (rows, cols) = (self.body.height.max(5), self.body.width.max(20));
        match Shell::spawn(title, cmd, rows, cols, self.dirty.clone()) {
            Ok(s) => {
                self.shells.push(s);
                self.tab = self.shells.len();
            }
            Err(e) => self.status = format!("cannot start a shell: {e:#}"),
        }
    }

    fn close_tab(&mut self) {
        if self.tab > 0 && self.tab <= self.shells.len() {
            self.shells.remove(self.tab - 1);
            self.tab -= 1;
        }
    }

    fn desktop(&mut self, node: &str) {
        let Some(n) = self.nodes.iter().find(|n| n.name == node).cloned() else {
            return;
        };
        let user = self
            .current()
            .and_then(|s| s.title.split('@').next().map(String::from))
            .filter(|_| self.tab > 0)
            .unwrap_or_else(|| self.login_user(node));
        let target = crate::desktop::client::Target {
            node: n,
            remote: Remote {
                user: user.clone(),
                socks: self.socks,
                timeout: Duration::from_secs(30),
            },
            session: "auto",
        };
        match crate::desktop::client::start(target, 0) {
            Ok(v) => {
                let mut lines = vec![
                    format!("Desktop of {user}@{node}:"),
                    String::new(),
                    format!("  {}", v.url),
                    String::new(),
                ];
                match crate::desktop::client::ssh_hint(v.port) {
                    Some(h) => lines.extend(h),
                    None => lines.push("Open the link in a browser on this machine.".into()),
                }
                lines.push(String::new());
                lines.push("It stays available until you quit the console. (any key closes this)".into());
                self.popup = Some(lines);
                self.viewers.push(v);
            }
            Err(e) => self.status = format!("desktop: {e:#}"),
        }
    }

    fn help(&mut self) {
        self.popup = Some(
            [
                "meshvpn console - the mesh in your terminal",
                "",
                "Nodes tab:   ↑↓ select   Enter shell   u shell as another user",
                "             d desktop link (browser)   r refresh   q quit",
                "",
                "Anywhere:    Alt+0 nodes, Alt+1..9 shells, Alt+←/→ previous/next",
                "             or Ctrl+B then: 0..9, n, p, w close tab, d desktop, ? help",
                "             (Ctrl+B Ctrl+B sends Ctrl+B to the shell)",
                "In a shell:  Shift+PgUp/PgDn scroll back",
                "",
                "Text selection works as usual in your terminal (no mouse capture).",
            ]
            .map(String::from)
            .to_vec(),
        );
    }

    // ------------------------------------------------------------------ drawing

    fn draw(&mut self, f: &mut Frame) {
        let [top, body, bottom] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1)]).areas(f.area());
        self.body = body;
        // Tabs
        let mut spans = vec![
            Span::styled(" meshvpn ", Style::new().bold().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" "),
        ];
        let mut tabs: Vec<String> = vec![format!("0 Nodes ({})", self.network)];
        tabs.extend(
            self.shells
                .iter()
                .enumerate()
                .map(|(i, s)| format!("{} {}", i + 1, s.title)),
        );
        for (i, t) in tabs.iter().enumerate() {
            let style = if i == self.tab {
                Style::new().bold().fg(Color::Black).bg(Color::White)
            } else {
                Style::new().fg(Color::Gray)
            };
            spans.push(Span::styled(format!(" {t} "), style));
            spans.push(Span::raw(" "));
        }
        f.render_widget(Line::from(spans), top);

        if self.tab == 0 {
            self.draw_nodes(f, body);
        } else if let Some(s) = self.shells.get(self.tab - 1) {
            draw_screen(f, body, s);
        }

        // Status line
        let help = if self.prefix {
            "Ctrl+B: 0-9 tab · n/p next/prev · w close · d desktop · ? help".to_string()
        } else if self.tab == 0 {
            "Enter shell · u as user · d desktop · Alt+1..9 / Ctrl+B n tabs · ? help · q quit".to_string()
        } else {
            "Alt+0 / Ctrl+B 0 nodes · Ctrl+B n/p tabs · Ctrl+B w close · Ctrl+B d desktop · Shift+PgUp scroll"
                .to_string()
        };
        let text = if self.status.is_empty() {
            help
        } else {
            std::mem::take(&mut self.status)
        };
        f.render_widget(Paragraph::new(text).style(Style::new().fg(Color::DarkGray)), bottom);

        if let Some((label, input)) = &self.prompt {
            let area = centered(f.area(), 60, 3);
            f.render_widget(Clear, area);
            f.render_widget(
                Paragraph::new(format!("{input}▏")).block(Block::bordered().title(format!(" {label} "))),
                area,
            );
        } else if let Some(lines) = &self.popup {
            let w = lines.iter().map(|l| l.chars().count()).max().unwrap_or(20) as u16 + 4;
            let area = centered(f.area(), w, lines.len() as u16 + 2);
            f.render_widget(Clear, area);
            f.render_widget(
                Paragraph::new(lines.iter().map(|l| Line::raw(l.clone())).collect::<Vec<_>>())
                    .wrap(Wrap { trim: false })
                    .block(Block::bordered()),
                area,
            );
        }
    }

    fn draw_nodes(&mut self, f: &mut Frame, area: Rect) {
        let [list, detail] = Layout::vertical([Constraint::Fill(1), Constraint::Length(7)]).areas(area);
        let rows = self.nodes.iter().map(|n| {
            let dot = if n.is_self {
                Span::styled("◆", Style::new().fg(Color::Cyan))
            } else if n.online {
                Span::styled("●", Style::new().fg(Color::Green))
            } else {
                Span::styled("○", Style::new().fg(Color::DarkGray))
            };
            let gpus = n.inventory.as_ref().map(|i| i.gpus.len()).unwrap_or(0);
            let gpu = if gpus > 0 {
                format!("{}/{gpus} free", n.free_gpus())
            } else {
                "-".into()
            };
            let path = if n.is_self {
                "this machine".to_string()
            } else {
                n.path.clone()
            };
            Row::new(vec![
                Cell::from(Line::from(vec![dot, Span::raw(" "), Span::raw(n.name.clone())])),
                Cell::from(n.ip.to_string()),
                Cell::from(path),
                Cell::from(
                    n.rtt_ms
                        .filter(|_| !n.is_self)
                        .map(|r| format!("{r} ms"))
                        .unwrap_or_default(),
                ),
                Cell::from(gpu),
                Cell::from(n.version.clone()),
                Cell::from(n.tags.join(",")),
            ])
            .style(if n.online || n.is_self {
                Style::new()
            } else {
                Style::new().fg(Color::DarkGray)
            })
        });
        let table = Table::new(
            rows,
            [
                Constraint::Min(18),
                Constraint::Length(16),
                Constraint::Min(22),
                Constraint::Length(8),
                Constraint::Length(10),
                Constraint::Length(8),
                Constraint::Min(8),
            ],
        )
        .header(
            Row::new(["NODE", "MESH IP", "PATH", "RTT", "GPUS", "VERSION", "TAGS"])
                .style(Style::new().bold().fg(Color::Cyan)),
        )
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .block(Block::bordered().title(format!(
            " {} nodes · shells as {} ",
            self.nodes.len(),
            self.user.as_deref().unwrap_or("with your ssh settings")
        )));
        f.render_stateful_widget(table, list, &mut self.table);

        let sel = self.table.selected().and_then(|i| self.nodes.get(i));
        let text = match sel {
            None => vec![Line::raw("No nodes known yet.")],
            Some(n) => {
                let mut l = vec![Line::from(vec![
                    Span::styled(n.name.clone(), Style::new().bold()),
                    Span::raw(format!("  {}.mesh  {}", n.name, n.ip)),
                ])];
                if let Some(i) = &n.inventory {
                    l.push(Line::raw(format!(
                        "{} {} · {} cores {} · {} GB RAM · {} GB disk free",
                        i.os,
                        i.arch,
                        i.cpu_cores,
                        i.cpu_model,
                        i.mem_total_mb / 1024,
                        i.disk_free_gb
                    )));
                    for g in i.gpus.iter().take(3) {
                        l.push(Line::raw(format!(
                            "GPU {}: {} · {}/{} MB · {}%",
                            g.index, g.name, g.mem_used_mb, g.mem_total_mb, g.util_pct
                        )));
                    }
                }
                if !n.lan.is_empty() {
                    l.push(Line::raw(format!("LAN: {}", n.lan.join(", "))));
                }
                l
            }
        };
        f.render_widget(Paragraph::new(text).block(Block::bordered()), detail);
    }
}

impl Shell {
    fn scroll_by(&mut self, delta: isize) {
        let mut p = self.parser.lock().unwrap();
        let next = (self.scroll as isize + delta).max(0) as usize;
        p.screen_mut().set_scrollback(next);
        self.scroll = p.screen().scrollback();
    }
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(area.x + (area.width - w) / 2, area.y + (area.height - h) / 2, w, h)
}

fn color(c: vt100::Color) -> Color {
    match c {
        vt100::Color::Default => Color::Reset,
        vt100::Color::Idx(i) => Color::Indexed(i),
        vt100::Color::Rgb(r, g, b) => Color::Rgb(r, g, b),
    }
}

/// The shell's screen into the frame, cell by cell.
fn draw_screen(f: &mut Frame, area: Rect, s: &Shell) {
    let parser = s.parser.lock().unwrap();
    let screen = parser.screen();
    let buf = f.buffer_mut();
    for row in 0..area.height {
        for col in 0..area.width {
            let Some(cell) = screen.cell(row, col) else { continue };
            if cell.is_wide_continuation() {
                continue;
            }
            let mut style = Style::new().fg(color(cell.fgcolor())).bg(color(cell.bgcolor()));
            if cell.bold() {
                style = style.add_modifier(Modifier::BOLD);
            }
            if cell.italic() {
                style = style.add_modifier(Modifier::ITALIC);
            }
            if cell.underline() {
                style = style.add_modifier(Modifier::UNDERLINED);
            }
            if cell.inverse() {
                style = style.add_modifier(Modifier::REVERSED);
            }
            let text = if cell.has_contents() { cell.contents() } else { " " };
            if let Some(c) = buf.cell_mut((area.x + col, area.y + row)) {
                c.set_symbol(text).set_style(style);
            }
        }
    }
    if s.exited.load(Ordering::Relaxed) {
        let msg = " session ended - Enter closes this tab ";
        let w = msg.chars().count() as u16;
        if area.width > w {
            let r = Rect::new(
                area.x + (area.width - w) / 2,
                area.y + area.height.saturating_sub(1),
                w,
                1,
            );
            f.render_widget(
                Paragraph::new(msg).style(Style::new().fg(Color::Black).bg(Color::Yellow)),
                r,
            );
        }
    } else if s.scroll == 0 && !screen.hide_cursor() {
        let (r, c) = screen.cursor_position();
        f.set_cursor_position((area.x + c, area.y + r));
    }
}

/// Bytes a terminal sends for a key.
fn encode_key(k: &KeyEvent, app_cursor: bool) -> Option<Vec<u8>> {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    let alt = k.modifiers.contains(KeyModifiers::ALT);
    let shift = k.modifiers.contains(KeyModifiers::SHIFT);
    let modifier = 1 + shift as u8 + 2 * alt as u8 + 4 * ctrl as u8;
    let csi = |final_: &str, plain_ss3: bool| -> Vec<u8> {
        if modifier > 1 {
            format!("\x1b[1;{modifier}{final_}").into_bytes()
        } else if plain_ss3 {
            format!("\x1bO{final_}").into_bytes()
        } else {
            format!("\x1b[{final_}").into_bytes()
        }
    };
    let tilde = |n: u8| -> Vec<u8> {
        if modifier > 1 {
            format!("\x1b[{n};{modifier}~").into_bytes()
        } else {
            format!("\x1b[{n}~").into_bytes()
        }
    };
    let mut out = match k.code {
        KeyCode::Char(c) if ctrl => {
            let b = match c.to_ascii_lowercase() {
                c @ 'a'..='z' => c as u8 - b'a' + 1,
                '@' | ' ' | '2' => 0,
                '[' | '3' => 27,
                '\\' | '4' => 28,
                ']' | '5' => 29,
                '^' | '6' => 30,
                '_' | '-' | '7' => 31,
                '?' | '8' => 127,
                _ => return None,
            };
            vec![b]
        }
        KeyCode::Char(c) => c.to_string().into_bytes(),
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Backspace => vec![if ctrl { 8 } else { 127 }],
        KeyCode::Esc => vec![27],
        KeyCode::Up => csi("A", app_cursor),
        KeyCode::Down => csi("B", app_cursor),
        KeyCode::Right => csi("C", app_cursor),
        KeyCode::Left => csi("D", app_cursor),
        KeyCode::Home => csi("H", app_cursor),
        KeyCode::End => csi("F", app_cursor),
        KeyCode::Insert => tilde(2),
        KeyCode::Delete => tilde(3),
        KeyCode::PageUp => tilde(5),
        KeyCode::PageDown => tilde(6),
        KeyCode::F(n @ 1..=4) => {
            if modifier > 1 {
                format!("\x1b[1;{modifier}{}", (b'P' + n - 1) as char).into_bytes()
            } else {
                format!("\x1bO{}", (b'P' + n - 1) as char).into_bytes()
            }
        }
        KeyCode::F(n @ 5..=12) => tilde([15, 17, 18, 19, 20, 21, 23, 24][n as usize - 5]),
        _ => return None,
    };
    // Alt+key: ESC prefix (for plain characters and the simple keys).
    if alt && matches!(k.code, KeyCode::Char(_) | KeyCode::Enter | KeyCode::Backspace) {
        out.insert(0, 27);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(code: KeyCode, m: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, m)
    }

    #[test]
    fn keys_encode_like_xterm() {
        assert_eq!(
            encode_key(&k(KeyCode::Char('c'), KeyModifiers::CONTROL), false),
            Some(vec![3])
        );
        assert_eq!(
            encode_key(&k(KeyCode::Up, KeyModifiers::NONE), false),
            Some(b"\x1b[A".to_vec())
        );
        assert_eq!(
            encode_key(&k(KeyCode::Up, KeyModifiers::NONE), true),
            Some(b"\x1bOA".to_vec())
        );
        assert_eq!(
            encode_key(&k(KeyCode::Right, KeyModifiers::CONTROL), false),
            Some(b"\x1b[1;5C".to_vec())
        );
        assert_eq!(
            encode_key(&k(KeyCode::Char('x'), KeyModifiers::ALT), false),
            Some(b"\x1bx".to_vec())
        );
        assert_eq!(
            encode_key(&k(KeyCode::F(5), KeyModifiers::NONE), false),
            Some(b"\x1b[15~".to_vec())
        );
        assert_eq!(
            encode_key(&k(KeyCode::Char('ä'), KeyModifiers::NONE), false),
            Some("ä".as_bytes().to_vec())
        );
    }
}
