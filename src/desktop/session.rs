//! A desktop session: one per user, running as that user. It starts the bundled Xvfb and is the
//! X client that does everything else: window manager, screen capture (only what changed),
//! input (XTest), clipboard and cursor. Browsers attach over a Unix socket (`meshvpn desktop
//! attach`, reached through SSH); the session keeps running when they detach.

use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::damage::{self, ConnectionExt as _};
use x11rb::protocol::randr::{self, ConnectionExt as _};
use x11rb::protocol::shm::{self, ConnectionExt as _};
use x11rb::protocol::xfixes::{self, ConnectionExt as _};
use x11rb::protocol::xproto::*;
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::{DefaultStream, RustConnection};
use x11rb::wrapper::ConnectionExt as _;

use super::bundle::{self, Bundle};
use super::proto::*;

/// Largest screen: Xvfb allocates this once; RandR shrinks the visible part to the browser.
const MAX_W: u16 = 3840;
const MAX_H: u16 = 2160;
const TILE: usize = 64;
const FRAME_INTERVAL: Duration = Duration::from_millis(33);

x11rb::atom_manager! {
    pub Atoms: AtomsCookie {
        WM_PROTOCOLS,
        WM_DELETE_WINDOW,
        WM_STATE,
        UTF8_STRING,
        _NET_WM_NAME,
        _NET_ACTIVE_WINDOW,
        _NET_SUPPORTED,
        _NET_SUPPORTING_WM_CHECK,
        _NET_CLIENT_LIST,
        _NET_WM_WINDOW_TYPE,
        _NET_WM_WINDOW_TYPE_DIALOG,
        _NET_WM_WINDOW_TYPE_SPLASH,
        _NET_WM_WINDOW_TYPE_UTILITY,
        _NET_WM_WINDOW_TYPE_DOCK,
        _NET_WM_WINDOW_TYPE_DESKTOP,
        _NET_WM_STATE,
        _NET_CLOSE_WINDOW,
        CLIPBOARD,
        TARGETS,
        TEXT,
        MESHVPN_SEL,
    }
}

// ---------------------------------------------------------------------------------------------
// Files of a user's session

/// `$XDG_RUNTIME_DIR/meshvpn-desktop`, else `/tmp/meshvpn-desktop-<uid>` (0700, ours).
pub fn runtime_dir() -> Result<PathBuf> {
    let uid = unsafe { libc::geteuid() };
    let dir = match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        Some(r) if Path::new(&r).is_dir() => PathBuf::from(r).join("meshvpn-desktop"),
        _ => PathBuf::from(format!("/tmp/meshvpn-desktop-{uid}")),
    };
    match std::fs::create_dir(&dir) {
        Ok(()) => std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
    }
    // Someone else's directory in /tmp would let them see the session: refuse.
    let m = std::fs::symlink_metadata(&dir)?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o077 != 0 {
        bail!("{} is not a private directory of this user", dir.display());
    }
    Ok(dir)
}

pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join("session.sock")
}

/// Xauthority with one wildcard entry (any host, any display) for `cookie`.
fn write_xauthority(path: &Path, cookie: &[u8; 16]) -> Result<()> {
    let mut b = vec![];
    let mut field = |v: &[u8]| {
        b.extend_from_slice(&(v.len() as u16).to_be_bytes());
        b.extend_from_slice(v);
    };
    let mut out = 0xffffu16.to_be_bytes().to_vec(); // FamilyWild
    field(b"");
    field(b"");
    field(b"MIT-MAGIC-COOKIE-1");
    field(cookie);
    out.extend(b);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, out)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

/// Fonts for applications: the system's, plus the bundled ones (bare images often have none).
fn write_fonts_conf(path: &Path, bundle: &Bundle, cache: &Path) -> Result<()> {
    let text = format!(
        "<?xml version=\"1.0\"?>\n<!DOCTYPE fontconfig SYSTEM \"fonts.dtd\">\n<fontconfig>\n\
         <include ignore_missing=\"yes\">/etc/fonts/fonts.conf</include>\n\
         <dir>{}</dir>\n<cachedir>{}</cachedir>\n</fontconfig>\n",
        bundle.fonts_dir().display(),
        cache.display()
    );
    std::fs::write(path, text)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// `meshvpn desktop attach`: stdin/stdout <-> the user's session (started if needed)

/// Desktop flavour: meshvpn's own window manager, or Xfce if the system has it.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    Plain,
    Xfce,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Plain => "plain",
            Mode::Xfce => "xfce",
        }
    }
}

/// Xfce is installed (its session manager is in PATH).
pub fn has_xfce() -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("xfce4-session").is_file()))
        .unwrap_or(false)
}

/// "auto" (Xfce if installed), "xfce" or "plain".
pub fn resolve_mode(want: &str) -> Result<Mode> {
    match want {
        "plain" => Ok(Mode::Plain),
        "xfce" if has_xfce() => Ok(Mode::Xfce),
        "xfce" => bail!(
            "Xfce is not installed on this machine - install it with `sudo meshvpn desktop setup --xfce` there, \
             or use the built-in desktop (--plain)"
        ),
        _ if has_xfce() => Ok(Mode::Xfce),
        _ => Ok(Mode::Plain),
    }
}

pub fn attach(want: &str) -> Result<()> {
    let notice = |text: &str| {
        let mut out = std::io::stdout();
        let _ = out.write_all(&frame(S_NOTICE, text.as_bytes()));
        let _ = out.flush();
    };
    let dir = match runtime_dir() {
        Ok(d) => d,
        Err(e) => {
            notice(&format!("{e:#}"));
            return Err(e);
        }
    };
    let sock = socket_path(&dir);
    let stream = match std::os::unix::net::UnixStream::connect(&sock) {
        Ok(s) => {
            // A running session keeps its flavour; say so if another one was asked for (or Xfce
            // was installed after the session started). Sessions before 0.13 were all plain.
            let running = std::fs::read_to_string(dir.join("mode")).unwrap_or_else(|_| "plain".into());
            let running = running.trim();
            let explicit = (want == "xfce" || want == "plain") && running != want;
            if explicit || (want == "auto" && running != "xfce" && has_xfce()) {
                let other = if running == "xfce" {
                    "the built-in desktop"
                } else {
                    "Xfce"
                };
                notice(&format!(
                    "This desktop session was started with {} and keeps it. To get {other}: End session (⏻, closes \
                     its applications), then reconnect.",
                    if running == "xfce" {
                        "Xfce"
                    } else {
                        "the built-in desktop"
                    }
                ));
            }
            s
        }
        Err(_) => {
            let mode = match resolve_mode(want) {
                Ok(m) => m,
                Err(e) => {
                    notice(&format!("{e:#}"));
                    return Err(e);
                }
            };
            if bundle::find().is_none() {
                notice("first use: installing the desktop components (about 5 MB)...");
                if let Err(e) = bundle::setup(None) {
                    notice(&format!("{e:#}"));
                    return Err(e);
                }
            }
            start_detached(&dir, mode)?;
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Ok(s) = std::os::unix::net::UnixStream::connect(&sock) {
                    break s;
                }
                if Instant::now() > deadline {
                    let log = std::fs::read_to_string(dir.join("session.log")).unwrap_or_default();
                    let tail: Vec<&str> = log
                        .lines()
                        .rev()
                        .take(8)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    let msg = format!("the desktop session did not start:\n{}", tail.join("\n"));
                    notice(&msg);
                    bail!("{msg}");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };
    // Plain copies both ways; the session speaks the protocol.
    let mut to_session = stream.try_clone()?;
    let mut from_session = stream;
    let up = std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let _ = std::io::copy(&mut stdin, &mut to_session);
        let _ = to_session.shutdown(std::net::Shutdown::Write);
    });
    let mut stdout = std::io::stdout().lock();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match from_session.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stdout.write_all(&buf[..n]).and_then(|_| stdout.flush()).is_err() {
                    break;
                }
            }
        }
    }
    drop(up);
    Ok(())
}

fn start_detached(dir: &Path, mode: Mode) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let exe = crate::update::current_exe()?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("session.log"))?;
    let mut c = std::process::Command::new(exe);
    c.args(["desktop", "session", "--session", mode.name()])
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    c.spawn().context("starting the desktop session")?;
    Ok(())
}

/// `meshvpn desktop stop`: ends the session of this user (closes its apps).
pub fn stop() -> Result<bool> {
    let sock = socket_path(&runtime_dir()?);
    let Ok(mut s) = std::os::unix::net::UnixStream::connect(&sock) else {
        return Ok(false);
    };
    s.write_all(&frame(C_STOP, b""))?;
    Ok(true)
}

// ---------------------------------------------------------------------------------------------
// `meshvpn desktop session`

enum Cmd {
    Join(u64, tokio::sync::mpsc::Sender<Vec<u8>>),
    Leave(u64),
    Msg(u64, Vec<u8>),
}

pub fn run(want: &str) -> Result<()> {
    let mode = resolve_mode(want)?;
    let dir = runtime_dir()?;
    let sock = socket_path(&dir);
    if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
        bail!("a desktop session is already running");
    }
    let bundle = bundle::find().ok_or_else(|| anyhow!("desktop components missing: run meshvpn desktop setup"))?;
    let mut cookie = [0u8; 16];
    cookie.copy_from_slice(&crate::keys::random32()[..16]);
    let xauth = dir.join("Xauthority");
    write_xauthority(&xauth, &cookie)?;
    let fonts_conf = dir.join("fonts.conf");
    let font_cache = dir.join("fontcache");
    write_fonts_conf(&fonts_conf, &bundle, &font_cache)?;

    let (mut xvfb, dpy) = start_xvfb(&bundle, &xauth)?;
    info!("Xvfb running as display :{dpy}");
    let path = format!("/tmp/.X11-unix/X{dpy}");
    let unix = std::os::unix::net::UnixStream::connect(&path).with_context(|| format!("connecting to {path}"))?;
    let (stream, _) = DefaultStream::from_unix_stream(unix)?;
    let conn =
        RustConnection::connect_to_stream_with_auth_info(stream, 0, b"MIT-MAGIC-COOKIE-1".to_vec(), cookie.to_vec())
            .context("connecting to Xvfb")?;

    let env = AppEnv {
        display: format!(":{dpy}"),
        xauthority: xauth.clone(),
        fonts_conf: fonts_conf.clone(),
    };
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    let mut desk = Desk::new(conn, env, mode)?;
    std::fs::write(dir.join("mode"), mode.name())?;
    if mode == Mode::Xfce {
        prepare_xfce();
        // With D-Bus if available (Xfce's settings and panel want a session bus).
        let line = if which("dbus-launch") {
            "exec dbus-launch --exit-with-session xfce4-session"
        } else {
            "exec xfce4-session"
        };
        desk.session = Some(desk.spawn(line).context("starting Xfce")?);
        info!("Xfce started");
    }

    // The socket for attaching browsers.
    let _ = std::fs::remove_file(&sock);
    let listener = std::os::unix::net::UnixListener::bind(&sock)?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let tx = cmd_tx.clone();
    rt.spawn(async move {
        listener.set_nonblocking(true).ok();
        let Ok(listener) = tokio::net::UnixListener::from_std(listener) else {
            return;
        };
        let mut next = 1u64;
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let id = next;
            next += 1;
            tokio::spawn(serve_client(stream, id, tx.clone()));
        }
    });

    let result = desk.run(cmd_rx);
    let _ = std::fs::remove_file(&sock);
    let _ = xvfb.kill();
    let _ = xvfb.wait();
    drop(rt);
    result
}

async fn serve_client(stream: tokio::net::UnixStream, id: u64, tx: mpsc::Sender<Cmd>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut r, mut w) = stream.into_split();
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    if tx.send(Cmd::Join(id, out_tx)).is_err() {
        return;
    }
    let writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if w.write_all(&m).await.is_err() {
                break;
            }
        }
    });
    let mut buf = vec![];
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                let Ok(msgs) = split(&mut buf) else { break };
                for m in msgs {
                    if tx.send(Cmd::Msg(id, m)).is_err() {
                        break;
                    }
                }
            }
        }
    }
    let _ = tx.send(Cmd::Leave(id));
    writer.abort();
}

fn which(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(cmd).is_file()))
        .unwrap_or(false)
}

/// First start of Xfce for this user: the default panel without asking, no compositing
/// (it only costs CPU on a virtual screen). Existing settings are left alone.
fn prepare_xfce() {
    let Some(home) = std::env::var_os("HOME") else { return };
    let dir = PathBuf::from(home).join(".config/xfce4/xfconf/xfce-perchannel-xml");
    let _ = std::fs::create_dir_all(&dir);
    let panel = dir.join("xfce4-panel.xml");
    if !panel.exists() {
        for default in ["/etc/xdg/xfce4/panel/default.xml", "/usr/share/xfce4/panel/default.xml"] {
            if std::fs::copy(default, &panel).is_ok() {
                break;
            }
        }
    }
    let wm = dir.join("xfwm4.xml");
    if !wm.exists() {
        let _ = std::fs::write(
            wm,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<channel name=\"xfwm4\" version=\"1.0\">\n  \
             <property name=\"general\" type=\"empty\">\n    \
             <property name=\"use_compositing\" type=\"bool\" value=\"false\"/>\n  </property>\n</channel>\n",
        );
    }
}

fn start_xvfb(bundle: &Bundle, xauth: &Path) -> Result<(std::process::Child, u32)> {
    use std::os::unix::process::CommandExt;
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    let (rfd, wfd) = (fds[0], fds[1]);
    let mut c = std::process::Command::new(bundle.xvfb());
    c.args(["-displayfd", "3", "-auth"])
        .arg(xauth)
        .args(["-nolisten", "tcp", "-screen", "0"])
        .arg(format!("{MAX_W}x{MAX_H}x24"))
        .args(["-fp", "built-ins", "-dpi", "96", "+extension", "RANDR", "-xkbdir"])
        .arg(bundle.xkb_dir())
        .env("MESHVPN_XKB_BIN", bundle.bin_dir())
        .stdin(std::process::Stdio::null());
    unsafe {
        c.pre_exec(move || {
            if libc::dup2(wfd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Ends with the session, however that ends.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let child = c.spawn().context("starting Xvfb")?;
    unsafe { libc::close(wfd) };
    let mut pipe = unsafe { std::fs::File::from_raw_fd(rfd) };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        let mut b = [0u8; 1];
        while pipe.read(&mut b).map(|n| n == 1).unwrap_or(false) {
            if b[0] == b'\n' {
                break;
            }
            s.push(b[0] as char);
        }
        let _ = tx.send(s);
    });
    let display = rx
        .recv_timeout(Duration::from_secs(20))
        .map_err(|_| anyhow!("Xvfb did not start (see the session log)"))?;
    let display: u32 = display
        .trim()
        .parse()
        .map_err(|_| anyhow!("Xvfb did not start (see the session log)"))?;
    Ok((child, display))
}

// ---------------------------------------------------------------------------------------------
// The X side: window manager, capture, input

struct AppEnv {
    display: String,
    xauthority: PathBuf,
    fonts_conf: PathBuf,
}

struct Client {
    id: u64,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    inflight: u32,
}

struct Managed {
    win: Window,
    title: String,
    floating: bool,
}

struct Shm {
    seg: shm::Seg,
    addr: *mut u8,
    size: usize,
}

impl Drop for Shm {
    fn drop(&mut self) {
        unsafe { libc::shmdt(self.addr as *const libc::c_void) };
    }
}

struct Desk {
    conn: RustConnection,
    root: Window,
    atoms: Atoms,
    env: AppEnv,
    w: u16,
    h: u16,
    shm: Option<Shm>,
    damage: damage::Damage,
    prev: Vec<u8>,
    dirty: bool,
    full: bool,
    last_frame: Instant,
    clients: Vec<Client>,
    windows: Vec<Managed>,
    active: Option<Window>,
    support: Window,
    // input
    keysyms: HashMap<u32, (u8, usize)>,
    spare: Vec<u8>,
    char_keys: HashMap<u32, u8>,
    pressed: HashMap<u32, u8>,
    shift: bool,
    buttons: u8,
    // clipboard and cursor
    clip_out: Option<String>,
    cursor: Option<Vec<u8>>,
    apps: Vec<u8>,
    children: Vec<std::process::Child>,
    stop: bool,
    /// Xfce: its window manager manages the windows, meshvpn only follows its client list.
    external_wm: bool,
    /// The desktop session (Xfce); when it ends (log out), so does this session.
    session: Option<std::process::Child>,
}

impl Desk {
    fn new(conn: RustConnection, env: AppEnv, mode: Mode) -> Result<Self> {
        let screen = conn.setup().roots[0].clone();
        let root = screen.root;
        let atoms = Atoms::new(&conn)?.reply()?;
        conn.damage_query_version(1, 1)?.reply().context("DAMAGE extension")?;
        conn.xfixes_query_version(5, 0)?.reply().context("XFIXES extension")?;
        let _ = conn.randr_query_version(1, 3)?.reply();
        let external_wm = mode == Mode::Xfce;

        if external_wm {
            // Follow the window manager's client list and active window.
            conn.change_window_attributes(
                root,
                &ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE | EventMask::STRUCTURE_NOTIFY),
            )?;
        } else {
            // Become the window manager.
            conn.change_window_attributes(
                root,
                &ChangeWindowAttributesAux::new().event_mask(
                    EventMask::SUBSTRUCTURE_REDIRECT | EventMask::SUBSTRUCTURE_NOTIFY | EventMask::STRUCTURE_NOTIFY,
                ),
            )?
            .check()
            .context("another window manager is running")?;
        }
        let support = conn.generate_id()?;
        conn.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            support,
            root,
            -10,
            -10,
            1,
            1,
            0,
            WindowClass::INPUT_OUTPUT,
            x11rb::COPY_FROM_PARENT,
            &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        )?;
        if !external_wm {
            conn.change_property32(
                PropMode::REPLACE,
                root,
                atoms._NET_SUPPORTING_WM_CHECK,
                AtomEnum::WINDOW,
                &[support],
            )?;
            conn.change_property32(
                PropMode::REPLACE,
                support,
                atoms._NET_SUPPORTING_WM_CHECK,
                AtomEnum::WINDOW,
                &[support],
            )?;
            conn.change_property8(
                PropMode::REPLACE,
                support,
                atoms._NET_WM_NAME,
                atoms.UTF8_STRING,
                b"meshvpn",
            )?;
            conn.change_property32(
                PropMode::REPLACE,
                root,
                atoms._NET_SUPPORTED,
                AtomEnum::ATOM,
                &[
                    atoms._NET_ACTIVE_WINDOW,
                    atoms._NET_CLIENT_LIST,
                    atoms._NET_WM_NAME,
                    atoms._NET_CLOSE_WINDOW,
                    atoms._NET_SUPPORTING_WM_CHECK,
                ],
            )?;
        }
        // A plain dark background instead of X's stipple (Xfce paints its own).
        conn.change_window_attributes(root, &ChangeWindowAttributesAux::new().background_pixel(0x2b2f36))?;
        conn.clear_area(false, root, 0, 0, 0, 0)?;

        let damage = conn.generate_id()?;
        conn.damage_create(damage, root, damage::ReportLevel::NON_EMPTY)?;
        conn.xfixes_select_cursor_input(root, xfixes::CursorNotifyMask::DISPLAY_CURSOR)?;
        conn.xfixes_select_selection_input(
            support,
            atoms.CLIPBOARD,
            xfixes::SelectionEventMask::SET_SELECTION_OWNER,
        )?;
        conn.flush()?;

        let shm = attach_shm(&conn).ok();
        if shm.is_none() {
            info!("MIT-SHM not usable: capturing without shared memory (slower)");
        }
        let mut d = Desk {
            conn,
            root,
            atoms,
            env,
            w: 1280,
            h: 800,
            shm,
            damage,
            prev: vec![],
            dirty: true,
            full: true,
            last_frame: Instant::now(),
            clients: vec![],
            windows: vec![],
            active: None,
            support,
            keysyms: HashMap::new(),
            spare: vec![],
            char_keys: HashMap::new(),
            pressed: HashMap::new(),
            shift: false,
            buttons: 0,
            clip_out: None,
            cursor: None,
            apps: frame(S_APPS, &serde_json::to_vec(&list_apps()).unwrap_or_default()),
            children: vec![],
            stop: false,
            external_wm,
            session: None,
        };
        d.load_keymap()?;
        d.resize(1280, 800);
        d.update_cursor();
        Ok(d)
    }

    fn run(&mut self, rx: mpsc::Receiver<Cmd>) -> Result<()> {
        let mut last_reap = Instant::now();
        while !self.stop {
            let mut busy = false;
            loop {
                match rx.try_recv() {
                    Ok(cmd) => {
                        busy = true;
                        self.command(cmd);
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
                }
            }
            while let Some(ev) = self.conn.poll_for_event()? {
                busy = true;
                self.event(ev);
            }
            if self.dirty
                && !self.clients.is_empty()
                && self.last_frame.elapsed() >= FRAME_INTERVAL
                && self.clients.iter().all(|c| c.inflight < 2)
            {
                busy = true;
                self.send_frame();
            }
            self.conn.flush()?;
            if last_reap.elapsed() > Duration::from_secs(2) {
                self.children.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
                if let Some(s) = &mut self.session
                    && !matches!(s.try_wait(), Ok(None))
                {
                    self.session = None;
                    // A window manager that registered itself means Xfce was up: this is a log
                    // out. Without one, Xfce failed to start.
                    let wm_was_up = self
                        .conn
                        .get_property(
                            false,
                            self.root,
                            self.atoms._NET_SUPPORTING_WM_CHECK,
                            AtomEnum::WINDOW,
                            0,
                            1,
                        )
                        .ok()
                        .and_then(|c| c.reply().ok())
                        .and_then(|r| r.value32().and_then(|mut v| v.next()))
                        .is_some_and(|w| w != 0);
                    if !wm_was_up {
                        // Xfce gave up right away: keep the session with the built-in desktop.
                        warn!("Xfce ended right after starting - using the built-in desktop");
                        if let Err(e) = self.become_wm() {
                            warn!("taking over the windows: {e:#}");
                        }
                        let msg = frame(
                            S_NOTICE,
                            "Xfce stopped right after starting, so this is the built-in desktop. The reason is in \
                             the session log on the node (meshvpn-desktop*/session.log in $XDG_RUNTIME_DIR or /tmp)."
                                .as_bytes(),
                        );
                        self.broadcast(&msg);
                    } else {
                        info!("the desktop session ended (logged out)");
                        self.stop = true;
                    }
                }
                last_reap = Instant::now();
            }
            if !busy {
                std::thread::sleep(Duration::from_millis(4));
            }
        }
        info!("session stopped");
        Ok(())
    }

    // ----------------------------------------------------------------------- clients

    fn send_to(&mut self, id: u64, msg: Vec<u8>) {
        if let Some(c) = self.clients.iter().find(|c| c.id == id) {
            let _ = c.tx.try_send(msg);
        }
    }

    fn broadcast(&mut self, msg: &[u8]) {
        self.clients.retain(|c| c.tx.try_send(msg.to_vec()).is_ok());
    }

    fn command(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Join(id, tx) => {
                let c = Client { id, tx, inflight: 0 };
                let mut hello = frame(S_INIT, &[self.w.to_le_bytes(), self.h.to_le_bytes()].concat());
                hello.extend(self.windows_msg());
                // Apps installed since the session started show up too.
                self.apps = frame(S_APPS, &serde_json::to_vec(&list_apps()).unwrap_or_default());
                hello.extend(self.apps.clone());
                if let Some(cur) = &self.cursor {
                    hello.extend(cur.clone());
                }
                if c.tx.try_send(hello).is_ok() {
                    self.clients.push(c);
                }
                self.full = true;
                self.dirty = true;
            }
            Cmd::Leave(id) => self.clients.retain(|c| c.id != id),
            Cmd::Msg(id, m) => {
                let (kind, p) = (m[0], &m[5..]);
                if let Err(e) = self.input(id, kind, p) {
                    debug!("input: {e:#}");
                }
            }
        }
    }

    fn input(&mut self, from: u64, kind: u8, p: &[u8]) -> Result<()> {
        match kind {
            C_ACK => {
                if let Some(c) = self.clients.iter_mut().find(|c| c.id == from) {
                    c.inflight = c.inflight.saturating_sub(1);
                }
            }
            C_REFRESH => {
                self.full = true;
                self.dirty = true;
            }
            C_RESIZE => self.resize(u16_at(p, 0), u16_at(p, 2)),
            C_POINTER => self.pointer(u16_at(p, 0), u16_at(p, 2), p.get(4).copied().unwrap_or(0))?,
            C_WHEEL => {
                let dx = p.first().copied().unwrap_or(0) as i8;
                let dy = p.get(1).copied().unwrap_or(0) as i8;
                for (n, plus, minus) in [(dy, 5u8, 4u8), (dx, 7, 6)] {
                    let b = if n > 0 { plus } else { minus };
                    for _ in 0..n.unsigned_abs().min(20) {
                        self.conn
                            .xtest_fake_input(BUTTON_PRESS_EVENT, b, 0, self.root, 0, 0, 0)?;
                        self.conn
                            .xtest_fake_input(BUTTON_RELEASE_EVENT, b, 0, self.root, 0, 0, 0)?;
                    }
                }
            }
            C_KEY => {
                let down = p.first().copied().unwrap_or(0) == 1;
                let is_char = p.get(1).copied().unwrap_or(0) == 1;
                self.key(down, is_char, u32_at(p, 2))?;
            }
            C_CLIPBOARD => {
                let text = String::from_utf8_lossy(p).into_owned();
                self.clip_out = Some(text);
                for sel in [self.atoms.CLIPBOARD, AtomEnum::PRIMARY.into()] {
                    self.conn.set_selection_owner(self.support, sel, x11rb::CURRENT_TIME)?;
                }
            }
            C_ACTIVATE => self.activate(u32_at(p, 0))?,
            C_CLOSE => self.close(u32_at(p, 0))?,
            C_LAUNCH => {
                let line = String::from_utf8_lossy(p).trim().to_string();
                if !line.is_empty() {
                    self.launch(&line);
                }
            }
            C_STOP => self.stop = true,
            C_FILES => {
                let msg = files::list(&String::from_utf8_lossy(p));
                self.send_to(from, msg);
            }
            C_FILE_READ => {
                let id = u32_at(p, 0);
                let path = String::from_utf8_lossy(p.get(4..).unwrap_or_default()).into_owned();
                if let Some(c) = self.clients.iter().find(|c| c.id == from) {
                    files::read(id, path, c.tx.clone());
                }
            }
            C_FILE_WRITE => {
                if let (id, Some(r)) = files::write(p) {
                    self.send_to(from, files::done(id, r));
                }
            }
            C_FILE_OP => {
                let (id, r) = files::op(p);
                self.send_to(from, files::done(id, r));
            }
            _ => {}
        }
        Ok(())
    }

    fn launch(&mut self, line: &str) {
        match self.spawn(line) {
            Ok(child) => {
                info!("started {line:?}");
                self.children.push(child);
            }
            Err(e) => {
                let msg = frame(S_NOTICE, format!("cannot start {line:?}: {e}").as_bytes());
                self.broadcast(&msg);
            }
        }
    }

    /// A command in the session: its display, fonts and a UTF-8 locale; in its own session.
    fn spawn(&self, line: &str) -> std::io::Result<std::process::Child> {
        use std::os::unix::process::CommandExt;
        let mut c = std::process::Command::new("/bin/sh");
        c.arg("-c")
            .arg(line)
            .env("DISPLAY", &self.env.display)
            .env("XAUTHORITY", &self.env.xauthority)
            .env("FONTCONFIG_FILE", &self.env.fonts_conf)
            .env("NO_AT_BRIDGE", "1")
            .env("GDK_BACKEND", "x11")
            .env("QT_QPA_PLATFORM", "xcb")
            .env_remove("WAYLAND_DISPLAY")
            .stdin(std::process::Stdio::null());
        // Containers often set no locale: apps would fall back to ASCII/Latin-1.
        if std::env::var_os("LANG").is_none() && std::env::var_os("LC_ALL").is_none() {
            c.env("LANG", "C.UTF-8");
        }
        if let Some(home) = std::env::var_os("HOME") {
            c.current_dir(home);
        }
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        c.spawn()
    }

    // ----------------------------------------------------------------------- screen

    fn resize(&mut self, w: u16, h: u16) {
        let (w, h) = (w.clamp(320, MAX_W), h.clamp(240, MAX_H));
        if (w, h) != (self.w, self.h) || self.prev.is_empty() {
            if let Err(e) = self.set_screen_size(w, h) {
                warn!("resizing the screen to {w}x{h}: {e:#}");
            }
            // Whatever RandR made of it.
            if let Ok(g) = self
                .conn
                .get_geometry(self.root)
                .map_err(anyhow::Error::from)
                .and_then(|c| Ok(c.reply()?))
            {
                self.w = g.width.min(MAX_W);
                self.h = g.height.min(MAX_H);
            }
            self.prev = vec![0; self.w as usize * self.h as usize * 4];
            if !self.external_wm {
                for i in 0..self.windows.len() {
                    let win = self.windows[i].win;
                    let _ = self.place(win);
                }
            }
        }
        self.full = true;
        self.dirty = true;
        let init = frame(S_INIT, &[self.w.to_le_bytes(), self.h.to_le_bytes()].concat());
        self.broadcast(&init);
    }

    fn set_screen_size(&mut self, w: u16, h: u16) -> Result<()> {
        let res = self.conn.randr_get_screen_resources_current(self.root)?.reply()?;
        let (Some(&crtc), Some(&output)) = (res.crtcs.first(), res.outputs.first()) else {
            bail!("no RandR output");
        };
        let name = format!("{w}x{h}");
        let mode = match res.modes.iter().find(|m| m.width == w && m.height == h).map(|m| m.id) {
            Some(m) => m,
            None => {
                let info = randr::ModeInfo {
                    width: w,
                    height: h,
                    name_len: name.len() as u16,
                    ..Default::default()
                };
                let m = self
                    .conn
                    .randr_create_mode(self.root, info, name.as_bytes())?
                    .reply()?
                    .mode;
                self.conn.randr_add_output_mode(output, m)?;
                m
            }
        };
        let mm = |px: u16| (px as u32 * 254 / 960).max(1);
        // Growing: screen first, then the mode; shrinking the other way round.
        if w > self.w || h > self.h {
            self.conn
                .randr_set_screen_size(
                    self.root,
                    w.max(self.w),
                    h.max(self.h),
                    mm(w.max(self.w)),
                    mm(h.max(self.h)),
                )?
                .check()?;
        }
        self.conn
            .randr_set_crtc_config(
                crtc,
                x11rb::CURRENT_TIME,
                res.config_timestamp,
                0,
                0,
                mode,
                randr::Rotation::ROTATE0,
                &[output],
            )?
            .reply()?;
        self.conn
            .randr_set_screen_size(self.root, w, h, mm(w), mm(h))?
            .check()?;
        Ok(())
    }

    fn capture(&self) -> Result<Vec<u8>> {
        let (w, h) = (self.w, self.h);
        let len = w as usize * h as usize * 4;
        if let Some(s) = &self.shm
            && len <= s.size
        {
            self.conn
                .shm_get_image(self.root, 0, 0, w, h, !0, ImageFormat::Z_PIXMAP.into(), s.seg, 0)?
                .reply()?;
            let data = unsafe { std::slice::from_raw_parts(s.addr, len) };
            return Ok(data.to_vec());
        }
        let r = self
            .conn
            .get_image(ImageFormat::Z_PIXMAP, self.root, 0, 0, w, h, !0)?
            .reply()?;
        Ok(r.data)
    }

    fn send_frame(&mut self) {
        self.conn.damage_subtract(self.damage, x11rb::NONE, x11rb::NONE).ok();
        self.dirty = false;
        self.last_frame = Instant::now();
        let cur = match self.capture() {
            Ok(c) => c,
            Err(e) => {
                warn!("capture: {e:#}");
                return;
            }
        };
        let (w, h) = (self.w as usize, self.h as usize);
        if self.prev.len() != cur.len() {
            self.prev = vec![0; cur.len()];
            self.full = true;
        }
        let stride = w * 4;
        let mut out = vec![];
        for ty in (0..h).step_by(TILE) {
            for tx in (0..w).step_by(TILE) {
                let (tw, th) = (TILE.min(w - tx), TILE.min(h - ty));
                let changed = self.full
                    || (ty..ty + th).any(|y| {
                        let a = y * stride + tx * 4;
                        cur[a..a + tw * 4] != self.prev[a..a + tw * 4]
                    });
                if !changed {
                    continue;
                }
                for y in ty..ty + th {
                    let a = y * stride + tx * 4;
                    self.prev[a..a + tw * 4].copy_from_slice(&cur[a..a + tw * 4]);
                }
                let (fmt, img) = encode_tile(&cur, stride, tx, ty, tw, th);
                let mut p = Vec::with_capacity(9 + img.len());
                for v in [tx as u16, ty as u16, tw as u16, th as u16] {
                    p.extend_from_slice(&v.to_le_bytes());
                }
                p.push(fmt);
                p.extend_from_slice(&img);
                out.extend(frame(S_TILE, &p));
            }
        }
        self.full = false;
        if out.is_empty() {
            return;
        }
        out.extend(frame(S_FRAME_END, b""));
        for c in &mut self.clients {
            c.inflight += 1;
        }
        self.broadcast(&out);
    }

    fn update_cursor(&mut self) {
        let Ok(Ok(img)) = self.conn.xfixes_get_cursor_image().map(|c| c.reply()) else {
            return;
        };
        let (w, h) = (img.width as u32, img.height as u32);
        if w == 0 || h == 0 || w > 256 || h > 256 {
            return;
        }
        let mut rgba = Vec::with_capacity((w * h * 4) as usize);
        for &px in &img.cursor_image {
            let a = (px >> 24) & 0xff;
            // XFixes cursors are premultiplied; browsers want straight alpha.
            let un = |c: u32| (c * 255 + a / 2).checked_div(a).unwrap_or(0).min(255) as u8;
            rgba.extend_from_slice(&[un((px >> 16) & 0xff), un((px >> 8) & 0xff), un(px & 0xff), a as u8]);
        }
        let Some(png) = encode_png(&rgba, w, h, png::ColorType::Rgba) else {
            return;
        };
        let mut p = vec![];
        p.extend_from_slice(&img.xhot.to_le_bytes());
        p.extend_from_slice(&img.yhot.to_le_bytes());
        p.extend_from_slice(&png);
        let msg = frame(S_CURSOR, &p);
        self.cursor = Some(msg.clone());
        self.broadcast(&msg);
    }

    // ----------------------------------------------------------------------- window manager

    fn event(&mut self, ev: Event) {
        let r: Result<()> = (|| {
            match ev {
                Event::DamageNotify(_) => self.dirty = true,
                Event::MapRequest(e) => self.manage(e.window)?,
                Event::ConfigureRequest(e) => self.configure_request(e)?,
                Event::UnmapNotify(e) if !self.external_wm => {
                    if e.event == self.root || e.event == e.window {
                        self.unmanage(e.window);
                    }
                }
                Event::DestroyNotify(e) if !self.external_wm => self.unmanage(e.window),
                Event::PropertyNotify(e)
                    if self.external_wm
                        && e.window == self.root
                        && (e.atom == self.atoms._NET_CLIENT_LIST || e.atom == self.atoms._NET_ACTIVE_WINDOW) =>
                {
                    self.sync_clients()?;
                }
                Event::PropertyNotify(e) => {
                    if (e.atom == self.atoms._NET_WM_NAME || e.atom == u32::from(AtomEnum::WM_NAME))
                        && let Some(i) = self.windows.iter().position(|m| m.win == e.window)
                    {
                        self.windows[i].title = self.title(e.window);
                        let msg = self.windows_msg();
                        self.broadcast(&msg);
                    }
                }
                Event::ClientMessage(e) if !self.external_wm => {
                    if e.type_ == self.atoms._NET_ACTIVE_WINDOW {
                        self.activate(e.window)?;
                    } else if e.type_ == self.atoms._NET_CLOSE_WINDOW {
                        self.close(e.window)?;
                    }
                }
                Event::MappingNotify(_) => self.load_keymap()?,
                Event::XfixesCursorNotify(_) => self.update_cursor(),
                Event::XfixesSelectionNotify(e) => {
                    if e.owner != self.support && e.owner != x11rb::NONE {
                        self.conn.convert_selection(
                            self.support,
                            self.atoms.CLIPBOARD,
                            self.atoms.UTF8_STRING,
                            self.atoms.MESHVPN_SEL,
                            x11rb::CURRENT_TIME,
                        )?;
                    }
                }
                Event::SelectionNotify(e) => {
                    if e.property != x11rb::NONE {
                        let r = self
                            .conn
                            .get_property(true, self.support, e.property, AtomEnum::ANY, 0, 1 << 20)?
                            .reply()?;
                        let text = String::from_utf8_lossy(&r.value).into_owned();
                        if !text.is_empty() {
                            let msg = frame(S_CLIPBOARD, text.as_bytes());
                            self.broadcast(&msg);
                        }
                    }
                }
                Event::SelectionRequest(e) => self.selection_request(e)?,
                Event::Error(e) => debug!("X error: {e:?}"),
                _ => {}
            }
            Ok(())
        })();
        if let Err(e) = r {
            debug!("event: {e:#}");
        }
    }

    fn title(&self, win: Window) -> String {
        let get = |prop: Atom, ty: Atom| {
            self.conn
                .get_property(false, win, prop, ty, 0, 256)
                .ok()?
                .reply()
                .ok()
                .filter(|r| !r.value.is_empty())
                .map(|r| String::from_utf8_lossy(&r.value).into_owned())
        };
        get(self.atoms._NET_WM_NAME, self.atoms.UTF8_STRING)
            .or_else(|| get(AtomEnum::WM_NAME.into(), AtomEnum::ANY.into()))
            .unwrap_or_else(|| format!("window {win:#x}"))
    }

    /// Dialogs, splash screens and fixed-size windows keep their size (centered); everything
    /// else fills the screen - the browser's tab bar is the task bar.
    fn is_floating(&self, win: Window) -> bool {
        let transient = self
            .conn
            .get_property(false, win, AtomEnum::WM_TRANSIENT_FOR, AtomEnum::WINDOW, 0, 1)
            .ok()
            .and_then(|c| c.reply().ok())
            .is_some_and(|r| !r.value.is_empty());
        if transient {
            return true;
        }
        let types: Vec<u32> = self
            .conn
            .get_property(false, win, self.atoms._NET_WM_WINDOW_TYPE, AtomEnum::ATOM, 0, 16)
            .ok()
            .and_then(|c| c.reply().ok())
            .and_then(|r| r.value32().map(|v| v.collect()))
            .unwrap_or_default();
        if types.iter().any(|t| {
            [
                self.atoms._NET_WM_WINDOW_TYPE_DIALOG,
                self.atoms._NET_WM_WINDOW_TYPE_SPLASH,
                self.atoms._NET_WM_WINDOW_TYPE_UTILITY,
            ]
            .contains(t)
        }) {
            return true;
        }
        x11rb::properties::WmSizeHints::get_normal_hints(&self.conn, win)
            .ok()
            .and_then(|c| c.reply().ok())
            .flatten()
            .is_some_and(|h| h.min_size.is_some() && h.min_size == h.max_size)
    }

    fn manage(&mut self, win: Window) -> Result<()> {
        if self.windows.iter().any(|m| m.win == win) {
            self.conn.map_window(win)?;
            return Ok(());
        }
        let attrs = self.conn.get_window_attributes(win)?.reply()?;
        if attrs.override_redirect {
            self.conn.map_window(win)?;
            return Ok(());
        }
        let floating = self.is_floating(win);
        self.conn.change_window_attributes(
            win,
            &ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE | EventMask::STRUCTURE_NOTIFY),
        )?;
        let title = self.title(win);
        self.windows.push(Managed { win, title, floating });
        self.place(win)?;
        self.conn.map_window(win)?;
        self.conn.change_property32(
            PropMode::REPLACE,
            win,
            self.atoms.WM_STATE,
            self.atoms.WM_STATE,
            &[1, 0],
        )?;
        self.activate(win)?;
        self.client_list()?;
        Ok(())
    }

    fn place(&self, win: Window) -> Result<()> {
        let Some(m) = self.windows.iter().find(|m| m.win == win) else {
            return Ok(());
        };
        let aux = if m.floating {
            let g = self.conn.get_geometry(win)?.reply()?;
            let x = (self.w as i32 - g.width as i32).max(0) / 2;
            let y = (self.h as i32 - g.height as i32).max(0) / 2;
            ConfigureWindowAux::new().x(x).y(y).border_width(0)
        } else {
            ConfigureWindowAux::new()
                .x(0)
                .y(0)
                .width(self.w as u32)
                .height(self.h as u32)
                .border_width(0)
        };
        self.conn.configure_window(win, &aux)?;
        Ok(())
    }

    fn configure_request(&mut self, e: ConfigureRequestEvent) -> Result<()> {
        match self.windows.iter().find(|m| m.win == e.window) {
            Some(m) if !m.floating => {
                // Maximized windows stay so; tell the client where it is (ICCCM 4.1.5).
                let ev = ConfigureNotifyEvent {
                    response_type: CONFIGURE_NOTIFY_EVENT,
                    sequence: 0,
                    event: e.window,
                    window: e.window,
                    above_sibling: x11rb::NONE,
                    x: 0,
                    y: 0,
                    width: self.w,
                    height: self.h,
                    border_width: 0,
                    override_redirect: false,
                };
                self.conn.send_event(false, e.window, EventMask::STRUCTURE_NOTIFY, ev)?;
            }
            _ => {
                self.conn
                    .configure_window(e.window, &ConfigureWindowAux::from_configure_request(&e))?;
            }
        }
        Ok(())
    }

    fn unmanage(&mut self, win: Window) {
        let before = self.windows.len();
        self.windows.retain(|m| m.win != win);
        if self.windows.len() == before {
            return;
        }
        if self.active == Some(win) {
            self.active = None;
            if let Some(top) = self.windows.last().map(|m| m.win) {
                let _ = self.activate(top);
            }
        }
        let _ = self.client_list();
        let msg = self.windows_msg();
        self.broadcast(&msg);
    }

    /// Xfce is gone: be the window manager after all, and adopt the windows that are open.
    fn become_wm(&mut self) -> Result<()> {
        self.external_wm = false;
        self.conn
            .change_window_attributes(
                self.root,
                &ChangeWindowAttributesAux::new().event_mask(
                    EventMask::SUBSTRUCTURE_REDIRECT | EventMask::SUBSTRUCTURE_NOTIFY | EventMask::STRUCTURE_NOTIFY,
                ),
            )?
            .check()?;
        let a = &self.atoms;
        self.conn.change_property32(
            PropMode::REPLACE,
            self.root,
            a._NET_SUPPORTING_WM_CHECK,
            AtomEnum::WINDOW,
            &[self.support],
        )?;
        self.conn.change_property32(
            PropMode::REPLACE,
            self.support,
            a._NET_SUPPORTING_WM_CHECK,
            AtomEnum::WINDOW,
            &[self.support],
        )?;
        let _ = std::fs::write(self.env.xauthority.with_file_name("mode"), "plain");
        self.windows.clear();
        let tree = self.conn.query_tree(self.root)?.reply()?;
        for win in tree.children {
            let Ok(attrs) = self.conn.get_window_attributes(win)?.reply() else {
                continue;
            };
            if attrs.override_redirect || attrs.map_state != MapState::VIEWABLE || win == self.support {
                continue;
            }
            self.manage(win)?;
        }
        let msg = self.windows_msg();
        self.broadcast(&msg);
        Ok(())
    }

    /// Asks the window manager (Xfce) to do something with a window (EWMH).
    fn ask_wm(&self, kind: Atom, win: Window, data: [u32; 5]) -> Result<()> {
        let ev = ClientMessageEvent::new(32, win, kind, data);
        self.conn.send_event(
            false,
            self.root,
            EventMask::SUBSTRUCTURE_REDIRECT | EventMask::SUBSTRUCTURE_NOTIFY,
            ev,
        )?;
        Ok(())
    }

    /// Xfce mode: the windows (and the active one) as its window manager lists them.
    fn sync_clients(&mut self) -> Result<()> {
        let list: Vec<u32> = self
            .conn
            .get_property(false, self.root, self.atoms._NET_CLIENT_LIST, AtomEnum::WINDOW, 0, 1024)?
            .reply()?
            .value32()
            .map(|v| v.collect())
            .unwrap_or_default();
        let active = self
            .conn
            .get_property(false, self.root, self.atoms._NET_ACTIVE_WINDOW, AtomEnum::WINDOW, 0, 1)?
            .reply()?
            .value32()
            .and_then(|mut v| v.next())
            .filter(|w| *w != 0);
        let mut windows = vec![];
        for win in list {
            if let Some(m) = self.windows.iter().position(|m| m.win == win) {
                windows.push(self.windows.remove(m));
                continue;
            }
            // Panels and the desktop background are no windows to switch to.
            let types: Vec<u32> = self
                .conn
                .get_property(false, win, self.atoms._NET_WM_WINDOW_TYPE, AtomEnum::ATOM, 0, 16)
                .ok()
                .and_then(|c| c.reply().ok())
                .and_then(|r| r.value32().map(|v| v.collect()))
                .unwrap_or_default();
            if types
                .iter()
                .any(|t| *t == self.atoms._NET_WM_WINDOW_TYPE_DOCK || *t == self.atoms._NET_WM_WINDOW_TYPE_DESKTOP)
            {
                continue;
            }
            // Titles change: follow them.
            let _ = self.conn.change_window_attributes(
                win,
                &ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE),
            );
            windows.push(Managed {
                win,
                title: self.title(win),
                floating: false,
            });
        }
        self.windows = windows;
        self.active = active;
        let msg = self.windows_msg();
        self.broadcast(&msg);
        Ok(())
    }

    fn activate(&mut self, win: Window) -> Result<()> {
        if self.external_wm {
            // source 2: a pager/taskbar asked
            return self.ask_wm(self.atoms._NET_ACTIVE_WINDOW, win, [2, x11rb::CURRENT_TIME, 0, 0, 0]);
        }
        let Some(i) = self.windows.iter().position(|m| m.win == win) else {
            return Ok(());
        };
        let m = self.windows.remove(i);
        self.windows.push(m);
        self.conn
            .configure_window(win, &ConfigureWindowAux::new().stack_mode(StackMode::ABOVE))?;
        self.conn
            .set_input_focus(InputFocus::POINTER_ROOT, win, x11rb::CURRENT_TIME)?;
        self.conn.change_property32(
            PropMode::REPLACE,
            self.root,
            self.atoms._NET_ACTIVE_WINDOW,
            AtomEnum::WINDOW,
            &[win],
        )?;
        self.active = Some(win);
        let msg = self.windows_msg();
        self.broadcast(&msg);
        Ok(())
    }

    fn close(&mut self, win: Window) -> Result<()> {
        if !self.windows.iter().any(|m| m.win == win) {
            return Ok(());
        }
        if self.external_wm {
            return self.ask_wm(self.atoms._NET_CLOSE_WINDOW, win, [x11rb::CURRENT_TIME, 2, 0, 0, 0]);
        }
        let protocols: Vec<u32> = self
            .conn
            .get_property(false, win, self.atoms.WM_PROTOCOLS, AtomEnum::ATOM, 0, 32)?
            .reply()?
            .value32()
            .map(|v| v.collect())
            .unwrap_or_default();
        if protocols.contains(&self.atoms.WM_DELETE_WINDOW) {
            let ev = ClientMessageEvent::new(
                32,
                win,
                self.atoms.WM_PROTOCOLS,
                [self.atoms.WM_DELETE_WINDOW, x11rb::CURRENT_TIME, 0, 0, 0],
            );
            self.conn.send_event(false, win, EventMask::NO_EVENT, ev)?;
        } else {
            self.conn.kill_client(win)?;
        }
        Ok(())
    }

    fn client_list(&self) -> Result<()> {
        let ids: Vec<u32> = self.windows.iter().map(|m| m.win).collect();
        self.conn.change_property32(
            PropMode::REPLACE,
            self.root,
            self.atoms._NET_CLIENT_LIST,
            AtomEnum::WINDOW,
            &ids,
        )?;
        Ok(())
    }

    fn windows_msg(&self) -> Vec<u8> {
        let list: Vec<serde_json::Value> = self
            .windows
            .iter()
            .map(|m| serde_json::json!({"id": m.win, "title": m.title, "active": Some(m.win) == self.active}))
            .collect();
        frame(S_WINDOWS, &serde_json::to_vec(&list).unwrap_or_default())
    }

    // ----------------------------------------------------------------------- input

    fn pointer(&mut self, x: u16, y: u16, buttons: u8) -> Result<()> {
        let (x, y) = (
            x.min(self.w.saturating_sub(1)) as i16,
            y.min(self.h.saturating_sub(1)) as i16,
        );
        self.conn
            .xtest_fake_input(MOTION_NOTIFY_EVENT, 0, 0, self.root, x, y, 0)?;
        for (bit, button) in [(1u8, 1u8), (2, 3), (4, 2)] {
            let (was, is) = (self.buttons & bit != 0, buttons & bit != 0);
            if is && !was {
                // Click to focus.
                let under = self.conn.query_pointer(self.root)?.reply().map(|p| p.child).ok();
                if !self.external_wm
                    && let Some(child) = under
                    && child != x11rb::NONE
                    && Some(child) != self.active
                {
                    self.activate(child)?;
                }
                self.conn
                    .xtest_fake_input(BUTTON_PRESS_EVENT, button, 0, self.root, 0, 0, 0)?;
            } else if was && !is {
                self.conn
                    .xtest_fake_input(BUTTON_RELEASE_EVENT, button, 0, self.root, 0, 0, 0)?;
            }
        }
        self.buttons = buttons;
        Ok(())
    }

    fn load_keymap(&mut self) -> Result<()> {
        let setup = self.conn.setup();
        let (min, max) = (setup.min_keycode, setup.max_keycode);
        let r = self.conn.get_keyboard_mapping(min, max - min + 1)?.reply()?;
        let per = r.keysyms_per_keycode as usize;
        self.keysyms.clear();
        self.spare.clear();
        for (i, syms) in r.keysyms.chunks(per.max(1)).enumerate() {
            let kc = min as usize + i;
            if syms.iter().all(|s| *s == 0) {
                self.spare.push(kc as u8);
            }
            for (level, s) in syms.iter().enumerate().take(2) {
                if *s != 0 {
                    let e = self.keysyms.entry(*s).or_insert((kc as u8, level));
                    if level < e.1 {
                        *e = (kc as u8, level);
                    }
                }
            }
        }
        // Spare keycodes that the typed-character trick already uses stay valid.
        self.spare.retain(|k| !self.char_keys.values().any(|v| v == k));
        Ok(())
    }

    /// The keycode to press for `keysym`: its own key if the shift state fits, else a spare
    /// keycode bound to that keysym on all levels (any character, any keyboard layout).
    fn keycode_for(&mut self, keysym: u32, is_char: bool) -> Result<Option<u8>> {
        if let Some(&(kc, level)) = self.keysyms.get(&keysym)
            && (!is_char || (level == 1) == self.shift)
        {
            return Ok(Some(kc));
        }
        if let Some(&kc) = self.char_keys.get(&keysym) {
            return Ok(Some(kc));
        }
        let kc = match self.spare.pop() {
            Some(k) => k,
            None => {
                // Recycle the oldest binding.
                let Some((&old, &kc)) = self.char_keys.iter().next() else {
                    return Ok(None);
                };
                self.char_keys.remove(&old);
                kc
            }
        };
        let per = 4u8;
        self.conn.change_keyboard_mapping(1, kc, per, &[keysym; 4])?;
        self.char_keys.insert(keysym, kc);
        Ok(Some(kc))
    }

    fn key(&mut self, down: bool, is_char: bool, keysym: u32) -> Result<()> {
        if matches!(keysym, 0xffe1 | 0xffe2) {
            self.shift = down;
        }
        if down {
            let Some(kc) = self.keycode_for(keysym, is_char)? else {
                return Ok(());
            };
            self.pressed.insert(keysym, kc);
            self.conn.xtest_fake_input(KEY_PRESS_EVENT, kc, 0, self.root, 0, 0, 0)?;
        } else if let Some(kc) = self.pressed.remove(&keysym) {
            self.conn
                .xtest_fake_input(KEY_RELEASE_EVENT, kc, 0, self.root, 0, 0, 0)?;
        }
        Ok(())
    }

    fn selection_request(&mut self, e: SelectionRequestEvent) -> Result<()> {
        let mut property = e.property;
        let text = self.clip_out.clone().unwrap_or_default();
        if e.target == self.atoms.TARGETS {
            self.conn.change_property32(
                PropMode::REPLACE,
                e.requestor,
                e.property,
                AtomEnum::ATOM,
                &[
                    self.atoms.TARGETS,
                    self.atoms.UTF8_STRING,
                    AtomEnum::STRING.into(),
                    self.atoms.TEXT,
                ],
            )?;
        } else if e.target == self.atoms.UTF8_STRING || e.target == self.atoms.TEXT {
            self.conn.change_property8(
                PropMode::REPLACE,
                e.requestor,
                e.property,
                self.atoms.UTF8_STRING,
                text.as_bytes(),
            )?;
        } else if e.target == u32::from(AtomEnum::STRING) {
            let latin1: Vec<u8> = text
                .chars()
                .map(|c| if (c as u32) < 256 { c as u8 } else { b'?' })
                .collect();
            self.conn
                .change_property8(PropMode::REPLACE, e.requestor, e.property, AtomEnum::STRING, &latin1)?;
        } else {
            property = x11rb::NONE;
        }
        let ev = SelectionNotifyEvent {
            response_type: SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: e.time,
            requestor: e.requestor,
            selection: e.selection,
            target: e.target,
            property,
        };
        self.conn.send_event(false, e.requestor, EventMask::NO_EVENT, ev)?;
        Ok(())
    }
}

fn attach_shm(conn: &RustConnection) -> Result<Shm> {
    conn.shm_query_version()?.reply()?;
    let size = MAX_W as usize * MAX_H as usize * 4;
    let id = unsafe { libc::shmget(libc::IPC_PRIVATE, size, libc::IPC_CREAT | 0o600) };
    if id < 0 {
        bail!("shmget: {}", std::io::Error::last_os_error());
    }
    let addr = unsafe { libc::shmat(id, std::ptr::null(), 0) };
    if addr as isize == -1 {
        unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
        bail!("shmat: {}", std::io::Error::last_os_error());
    }
    let seg = conn.generate_id()?;
    let attached = conn
        .shm_attach(seg, id as u32, false)
        .map_err(anyhow::Error::from)
        .and_then(|c| Ok(c.check()?));
    // Freed once both sides detach.
    unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
    let shm = Shm {
        seg,
        addr: addr as *mut u8,
        size,
    };
    attached?;
    // A test capture: a server in another IPC namespace would fail here.
    conn.shm_get_image(
        conn.setup().roots[0].root,
        0,
        0,
        1,
        1,
        !0,
        ImageFormat::Z_PIXMAP.into(),
        seg,
        0,
    )?
    .reply()?;
    Ok(shm)
}

// ---------------------------------------------------------------------------------------------
// Encoding

fn encode_png(data: &[u8], w: u32, h: u32, color: png::ColorType) -> Option<Vec<u8>> {
    let mut out = vec![];
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(color);
        enc.set_depth(png::BitDepth::Eight);
        enc.set_compression(png::Compression::Fast);
        let mut wr = enc.write_header().ok()?;
        wr.write_image_data(data).ok()?;
    }
    Some(out)
}

/// A tile of BGRX pixels: PNG if it has few colors (text, UI: stays sharp), JPEG otherwise.
fn encode_tile(buf: &[u8], stride: usize, x: usize, y: usize, w: usize, h: usize) -> (u8, Vec<u8>) {
    let mut rgb = Vec::with_capacity(w * h * 3);
    let mut colors: Vec<u32> = Vec::with_capacity(64);
    let mut many = false;
    for row in y..y + h {
        let a = row * stride + x * 4;
        for px in buf[a..a + w * 4].as_chunks::<4>().0 {
            rgb.extend_from_slice(&[px[2], px[1], px[0]]);
            if !many {
                let c = u32::from_le_bytes([px[0], px[1], px[2], 0]);
                if !colors.contains(&c) {
                    if colors.len() >= 48 {
                        many = true;
                    } else {
                        colors.push(c);
                    }
                }
            }
        }
    }
    if !many && let Some(png) = encode_png(&rgb, w as u32, h as u32, png::ColorType::Rgb) {
        return (1, png);
    }
    let mut jpg = vec![];
    let enc = jpeg_encoder::Encoder::new(&mut jpg, 80);
    if enc
        .encode(&rgb, w as u16, h as u16, jpeg_encoder::ColorType::Rgb)
        .is_ok()
    {
        return (2, jpg);
    }
    (
        1,
        encode_png(&rgb, w as u32, h as u32, png::ColorType::Rgb).unwrap_or_default(),
    )
}

// ---------------------------------------------------------------------------------------------
// Applications

#[derive(serde::Serialize)]
struct App {
    name: String,
    exec: String,
}

/// Installed GUI applications (freedesktop .desktop files).
fn list_apps() -> Vec<App> {
    let mut dirs = vec![
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
        PathBuf::from("/var/lib/flatpak/exports/share/applications"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share/applications"));
    }
    let mut apps: Vec<App> = vec![];
    for d in dirs {
        for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
            if e.path().extension().is_none_or(|x| x != "desktop") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(e.path()) else {
                continue;
            };
            if let Some(app) = parse_desktop_entry(&text)
                && !apps.iter().any(|a| a.name == app.name)
            {
                apps.push(app);
            }
        }
    }
    apps.sort_by_key(|a| a.name.to_lowercase());
    apps
}

fn parse_desktop_entry(text: &str) -> Option<App> {
    let mut in_entry = false;
    let (mut name, mut exec) = (None, None);
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        match k.trim() {
            "Name" => name = Some(v.trim().to_string()),
            "Exec" => exec = Some(v.trim().to_string()),
            "Type" if v.trim() != "Application" => return None,
            "NoDisplay" | "Hidden" | "Terminal" if v.trim() == "true" => return None,
            _ => {}
        }
    }
    // Field codes (%f, %U, ...) are for files and URLs; we start the app without any.
    let exec: String = exec?
        .split_whitespace()
        .filter(|w| !(w.len() == 2 && w.starts_with('%')))
        .collect::<Vec<_>>()
        .join(" ");
    Some(App { name: name?, exec })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_entries() {
        let app = parse_desktop_entry("[Desktop Entry]\nType=Application\nName=Editor\nExec=gedit %U\n").unwrap();
        assert_eq!((app.name.as_str(), app.exec.as_str()), ("Editor", "gedit"));
        assert!(parse_desktop_entry("[Desktop Entry]\nName=x\nExec=x\nNoDisplay=true\n").is_none());
        assert!(parse_desktop_entry("[Desktop Entry]\nName=t\nExec=t\nTerminal=true\n").is_none());
    }

    #[test]
    fn tiles_choose_format() {
        let flat = vec![200u8; 64 * 64 * 4];
        assert_eq!(encode_tile(&flat, 64 * 4, 0, 0, 64, 64).0, 1);
        let noise: Vec<u8> = (0..64 * 64 * 4).map(|i| (i * 7919 % 251) as u8).collect();
        assert_eq!(encode_tile(&noise, 64 * 4, 0, 0, 64, 64).0, 2);
    }
}

// ---------------------------------------------------------------------------------------------
// Files: the viewer's file browser and image viewer (the session runs as the user, so it sees
// exactly what the user may see).

pub(super) mod files {
    use super::super::proto::*;
    use std::path::{Path, PathBuf};

    pub fn home() -> PathBuf {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"))
    }

    /// A directory listing for the viewer: folders first, then by name.
    pub fn list(path: &str) -> Vec<u8> {
        let dir = if path.trim().is_empty() {
            home()
        } else {
            PathBuf::from(path)
        };
        let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
        let mut entries = vec![];
        let error = match std::fs::read_dir(&dir) {
            Ok(rd) => {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let link = e.file_type().is_ok_and(|t| t.is_symlink());
                    // Follow links for what they point to.
                    let meta = std::fs::metadata(e.path()).or_else(|_| e.metadata());
                    let (is_dir, size, mtime) = match &meta {
                        Ok(m) => (
                            m.is_dir(),
                            m.len(),
                            m.modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map_or(0, |d| d.as_secs()),
                        ),
                        Err(_) => (false, 0, 0),
                    };
                    entries.push(
                        serde_json::json!({"name": name, "dir": is_dir, "size": size, "mtime": mtime, "link": link}),
                    );
                }
                None
            }
            Err(e) => Some(e.to_string()),
        };
        entries.sort_by_key(|e| {
            (
                !e["dir"].as_bool().unwrap_or(false),
                e["name"].as_str().unwrap_or("").to_lowercase(),
            )
        });
        let parent = dir.parent().map(|p| p.display().to_string());
        frame(
            S_FILES,
            &serde_json::to_vec(&serde_json::json!({
                "path": dir.display().to_string(),
                "parent": parent,
                "home": home().display().to_string(),
                "entries": entries,
                "error": error,
            }))
            .unwrap_or_default(),
        )
    }

    pub fn done(id: u32, result: Result<(), String>) -> Vec<u8> {
        let (ok, error) = match result {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e)),
        };
        frame(
            S_FILE_DONE,
            &serde_json::to_vec(&serde_json::json!({"id": id, "ok": ok, "error": error})).unwrap_or_default(),
        )
    }

    /// Streams a file to one viewer, in its own thread (back pressure from the connection).
    pub fn read(id: u32, path: String, tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut f = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    let _ = tx.blocking_send(done(id, Err(e.to_string())));
                    return;
                }
            };
            let total = f.metadata().map(|m| m.len()).unwrap_or(0);
            if total == 0 {
                let mut p = Vec::with_capacity(20);
                p.extend_from_slice(&id.to_le_bytes());
                p.extend_from_slice(&0u64.to_le_bytes());
                p.extend_from_slice(&0u64.to_le_bytes());
                let _ = tx.blocking_send(frame(S_FILE_DATA, &p));
                return;
            }
            let mut offset = 0u64;
            let mut buf = vec![0u8; 256 * 1024];
            while offset < total {
                let n = match f.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        let _ = tx.blocking_send(done(id, Err(e.to_string())));
                        return;
                    }
                };
                let mut p = Vec::with_capacity(20 + n);
                p.extend_from_slice(&id.to_le_bytes());
                p.extend_from_slice(&offset.to_le_bytes());
                p.extend_from_slice(&total.to_le_bytes());
                p.extend_from_slice(&buf[..n]);
                if tx.blocking_send(frame(S_FILE_DATA, &p)).is_err() {
                    return; // the viewer went away
                }
                offset += n as u64;
            }
            if offset < total {
                let _ = tx.blocking_send(done(id, Err("the file got shorter while reading".into())));
            }
        });
    }

    fn upload_tmp(path: &Path) -> PathBuf {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        path.with_file_name(format!(".{name}.meshvpn-upload"))
    }

    /// One part of an upload; the finished file replaces `path` atomically. Some(result) at the end.
    pub fn write(p: &[u8]) -> (u32, Option<Result<(), String>>) {
        use std::os::unix::fs::FileExt;
        let id = u32_at(p, 0);
        let (Some(off), Some(total)) = (p.get(4..12), p.get(12..20)) else {
            return (id, Some(Err("bad upload".into())));
        };
        let offset = u64::from_le_bytes(off.try_into().unwrap());
        let total = u64::from_le_bytes(total.try_into().unwrap());
        let plen = u16_at(p, 20) as usize;
        let Some(path) = p
            .get(22..22 + plen)
            .map(|b| PathBuf::from(String::from_utf8_lossy(b).into_owned()))
        else {
            return (id, Some(Err("bad upload".into())));
        };
        let data = &p[22 + plen..];
        let tmp = upload_tmp(&path);
        let r: std::io::Result<bool> = (|| {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(offset == 0)
                .open(&tmp)?;
            f.write_all_at(data, offset)?;
            if offset + data.len() as u64 >= total {
                drop(f);
                std::fs::rename(&tmp, &path)?;
                return Ok(true);
            }
            Ok(false)
        })();
        match r {
            Ok(true) => (id, Some(Ok(()))),
            Ok(false) => (id, None),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                (id, Some(Err(e.to_string())))
            }
        }
    }

    /// mkdir / delete / rename from the file browser.
    pub fn op(p: &[u8]) -> (u32, Result<(), String>) {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(p) else {
            return (0, Err("bad request".into()));
        };
        let id = v["id"].as_u64().unwrap_or(0) as u32;
        let path = PathBuf::from(v["path"].as_str().unwrap_or(""));
        if path.as_os_str().is_empty() || path == Path::new("/") {
            return (id, Err("no path".into()));
        }
        let r = match v["op"].as_str() {
            Some("mkdir") => std::fs::create_dir(&path),
            Some("delete") => match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => std::fs::remove_dir_all(&path),
                Ok(_) => std::fs::remove_file(&path),
                Err(e) => Err(e),
            },
            Some("rename") => {
                let to = v["to"].as_str().unwrap_or("");
                if to.is_empty() || to.contains('/') {
                    return (id, Err("invalid name".into()));
                }
                std::fs::rename(&path, path.with_file_name(to))
            }
            _ => return (id, Err("unknown operation".into())),
        };
        (id, r.map_err(|e| e.to_string()))
    }
}
