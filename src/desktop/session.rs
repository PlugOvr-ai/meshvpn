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

/// `/tmp/meshvpn-desktop-<uid>` (0700, ours). Not `$XDG_RUNTIME_DIR`: logind removes that when
/// the user's last login ends (leaving the desk, an SSH connection closing), and the session
/// outlives them. A session started there before still is found there.
pub fn runtime_dir() -> Result<PathBuf> {
    let uid = unsafe { libc::geteuid() };
    let legacy = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(|r| PathBuf::from(r).join("meshvpn-desktop"))
        .filter(|d| std::os::unix::net::UnixStream::connect(socket_path(d)).is_ok());
    let dir = legacy.unwrap_or_else(|| PathBuf::from(format!("/tmp/meshvpn-desktop-{uid}")));
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

/// Where a session of `mode` keeps its files: the shared screen apart from the desktop of its
/// own, so both can run at once.
fn session_dir(mode_name: &str) -> Result<PathBuf> {
    let dir = runtime_dir()?;
    if mode_name != "screen" {
        return Ok(dir);
    }
    let dir = dir.join("screen");
    match std::fs::create_dir(&dir) {
        Ok(()) => std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
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
/// Without a system configuration "Monospace" is no font at all, and terminals space out a
/// proportional one; `default` leaves the choice to the system's configuration if there is one.
fn write_fonts_conf(path: &Path, bundle: &Bundle, cache: &Path) -> Result<()> {
    let generic: String = [
        ("monospace", "DejaVu Sans Mono"),
        ("sans-serif", "DejaVu Sans"),
        ("sans", "DejaVu Sans"),
        ("serif", "DejaVu Serif"),
    ]
    .iter()
    .map(|(name, font)| format!("<alias><family>{name}</family><default><family>{font}</family></default></alias>\n"))
    .collect();
    let text = format!(
        "<?xml version=\"1.0\"?>\n<!DOCTYPE fontconfig SYSTEM \"fonts.dtd\">\n<fontconfig>\n\
         <include ignore_missing=\"yes\">/etc/fonts/fonts.conf</include>\n\
         <dir>{}</dir>\n<cachedir>{}</cachedir>\n{generic}</fontconfig>\n",
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
    Mate,
    Cinnamon,
    /// The screen of the machine itself: the desktop someone is logged in to there (X11).
    Screen,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Plain => "plain",
            Mode::Xfce => "xfce",
            Mode::Mate => "mate",
            Mode::Cinnamon => "cinnamon",
            Mode::Screen => "screen",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Mode::Plain => "the built-in desktop",
            Mode::Xfce => "Xfce",
            Mode::Mate => "MATE",
            Mode::Cinnamon => "Cinnamon",
            Mode::Screen => "the machine's screen",
        }
    }

    fn from_name(name: &str) -> Option<Mode> {
        [Mode::Plain, Mode::Xfce, Mode::Mate, Mode::Cinnamon, Mode::Screen]
            .into_iter()
            .find(|m| m.name() == name)
    }

    /// Its programs are there (Cinnamon also needs an X server with OpenGL: the system's Xvfb).
    fn installed(self) -> bool {
        match self {
            Mode::Xfce => has_xfce(),
            Mode::Mate => which("mate-session"),
            Mode::Cinnamon => which("cinnamon-session") && system_xvfb().is_some(),
            Mode::Plain | Mode::Screen => true,
        }
    }

    /// The variables a session of this desktop has (a display manager would set them): its
    /// window manager wants to know it's X11, its programs which desktop they are in.
    fn environment(self) -> Vec<(&'static str, &'static str)> {
        let (current, session) = match self {
            Mode::Xfce => ("XFCE", "xfce"),
            Mode::Mate => ("MATE", "mate"),
            Mode::Cinnamon => ("X-Cinnamon", "cinnamon"),
            Mode::Plain | Mode::Screen => return vec![("XDG_SESSION_TYPE", "x11")],
        };
        vec![
            ("XDG_SESSION_TYPE", "x11"),
            ("XDG_CURRENT_DESKTOP", current),
            ("XDG_SESSION_DESKTOP", session),
            ("DESKTOP_SESSION", session),
        ]
    }

    /// The command line starting it, with its own D-Bus if available (settings and panels want one).
    fn start_line(self) -> Option<String> {
        let cmd = match self {
            Mode::Xfce => "xfce4-session",
            Mode::Mate => "mate-session",
            // Software rendering: the X server's OpenGL is Mesa's, on the CPU.
            Mode::Cinnamon if which("cinnamon-session-cinnamon2d") => "cinnamon-session-cinnamon2d",
            Mode::Cinnamon => "cinnamon-session --session cinnamon2d",
            Mode::Plain | Mode::Screen => return None,
        };
        Some(if which("dbus-launch") {
            format!("exec dbus-launch --exit-with-session {cmd}")
        } else {
            format!("exec {cmd}")
        })
    }
}

/// The desktops meshvpn can run, in the order "auto" tries them (after the one chosen with
/// `meshvpn desktop setup --desktop`).
pub const DESKTOPS: [&str; 3] = ["xfce", "mate", "cinnamon"];

/// The system's Xvfb (with OpenGL through Mesa), unlike the bundled one.
pub fn system_xvfb() -> Option<PathBuf> {
    ["/usr/bin/Xvfb", "/usr/local/bin/Xvfb"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// Xfce is installed (its session manager is in PATH).
pub fn has_xfce() -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("xfce4-session").is_file()))
        .unwrap_or(false)
}

/// "auto" (the machine's chosen desktop, else the first installed of `DESKTOPS`, else the
/// built-in one), or a desktop by name.
pub fn resolve_mode(want: &str) -> Result<Mode> {
    if let Some(m) = Mode::from_name(want) {
        if m.installed() {
            return Ok(m);
        }
        bail!(
            "{} is not installed on this machine - install it with `sudo meshvpn desktop setup --desktop {}` \
             there, or use the built-in desktop (--plain)",
            m.label(),
            m.name()
        );
    }
    let chosen = std::fs::read_to_string(bundle::DEFAULT_FILE).unwrap_or_default();
    Ok(std::iter::once(chosen.trim())
        .chain(DESKTOPS)
        .filter_map(Mode::from_name)
        .find(|m| *m != Mode::Plain && *m != Mode::Screen && m.installed())
        .unwrap_or(Mode::Plain))
}

pub fn attach(want: &str) -> Result<()> {
    let notice = |text: &str| {
        let mut out = std::io::stdout();
        let _ = out.write_all(&frame(S_NOTICE, text.as_bytes()));
        let _ = out.flush();
    };
    let stream = connect(want, &notice)?;
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

/// The user's session of kind `want`, started if it isn't running. `notice` tells the user
/// what happens (and why not).
pub fn connect(want: &str, notice: &dyn Fn(&str)) -> Result<std::os::unix::net::UnixStream> {
    let dir = match session_dir(want) {
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
            let running = Mode::from_name(running).unwrap_or(Mode::Plain);
            let wanted = resolve_mode(want).ok();
            if want != "screen"
                && let Some(other) = wanted.filter(|w| *w != running)
            {
                notice(&format!(
                    "This desktop session was started with {} and keeps it. To get {}: End session (⏻, closes \
                     its applications), then reconnect.",
                    running.label(),
                    other.label()
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
            // Nothing to share: say why right away.
            if mode == Mode::Screen
                && let Err(e) = local_screen(&dir)
            {
                notice(&format!("{e:#}"));
                return Err(e);
            }
            if mode != Mode::Screen && bundle::find().is_none() {
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
    Ok(stream)
}

fn start_detached(dir: &Path, mode: Mode) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let exe = crate::update::current_exe()?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("session.log"))?;
    let mut c = std::process::Command::new(exe);
    c.args(["desktop", "session", "--session", mode.name()]);
    if mode != Mode::Screen {
        // A desktop of its own outlives the login that started it (the desk, an SSH
        // connection): not that login's session, bus or runtime directory (logind removes it).
        for v in [
            "XDG_SESSION_ID",
            "XDG_SESSION_TYPE",
            "XDG_SESSION_CLASS",
            "XDG_SESSION_DESKTOP",
            "XDG_CURRENT_DESKTOP",
            "XDG_SEAT",
            "XDG_VTNR",
            "XDG_SEAT_PATH",
            "XDG_SESSION_PATH",
            "DESKTOP_SESSION",
            "GDMSESSION",
            "DBUS_SESSION_BUS_ADDRESS",
            "SESSION_MANAGER",
        ] {
            c.env_remove(v);
        }
        let run = dir.join("run");
        if std::fs::create_dir(&run).is_ok() {
            std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700))?;
        }
        c.env("XDG_RUNTIME_DIR", &run);
    }
    c.stdin(std::process::Stdio::null())
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
    let dir = session_dir(mode.name())?;
    let sock = socket_path(&dir);
    if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
        bail!("a desktop session is already running");
    }
    if mode == Mode::Screen {
        return run_screen(&dir, &sock);
    }
    let bundle = bundle::find().ok_or_else(|| anyhow!("desktop components missing: run meshvpn desktop setup"))?;
    let mut cookie = [0u8; 16];
    cookie.copy_from_slice(&crate::keys::random32()[..16]);
    let xauth = dir.join("Xauthority");
    write_xauthority(&xauth, &cookie)?;
    let fonts_conf = dir.join("fonts.conf");
    let font_cache = dir.join("fontcache");
    write_fonts_conf(&fonts_conf, &bundle, &font_cache)?;

    // VirtualGL needs an X server with GLX, as Cinnamon does: then the system's Xvfb.
    let mut gpu = gl_on_gpu();
    let system = (mode == Mode::Cinnamon || !gpu.is_empty()).then(system_xvfb).flatten();
    if !gpu.is_empty() && system.is_none() {
        warn!(
            "3D: VirtualGL needs the system's Xvfb (install it, or `meshvpn desktop setup --gpu`) - OpenGL on the CPU"
        );
        gpu.clear();
    }
    let (mut xvfb, dpy) = start_xvfb(&bundle, &xauth, system.as_deref())?;
    info!("Xvfb running as display :{dpy}");
    // For the viewer at the desk (it copies the keyboard layout there to here).
    std::fs::write(dir.join("display"), format!(":{dpy}"))?;
    let path = format!("/tmp/.X11-unix/X{dpy}");
    let unix = std::os::unix::net::UnixStream::connect(&path).with_context(|| format!("connecting to {path}"))?;
    let (stream, _) = DefaultStream::from_unix_stream(unix)?;
    let conn =
        RustConnection::connect_to_stream_with_auth_info(stream, 0, b"MIT-MAGIC-COOKIE-1".to_vec(), cookie.to_vec())
            .context("connecting to Xvfb")?;

    let env = AppEnv {
        display: format!(":{dpy}"),
        xauthority: Some(xauth.clone()),
        fonts_conf: Some(fonts_conf.clone()),
        dir: dir.clone(),
        proxy: login_proxy(),
        chrome_home: browser_home(),
        desktop: mode.environment(),
        gpu,
    };
    if let Some(h) = &env.chrome_home {
        info!("Chrome runs with its own profile here: {}", h.display());
    }
    if !env.proxy.is_empty() {
        let names: Vec<&str> = env.proxy.iter().map(|(k, _)| k.as_str()).collect();
        info!("proxy settings of a login: {}", names.join(", "));
    }
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    let mut desk = Desk::new(conn, env, mode)?;
    std::fs::write(dir.join("mode"), mode.name())?;
    if let Some(line) = mode.start_line() {
        if mode == Mode::Xfce {
            prepare_xfce();
        }
        no_screen_lock(&dir);
        desk.session = Some(
            desk.spawn(&line)
                .with_context(|| format!("starting {}", mode.label()))?,
        );
        info!("{} started", mode.label());
    }

    let result = serve(&mut desk, &sock, cmd_tx, cmd_rx);
    let _ = xvfb.kill();
    let _ = xvfb.wait();
    result
}

/// Takes browsers on `sock` and runs the session until it ends.
fn serve(desk: &mut Desk, sock: &Path, cmd_tx: mpsc::Sender<Cmd>, cmd_rx: mpsc::Receiver<Cmd>) -> Result<()> {
    // The socket for attaching browsers.
    let _ = std::fs::remove_file(sock);
    let listener = std::os::unix::net::UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))?;
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
    let _ = std::fs::remove_file(sock);
    drop(rt);
    result
}

/// `meshvpn desktop <node> --screen`: the machine's own screen, as the person logged in there
/// sees it. Nothing is started or resized; it ends when the last browser leaves.
fn run_screen(dir: &Path, sock: &Path) -> Result<()> {
    let (screen, xauth) = local_screen(dir)?;
    info!("sharing the screen {screen}");
    if let Some(x) = &xauth {
        // Safety: no other threads yet.
        unsafe { std::env::set_var("XAUTHORITY", x) };
    }
    let (conn, _) =
        RustConnection::connect(Some(&screen)).with_context(|| format!("connecting to the screen {screen}"))?;
    let env = AppEnv {
        display: screen,
        xauthority: xauth,
        fonts_conf: None,
        dir: dir.to_path_buf(),
        proxy: vec![],
        chrome_home: None,
        desktop: vec![],
        gpu: vec![],
    };
    std::fs::write(dir.join("mode"), Mode::Screen.name())?;
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    let mut desk = Desk::new(conn, env, Mode::Screen)?;
    let result = serve(&mut desk, sock, cmd_tx, cmd_rx);
    desk.restore_keys();
    result
}

/// "7" for ":7" or ":7.0".
fn display_number(d: &str) -> String {
    d.trim_start_matches(':').split('.').next().unwrap_or("").to_string()
}

/// The (real) user running the X server of display `n`, if there is one.
fn x_server_uid(n: &str) -> Option<u32> {
    let want = format!(":{n}");
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let comm = std::fs::read_to_string(e.path().join("comm")).unwrap_or_default();
        if !comm.starts_with('X') {
            continue;
        }
        let cmdline = std::fs::read(e.path().join("cmdline")).unwrap_or_default();
        if !cmdline.split(|b| *b == 0).any(|a| a == want.as_bytes()) {
            continue;
        }
        let status = std::fs::read_to_string(e.path().join("status")).ok()?;
        return status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|v| v.split_whitespace().next()?.parse().ok());
    }
    None
}

/// The X display of this user's desktop at the machine (logind's local session), and its
/// Xauthority. Without logind: the display the user's own programs use.
fn local_screen(own: &Path) -> Result<(String, Option<PathBuf>)> {
    let uid = unsafe { libc::geteuid() };
    let mut display = None;
    let mut wayland = false;
    let mut others: Vec<String> = vec![];
    if let Ok(o) = std::process::Command::new("loginctl")
        .args(["list-sessions", "--no-legend"])
        .stderr(std::process::Stdio::null())
        .output()
    {
        for id in String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| l.split_whitespace().next())
        {
            let Ok(o) = std::process::Command::new("loginctl")
                .args([
                    "show-session",
                    id,
                    "-p",
                    "User",
                    "-p",
                    "Type",
                    "-p",
                    "Display",
                    "-p",
                    "Remote",
                    "-p",
                    "State",
                ])
                .stderr(std::process::Stdio::null())
                .output()
            else {
                continue;
            };
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            let get = |k: &str| {
                text.lines()
                    .find_map(|l| l.strip_prefix(&format!("{k}=")))
                    .unwrap_or("")
                    .to_string()
            };
            if get("User") != uid.to_string() {
                // Someone else's screen: never this user's, whatever their programs say.
                if !get("Display").is_empty() {
                    others.push(display_number(&get("Display")));
                }
                continue;
            }
            if get("Remote") != "no" || get("State") == "closing" {
                continue;
            }
            match get("Type").as_str() {
                "x11" if !get("Display").is_empty() => display = Some(get("Display")),
                "wayland" => wayland = true,
                _ => {}
            }
        }
    }
    // The environments of this user's programs: the Xauthority of that display, or the display
    // itself where there is no logind. Not those of meshvpn's own desktops.
    let mut seen: Vec<(String, Option<PathBuf>)> = vec![];
    let base = own.parent().unwrap_or(own).to_path_buf();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if !e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if e.metadata().map(|m| m.uid() != uid).unwrap_or(true) {
                continue;
            }
            let Ok(raw) = std::fs::read(e.path().join("environ")) else {
                continue;
            };
            let vars: HashMap<&str, &str> = raw
                .split(|b| *b == 0)
                .filter_map(|kv| std::str::from_utf8(kv).ok()?.split_once('='))
                .collect();
            let Some(d) = vars.get("DISPLAY").filter(|d| d.starts_with(':')) else {
                continue;
            };
            let xa = vars.get("XAUTHORITY").map(PathBuf::from);
            if xa
                .as_ref()
                .is_some_and(|x| x.starts_with(&base) || x.starts_with("/tmp/meshvpn-desktop-"))
            {
                continue;
            }
            if vars.get("XDG_SESSION_TYPE") == Some(&"wayland") {
                wayland = true;
                continue;
            }
            seen.push((d.to_string(), xa));
        }
    }
    let display = match display {
        Some(d) => d,
        None => {
            // The display most of them use, if its X server is there and runs as this user (not
            // knowing logind, nothing else says whose screen it is: a display someone else opened
            // to all, `xhost +`, stays theirs).
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for (d, _) in &seen {
                *counts.entry(d.as_str()).or_default() += 1;
            }
            let running: Vec<(&str, usize)> = counts
                .into_iter()
                .filter(|(d, _)| Path::new(&format!("/tmp/.X11-unix/X{}", display_number(d))).exists())
                .collect();
            let found = running
                .iter()
                .filter(|(d, _)| !others.contains(&display_number(d)) && x_server_uid(&display_number(d)) == Some(uid))
                .max_by_key(|(_, c)| *c)
                .map(|(d, _)| d.to_string());
            match found {
                Some(d) => d,
                None if !running.is_empty() => bail!(
                    "the screen your programs here use ({}) is not yours - only the person logged in at a screen \
                     can share it",
                    running.iter().map(|(d, _)| *d).collect::<Vec<_>>().join(", ")
                ),
                None if wayland => bail!(
                    "the desktop on this machine's screen is a Wayland session, which can't be shared this way -                      log in there with an X11 (Xorg) session to share it, or use the desktop of its own                      (meshvpn desktop <node>, without --screen)"
                ),
                None => bail!(
                    "nobody is logged in to a desktop on this machine's screen as this user -                      use the desktop of its own (meshvpn desktop <node>, without --screen)"
                ),
            }
        }
    };
    let xauth = seen
        .iter()
        .filter(|(d, _)| *d == display)
        .find_map(|(_, x)| x.clone())
        .filter(|x| x.is_file())
        .or_else(|| {
            let h = PathBuf::from(std::env::var_os("HOME")?).join(".Xauthority");
            h.is_file().then_some(h)
        });
    Ok((display, xauth))
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

/// VirtualGL for the whole session, as TurboVNC does it: every program's OpenGL renders on a GPU
/// (EGL, no X server on it needed) and the finished picture goes into the session's X server.
/// The GPU: MESHVPN_DESKTOP_GPU (a /dev/dri/card* device, "egl" for EGL's own choice, or "off"),
/// else the first GPU this user may use (its device is accessible: with bookings, the booked
/// one). Nothing without VirtualGL (`meshvpn desktop setup --gpu`).
fn gl_on_gpu() -> Vec<(String, String)> {
    let want = std::env::var("MESHVPN_DESKTOP_GPU").unwrap_or_default();
    if want == "off" {
        return vec![];
    }
    let Some(lib) = ["/usr/lib", "/usr/lib64", "/opt/VirtualGL/lib", "/opt/VirtualGL/lib64"]
        .into_iter()
        .map(Path::new)
        .find(|d| d.join("libvglfaker.so").is_file() && d.join("libdlfaker.so").is_file())
    else {
        return vec![];
    };
    let device = if !want.is_empty() {
        Some(want)
    } else {
        let mut cards: Vec<PathBuf> = std::fs::read_dir("/dev/dri")
            .map(|d| d.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        cards.sort();
        cards
            .into_iter()
            .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("card")))
            .find(|p| {
                let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
                // A real GPU (not a firmware framebuffer), and ours to use.
                let driver = std::fs::read_link(format!("/sys/class/drm/{name}/device/driver"))
                    .ok()
                    .and_then(|d| d.file_name().map(|f| f.to_string_lossy().into_owned()))
                    .unwrap_or_default();
                let ok = ["nvidia", "amdgpu", "radeon", "i915", "xe", "nouveau"].contains(&driver.as_str());
                let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap_or_default();
                ok && unsafe { libc::access(c.as_ptr(), libc::R_OK | libc::W_OK) } == 0
            })
            .map(|p| p.display().to_string())
    };
    let Some(device) = device else {
        info!("3D: VirtualGL is installed, but no GPU here is this user's to use - OpenGL on the CPU");
        return vec![];
    };
    info!("3D: VirtualGL on {device}");
    let mut preload = format!(
        "{}:{}",
        lib.join("libdlfaker.so").display(),
        lib.join("libvglfaker.so").display()
    );
    if let Ok(p) = std::env::var("LD_PRELOAD")
        && !p.is_empty()
    {
        preload = format!("{p}:{preload}");
    }
    vec![
        ("LD_PRELOAD".into(), preload),
        ("VGL_DISPLAY".into(), device),
        // A whole desktop runs under it (window manager, compositor).
        ("VGL_WM".into(), "1".into()),
    ]
}

/// No screen locker in this session: it would lock a desktop that only a browser shows, and
/// accounts that log in with keys often have no password to unlock it with. (Cinnamon starts
/// its own over D-Bus: that one stays.) Per session: the
/// autostart entries are hidden through a directory of its own first in XDG_CONFIG_DIRS (the
/// user's desktop at the machine keeps its locker).
fn no_screen_lock(dir: &Path) {
    let auto = dir.join("xdg/autostart");
    let _ = std::fs::create_dir_all(&auto);
    for name in [
        "mate-screensaver",
        "xfce4-screensaver",
        "xscreensaver",
        "light-locker",
        "gnome-screensaver",
        "cinnamon-screensaver",
    ] {
        let _ = std::fs::write(
            auto.join(format!("{name}.desktop")),
            format!("[Desktop Entry]\nType=Application\nName={name}\nExec={name}\nHidden=true\n"),
        );
    }
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

/// The bundled Xvfb, or `system`'s (the system's own, with OpenGL through Mesa).
fn start_xvfb(bundle: &Bundle, xauth: &Path, system: Option<&Path>) -> Result<(std::process::Child, u32)> {
    use std::os::unix::process::CommandExt;
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    let (rfd, wfd) = (fds[0], fds[1]);
    let mut c = std::process::Command::new(system.map(Path::to_path_buf).unwrap_or_else(|| bundle.xvfb()));
    c.args(["-displayfd", "3", "-auth"])
        .arg(xauth)
        .args(["-nolisten", "tcp", "-screen", "0"])
        .arg(format!("{MAX_W}x{MAX_H}x24"))
        .args(["-dpi", "96", "+extension", "RANDR"]);
    if system.is_some() {
        c.args(["+extension", "GLX"]);
    } else {
        c.args(["-fp", "built-ins", "-xkbdir"])
            .arg(bundle.xkb_dir())
            .env("MESHVPN_XKB_BIN", bundle.bin_dir());
    }
    c.stdin(std::process::Stdio::null());
    unsafe {
        c.pre_exec(move || {
            if libc::dup2(wfd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Ends with the session, however that ends.
            crate::sys::die_with_parent();
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
    xauthority: Option<PathBuf>,
    fonts_conf: Option<PathBuf>,
    /// The session's own directory (session.log, mode).
    dir: PathBuf,
    /// The proxy settings of a login (see `login_proxy`).
    proxy: Vec<(String, String)>,
    /// Chrome's own profile for this desktop (see `browser_home`).
    chrome_home: Option<PathBuf>,
    /// What the desktop's programs check to know where they are (XDG_SESSION_TYPE and co.).
    desktop: Vec<(&'static str, &'static str)>,
    /// VirtualGL: OpenGL of every program on the GPU (see `gl_on_gpu`).
    gpu: Vec<(String, String)>,
}

/// Chrome and Chromium hand a start over to a browser of the same profile that already runs on
/// this machine, and that one opens the window on its own screen: on a machine with a local
/// desktop, Chrome would appear there and not here. So while the usual profile is in use, the
/// browsers of this desktop get a profile of their own (`CHROME_CONFIG_HOME`), and keep it from
/// then on, so bookmarks and logins don't change between sessions.
fn browser_home() -> Option<PathBuf> {
    if std::env::var_os("CHROME_CONFIG_HOME").is_some() {
        return None;
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let own = home.join(".config/meshvpn-desktop");
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    const PROFILES: &[&str] = &[
        "google-chrome",
        "google-chrome-beta",
        "google-chrome-unstable",
        "chromium",
        "microsoft-edge",
        "BraveSoftware/Brave-Browser",
        "vivaldi",
    ];
    let host = crate::sys::hostname();
    // The lock names "<host>-<pid>" of the browser holding it.
    let running = |dir: &str| {
        std::fs::read_link(config.join(dir).join("SingletonLock"))
            .ok()
            .and_then(|t| {
                let t = t.to_string_lossy().into_owned();
                let (h, pid) = t.rsplit_once('-')?;
                Some(h == host && Path::new(&format!("/proc/{pid}")).exists())
            })
            .unwrap_or(false)
    };
    let used = PROFILES.iter().any(|d| own.join(d).exists());
    (used || PROFILES.iter().any(|d| running(d))).then_some(own)
}

const PROXY_VARS: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "ftp_proxy",
    "all_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "FTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
];

/// The proxy settings a login of this user gets: from /etc/environment, and from the login
/// scripts (/etc/profile, /etc/profile.d, ~/.profile), where companies usually set them. This
/// session starts over ssh without a login, so it lacks them, and a browser that doesn't know the
/// proxy can't log in to it. Those already set here win.
fn login_proxy() -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = vec![];
    let mut add = |k: &str, v: &str| {
        let v = v.trim().trim_matches('"').trim_matches('\'');
        if PROXY_VARS.contains(&k)
            && !v.is_empty()
            && std::env::var_os(k).is_none()
            && !found.iter().any(|(f, _)| f == k)
        {
            found.push((k.to_string(), v.to_string()));
        }
    };
    let etc = std::fs::read_to_string("/etc/environment").unwrap_or_default();
    // A login shell's environment, in a few seconds at most (a script could wait for input).
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| s.starts_with('/'))
        .unwrap_or("/bin/sh".into());
    let login = std::process::Command::new("timeout")
        .args(["5", &shell, "-l", "-c", "env"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    for line in login.lines().chain(etc.lines()) {
        let line = line.trim().trim_start_matches("export ");
        if let Some((k, v)) = line.split_once('=') {
            add(k.trim(), v);
        }
    }
    found
}

struct Client {
    id: u64,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    inflight: u32,
    /// The viewer on this machine's own screen (`meshvpn desktop local`): raw pixels, its
    /// keyboard's key codes, and its screen size wins.
    local: bool,
    /// Gets the H.264 stream instead of tiles (it said it can decode it, and there's an encoder).
    video: bool,
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
    /// The machine's own screen (--screen): its size stays, and it is shared only while watched.
    screen: bool,
    /// --screen: the monitors of that screen, and the one shown (`None`: all of them).
    monitors: Vec<Monitor>,
    view: Option<usize>,
    /// H.264: the encoder this machine has (None: not looked yet), and the running one.
    video_kind: Option<Option<super::video::Kind>>,
    encoder: Option<super::video::Encoder>,
    /// Monitors set up like the desk's while someone sits there.
    desk_monitors: Vec<Atom>,
    /// Where the part shown starts on the X screen.
    ox: u16,
    oy: u16,
}

/// A monitor of the shared screen (RandR).
#[derive(serde::Serialize, Clone)]
struct Monitor {
    name: String,
    primary: bool,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
}

impl Desk {
    fn new(conn: RustConnection, env: AppEnv, mode: Mode) -> Result<Self> {
        let screen = conn.setup().roots[0].clone();
        let root = screen.root;
        let atoms = Atoms::new(&conn)?.reply()?;
        conn.damage_query_version(1, 1)?.reply().context("DAMAGE extension")?;
        conn.xfixes_query_version(5, 0)?.reply().context("XFIXES extension")?;
        // 1.5 for the monitors of a shared screen.
        let _ = conn.randr_query_version(1, 5)?.reply();
        let external_wm = mode != Mode::Plain;
        let shared = mode == Mode::Screen;

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
        if !shared {
            conn.change_window_attributes(root, &ChangeWindowAttributesAux::new().background_pixel(0x2b2f36))?;
            conn.clear_area(false, root, 0, 0, 0, 0)?;
        }

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
            screen: shared,
            monitors: vec![],
            desk_monitors: vec![],
            video_kind: None,
            encoder: None,
            view: None,
            ox: 0,
            oy: 0,
        };
        if shared {
            d.load_monitors();
        }
        d.load_keymap()?;
        d.resize(1280, 800);
        d.update_cursor();
        Ok(d)
    }

    fn run(&mut self, rx: mpsc::Receiver<Cmd>) -> Result<()> {
        let mut last_reap = Instant::now();
        let mut last_touch = Instant::now();
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
            if self.video_out() {
                busy = true;
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
            if last_touch.elapsed() > Duration::from_secs(3600) {
                // Cleaners of /tmp (systemd-tmpfiles) remove what hasn't changed in days.
                for f in [self.env.dir.clone(), socket_path(&self.env.dir)] {
                    if let Ok(c) = std::ffi::CString::new(f.as_os_str().as_encoded_bytes()) {
                        unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), std::ptr::null(), 0) };
                    }
                }
                last_touch = Instant::now();
            }
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
                if self.screen {
                    // Monitors plugged in or arranged since.
                    self.load_monitors();
                }
                let c = Client {
                    id,
                    tx,
                    inflight: 0,
                    local: false,
                    video: false,
                };
                let mut hello = frame(S_INIT, &[self.w.to_le_bytes(), self.h.to_le_bytes()].concat());
                hello.extend(self.windows_msg());
                // Apps installed since the session started show up too.
                self.apps = frame(S_APPS, &serde_json::to_vec(&list_apps()).unwrap_or_default());
                hello.extend(self.apps.clone());
                if let Some(cur) = &self.cursor {
                    hello.extend(cur.clone());
                }
                if c.tx.try_send(hello).is_ok() {
                    if self.screen && self.clients.is_empty() {
                        self.tell_screen("Your screen is being shared through meshvpn desktop.");
                    }
                    self.clients.push(c);
                }
                self.full = true;
                self.dirty = true;
            }
            Cmd::Leave(id) => {
                let was_local = self.is_local(id);
                self.clients.retain(|c| c.id != id);
                if !self.clients.iter().any(|c| c.video) {
                    self.encoder = None;
                }
                if was_local && !self.clients.iter().any(|c| c.local) {
                    let _ = self.set_desk_monitors(&[]);
                    let _ = self.conn.change_keyboard_control(
                        &ChangeKeyboardControlAux::new().auto_repeat_mode(AutoRepeatMode::DEFAULT),
                    );
                }
                if self.screen && self.clients.is_empty() {
                    self.tell_screen("Your screen is no longer shared.");
                    self.stop = true;
                }
            }
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
            // At the desk, the desk's screen size wins.
            C_RESIZE if !self.is_local(from) && self.clients.iter().any(|c| c.local) => {
                let init = frame(S_INIT, &[self.w.to_le_bytes(), self.h.to_le_bytes()].concat());
                self.send_to(from, init);
            }
            C_RESIZE => self.resize(u16_at(p, 0), u16_at(p, 2)),
            C_CAPS => {
                let caps: serde_json::Value = serde_json::from_slice(p).unwrap_or_default();
                let wants = caps["video"].as_array().is_some_and(|a| a.iter().any(|v| v == "h264"));
                if wants && self.video_kind.is_none() {
                    // Once per session: which encoder this machine has.
                    let k = super::video::pick();
                    info!(
                        "video: {}",
                        k.as_ref()
                            .map(|k| k.name())
                            .unwrap_or("no hardware encoder - picture tiles".into())
                    );
                    self.video_kind = Some(k);
                }
                let on = wants && matches!(self.video_kind, Some(Some(_)));
                if let Some(c) = self.clients.iter_mut().find(|c| c.id == from) {
                    c.video = on;
                    c.inflight = 0;
                }
                if on {
                    // A new decoder starts with a key frame: a new stream for all.
                    self.encoder = None;
                }
                self.full = true;
                self.dirty = true;
            }
            C_LOCAL => {
                if let Some(c) = self.clients.iter_mut().find(|c| c.id == from) {
                    c.local = true;
                }
                // The desk's keyboard repeats keys itself.
                self.conn
                    .change_keyboard_control(&ChangeKeyboardControlAux::new().auto_repeat_mode(AutoRepeatMode::OFF))?;
                // And its monitors are this screen's.
                let list: Vec<(i16, i16, u16, u16, bool)> = serde_json::from_slice::<serde_json::Value>(p)
                    .ok()
                    .and_then(|v| {
                        v["monitors"].as_array().map(|a| {
                            a.iter()
                                .filter_map(|m| {
                                    Some((
                                        m["x"].as_i64()? as i16,
                                        m["y"].as_i64()? as i16,
                                        m["w"].as_u64()? as u16,
                                        m["h"].as_u64()? as u16,
                                        m["primary"].as_bool().unwrap_or(false),
                                    ))
                                })
                                .collect()
                        })
                    })
                    .unwrap_or_default();
                if let Err(e) = self.set_desk_monitors(&list) {
                    warn!("the desk's monitors: {e:#}");
                }
                self.full = true;
                self.dirty = true;
            }
            C_RAWKEY => {
                let (down, kc) = (p.first().copied().unwrap_or(0) == 1, p.get(1).copied().unwrap_or(0));
                if kc >= 8 {
                    let kind = if down { KEY_PRESS_EVENT } else { KEY_RELEASE_EVENT };
                    self.conn.xtest_fake_input(kind, kc, 0, self.root, 0, 0, 0)?;
                }
            }
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
            C_MONITOR if self.screen => {
                self.load_monitors();
                let v = p.first().copied().unwrap_or(255) as usize;
                self.view = (v < self.monitors.len()).then_some(v);
                let (w, h) = (self.w, self.h);
                self.resize(w, h);
            }
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
            .envs(self.env.xauthority.iter().map(|x| ("XAUTHORITY", x)))
            .envs(self.env.fonts_conf.iter().map(|f| ("FONTCONFIG_FILE", f)))
            .env("NO_AT_BRIDGE", "1")
            .env("GDK_BACKEND", "x11")
            .env("QT_QPA_PLATFORM", "xcb")
            .env_remove("WAYLAND_DISPLAY")
            .envs(self.env.proxy.iter().map(|(k, v)| (k, v)))
            .envs(self.env.chrome_home.iter().map(|h| ("CHROME_CONFIG_HOME", h)))
            .envs(self.env.desktop.iter().copied())
            .envs(self.env.gpu.iter().map(|(k, v)| (k, v)))
            .envs((!self.screen).then(|| {
                let dirs = std::env::var("XDG_CONFIG_DIRS")
                    .ok()
                    .filter(|d| !d.is_empty())
                    .unwrap_or_else(|| "/etc/xdg".into());
                (
                    "XDG_CONFIG_DIRS",
                    format!("{}:{dirs}", self.env.dir.join("xdg").display()),
                )
            }))
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
        if self.screen {
            // A real screen keeps its size (the browser scales it): the monitor shown, or all.
            self.show_view();
        } else if (w, h) != (self.w, self.h) || self.prev.is_empty() {
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

    /// --screen: the monitors as RandR has them now, left to right; shown first: the primary.
    fn load_monitors(&mut self) {
        let Ok(Ok(r)) = self.conn.randr_get_monitors(self.root, true).map(|c| c.reply()) else {
            return;
        };
        let mut list: Vec<Monitor> = r
            .monitors
            .iter()
            .filter(|m| m.width > 0 && m.height > 0)
            .map(|m| Monitor {
                name: self
                    .conn
                    .get_atom_name(m.name)
                    .ok()
                    .and_then(|c| c.reply().ok())
                    .map(|n| String::from_utf8_lossy(&n.name).into_owned())
                    .unwrap_or_default(),
                primary: m.primary,
                x: m.x.max(0) as u16,
                y: m.y.max(0) as u16,
                w: m.width,
                h: m.height,
            })
            .collect();
        // One spanning others (a virtual screen's own output, say) isn't a monitor of its own.
        let inside =
            |a: &Monitor, b: &Monitor| a.x >= b.x && a.y >= b.y && a.x + a.w <= b.x + b.w && a.y + a.h <= b.y + b.h;
        let all = list.clone();
        list.retain(|b| !all.iter().any(|a| (a.w, a.h) != (b.w, b.h) && inside(a, b)));
        list.sort_by_key(|m| (m.x, m.y));
        let first = self.monitors.len() < 2;
        self.monitors = list;
        if self.monitors.len() < 2 {
            self.view = None;
        } else if first || self.view.is_some_and(|v| v >= self.monitors.len()) {
            self.view = Some(self.monitors.iter().position(|m| m.primary).unwrap_or(0));
        }
    }

    /// --screen: the part of the screen shown to the browsers, and the monitor list for its
    /// switcher.
    fn show_view(&mut self) {
        let (ox, oy, w, h) = match self.view.and_then(|v| self.monitors.get(v)) {
            Some(m) => (m.x, m.y, m.w, m.h),
            None => {
                let g = self.conn.get_geometry(self.root).ok().and_then(|c| c.reply().ok());
                g.map(|g| (0, 0, g.width, g.height)).unwrap_or((0, 0, self.w, self.h))
            }
        };
        let (w, h) = (w.min(MAX_W), h.min(MAX_H));
        if (ox, oy, w, h) != (self.ox, self.oy, self.w, self.h) || self.prev.is_empty() {
            (self.ox, self.oy, self.w, self.h) = (ox, oy, w, h);
            self.prev = vec![0; w as usize * h as usize * 4];
        }
        let list = serde_json::json!({ "monitors": self.monitors, "view": self.view });
        let msg = frame(S_MONITORS, list.to_string().as_bytes());
        self.broadcast(&msg);
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
                .shm_get_image(
                    self.root,
                    self.ox as i16,
                    self.oy as i16,
                    w,
                    h,
                    !0,
                    ImageFormat::Z_PIXMAP.into(),
                    s.seg,
                    0,
                )?
                .reply()?;
            let data = unsafe { std::slice::from_raw_parts(s.addr, len) };
            return Ok(data.to_vec());
        }
        let r = self
            .conn
            .get_image(
                ImageFormat::Z_PIXMAP,
                self.root,
                self.ox as i16,
                self.oy as i16,
                w,
                h,
                !0,
            )?
            .reply()?;
        Ok(r.data)
    }

    /// Monitors like the desk's (two or more), or none of its own again (`list` empty).
    fn set_desk_monitors(&mut self, list: &[(i16, i16, u16, u16, bool)]) -> Result<()> {
        for name in std::mem::take(&mut self.desk_monitors) {
            self.conn.randr_delete_monitor(self.root, name)?;
        }
        if list.len() < 2 {
            self.conn.flush()?;
            return Ok(());
        }
        let res = self.conn.randr_get_screen_resources_current(self.root)?.reply()?;
        let mm = |px: u16| (px as u32 * 254 / 960).max(1);
        for (i, &(x, y, w, h, primary)) in list.iter().enumerate() {
            let name = self
                .conn
                .intern_atom(false, format!("DESK-{}", i + 1).as_bytes())?
                .reply()?
                .atom;
            // The first takes the screen's output: its automatic monitor (all of it) goes.
            let outputs = if i == 0 {
                res.outputs.first().copied().into_iter().collect()
            } else {
                vec![]
            };
            self.conn
                .randr_set_monitor(
                    self.root,
                    randr::MonitorInfo {
                        name,
                        primary,
                        automatic: false,
                        x,
                        y,
                        width: w,
                        height: h,
                        width_in_millimeters: mm(w),
                        height_in_millimeters: mm(h),
                        outputs,
                    },
                )?
                .check()?;
            self.desk_monitors.push(name);
        }
        Ok(())
    }

    fn is_local(&self, id: u64) -> bool {
        self.clients.iter().any(|c| c.id == id && c.local)
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
        let (want_enc, want_raw) = (
            self.clients.iter().any(|c| !c.local && !c.video),
            self.clients.iter().any(|c| c.local),
        );
        let mut any_change = false;
        let mut out = vec![];
        let mut raw_out = vec![];
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
                any_change = true;
                for y in ty..ty + th {
                    let a = y * stride + tx * 4;
                    self.prev[a..a + tw * 4].copy_from_slice(&cur[a..a + tw * 4]);
                }
                let mut head = Vec::with_capacity(9);
                for v in [tx as u16, ty as u16, tw as u16, th as u16] {
                    head.extend_from_slice(&v.to_le_bytes());
                }
                if want_enc {
                    let (fmt, img) = encode_tile(&cur, stride, tx, ty, tw, th);
                    let mut p = head.clone();
                    p.push(fmt);
                    p.extend_from_slice(&img);
                    out.extend(frame(S_TILE, &p));
                }
                if want_raw {
                    // On the same machine: the pixels as they are (BGRX rows).
                    let mut p = Vec::with_capacity(9 + tw * th * 4);
                    p.extend_from_slice(&head);
                    p.push(TILE_RAW);
                    for y in ty..ty + th {
                        let a = y * stride + tx * 4;
                        p.extend_from_slice(&cur[a..a + tw * 4]);
                    }
                    raw_out.extend(frame(S_TILE, &p));
                }
            }
        }
        self.full = false;
        if any_change && self.clients.iter().any(|c| c.video) {
            self.encode(&cur);
        }
        if out.is_empty() && raw_out.is_empty() {
            return;
        }
        out.extend(frame(S_FRAME_END, b""));
        raw_out.extend(frame(S_FRAME_END, b""));
        self.clients.retain_mut(|c| {
            if c.video {
                return true;
            }
            c.inflight += 1;
            c.tx.try_send(if c.local { raw_out.clone() } else { out.clone() })
                .is_ok()
        });
    }

    /// The frame to the H.264 encoder (started, or started again at a new size). H.264 wants an
    /// even size: an odd last row or column is left out.
    fn encode(&mut self, cur: &[u8]) {
        let Some(kind) = self.video_kind.clone().flatten() else {
            return;
        };
        let (w, h) = (self.w & !1, self.h & !1);
        if self.encoder.as_ref().is_none_or(|e| (e.w, e.h) != (w, h)) {
            self.encoder = None;
            match super::video::Encoder::start(&kind, w, h) {
                Ok(e) => self.encoder = Some(e),
                Err(e) => {
                    warn!("video: {e:#} - picture tiles instead");
                    self.no_video();
                    return;
                }
            }
        }
        let Some(enc) = &self.encoder else { return };
        if (w, h) == (self.w, self.h) {
            enc.frame(cur);
        } else {
            let (sw, dw) = (self.w as usize * 4, w as usize * 4);
            let mut c = Vec::with_capacity(dw * h as usize);
            for y in 0..h as usize {
                c.extend_from_slice(&cur[y * sw..y * sw + dw]);
            }
            enc.frame(&c);
        }
    }

    /// The encoder's frames to the browsers that take them.
    fn video_out(&mut self) -> bool {
        let Some(enc) = &self.encoder else { return false };
        let mut msgs = vec![];
        let mut ended = false;
        loop {
            match enc.out.try_recv() {
                Ok(p) => msgs.push(p),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    ended = true;
                    break;
                }
            }
        }
        let busy = !msgs.is_empty();
        for p in msgs {
            let counts = p[0] != super::video::CONFIG;
            let m = frame(S_VIDEO, &p);
            self.clients.retain_mut(|c| {
                if !c.video {
                    return true;
                }
                if counts {
                    c.inflight += 1;
                }
                c.tx.try_send(m.clone()).is_ok()
            });
        }
        if ended {
            warn!("video: the encoder stopped - picture tiles instead");
            self.no_video();
        }
        busy
    }

    /// Back to tiles for everyone (the encoder failed).
    fn no_video(&mut self) {
        self.encoder = None;
        self.video_kind = Some(None);
        for c in &mut self.clients {
            c.video = false;
            c.inflight = 0;
        }
        self.full = true;
        self.dirty = true;
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
        let _ = std::fs::write(self.env.dir.join("mode"), "plain");
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
            (x.min(self.w.saturating_sub(1)) + self.ox) as i16,
            (y.min(self.h.saturating_sub(1)) + self.oy) as i16,
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

    /// The spare keycodes bound to typed characters free again (on a real screen they would
    /// stay in its keymap).
    fn restore_keys(&mut self) {
        for (_, kc) in self.char_keys.drain() {
            let _ = self.conn.change_keyboard_mapping(1, kc, 4, &[0; 4]);
        }
        for (_, kc) in self.pressed.drain() {
            let _ = self.conn.xtest_fake_input(KEY_RELEASE_EVENT, kc, 0, self.root, 0, 0, 0);
        }
        let _ = self.conn.flush();
    }

    /// A notification on the shared screen itself, for whoever sits in front of it.
    fn tell_screen(&self, text: &str) {
        if which("notify-send") {
            let _ = self.spawn(&format!("exec notify-send -a meshvpn meshvpn '{text}'"));
        }
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
