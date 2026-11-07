//! Sessions of the built-in SSH server (Unix).

use super::*;
use anyhow::Result;
use russh::keys::PublicKey;
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, ChannelOpenFailure};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::node::Node;

/// Serves one SSH connection that came in from mesh address `peer`.
pub async fn serve<S>(node: Arc<Node>, stream: S, peer: SocketAddr, local: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let attempts = Arc::new(Mutex::new(Attempts::default()));
    let handler = Conn {
        node: node.clone(),
        peer,
        local,
        account: None,
        who: String::new(),
        channels: HashMap::new(),
        ptys: Arc::new(Mutex::new(HashMap::new())),
        attempts: attempts.clone(),
    };
    match russh::server::run_stream(node.ssh_config(), stream, handler).await {
        Ok(session) => {
            if let Err(e) = session.await {
                debug!("ssh from {peer}: {e:#}");
            }
        }
        Err(e) => debug!("ssh from {peer}: {e:#}"),
    }
    // A login that never succeeded: say why, once per connection (clients try several keys).
    let a = attempts.lock().unwrap();
    if !a.ok && !a.users.is_empty() {
        let text = format!(
            "login as {} from {}: {}",
            a.users.join("/"),
            peer.ip(),
            a.reasons.join("; ")
        );
        info!("ssh: refused {text}");
        node.ssh_refused(text);
    }
}

/// What happened during authentication, for a useful message if it fails.
#[derive(Default)]
struct Attempts {
    ok: bool,
    users: Vec<String>,
    reasons: Vec<String>,
}

impl Attempts {
    fn note(&mut self, user: &str, reason: String) {
        if !self.users.iter().any(|u| u == user) {
            self.users.push(user.to_string());
        }
        if !self.reasons.contains(&reason) && self.reasons.len() < 6 {
            self.reasons.push(reason);
        }
    }
}

/// Kernel mode: listens on the mesh address only.
pub async fn listen(node: Arc<Node>, listener: tokio::net::TcpListener) {
    let local = listener.local_addr().ok();
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        // Only the mesh may connect (the address is routable from the LAN in principle). Over
        // IPv6 the node is known by its IPv4 mesh address all the same.
        let (ip, peer) = match peer.ip() {
            IpAddr::V4(ip) => (ip, peer),
            IpAddr::V6(ip6) => match node.mesh_ip_of6(ip6) {
                Some(ip) => (ip, SocketAddr::from((ip, peer.port()))),
                None => {
                    debug!("ssh: refusing a connection from {peer} (not a mesh address)");
                    continue;
                }
            },
        };
        if !crate::keys::in_overlay(ip) {
            debug!("ssh: refusing a connection from {peer} (not a mesh address)");
            continue;
        }
        let _ = stream.set_nodelay(true);
        let local = local
            .filter(|l| l.is_ipv4())
            .unwrap_or(SocketAddr::from((node.my_ip(), 22)));
        tokio::spawn(serve(node.clone(), stream, peer, local));
    }
}

// ---------------------------------------------------------------------------------------------
// Accounts

#[derive(Clone)]
struct Account {
    name: String,
    uid: libc::uid_t,
    gid: libc::gid_t,
    home: PathBuf,
    shell: PathBuf,
    groups: Vec<libc::gid_t>,
}

/// A shell that means "this account doesn't log in".
fn no_login_shell(shell: &str) -> bool {
    let name = Path::new(shell)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    matches!(name.as_str(), "nologin" | "false" | "git-shell" | "scponly" | "rssh")
}

fn lookup(name: &str) -> Option<Account> {
    let cname = CString::new(name).ok()?;
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 16384];
    let rc = unsafe { libc::getpwnam_r(cname.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        return None;
    }
    let s = |p: *const libc::c_char| {
        if p.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    };
    let home = PathBuf::from(s(pw.pw_dir));
    let configured = s(pw.pw_shell);
    // An account that may not log in (nologin, false): not here either - no shell, no SFTP, no
    // forwards. Also when that program is missing, which would otherwise make it /bin/sh.
    if no_login_shell(&configured) {
        return None;
    }
    // A shell missing in this image (bash in a minimal container): /bin/sh.
    let shell = Some(configured)
        .filter(|sh| !sh.is_empty() && Path::new(sh).exists())
        .unwrap_or_else(|| "/bin/sh".into());
    let mut groups = vec![0 as libc::gid_t; 64];
    loop {
        let mut n = groups.len() as libc::c_int;
        let rc = unsafe { libc::getgrouplist(cname.as_ptr(), pw.pw_gid as _, groups.as_mut_ptr() as *mut _, &mut n) };
        if rc >= 0 {
            groups.truncate(n.max(0) as usize);
            break;
        }
        if groups.len() >= 65536 {
            groups = vec![pw.pw_gid];
            break;
        }
        groups.resize((n.max(0) as usize).max(groups.len() * 2), 0);
    }
    Some(Account {
        name: name.to_string(),
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        home,
        shell: PathBuf::from(shell),
        groups,
    })
}

/// The account `user` logs in as, if this meshvpn may start processes for it.
fn account_for(user: &str) -> Option<Account> {
    let me = unsafe { libc::geteuid() };
    match lookup(user) {
        Some(acct) => (me == 0 || acct.uid == me).then_some(acct),
        None => unnamed_account(user, me),
    }
}

/// Containers often run with a number for a user, with no line in /etc/passwd: this meshvpn itself
/// can then log in under that number, and nobody else. Who may do so is still up to `ssh allow`.
fn unnamed_account(user: &str, me: libc::uid_t) -> Option<Account> {
    if me == 0 || crate::sys::user_name_of(me).is_some() || user != me.to_string() {
        return None;
    }
    let gid = unsafe { libc::getegid() };
    Some(Account {
        name: user.to_string(),
        uid: me,
        gid,
        home: std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map_or_else(|| PathBuf::from("/"), PathBuf::from),
        shell: "/bin/sh".into(),
        groups: vec![gid],
    })
}

// ---------------------------------------------------------------------------------------------
// The account's own authorized_keys

const MAX_AUTHORIZED_KEYS: u64 = 1 << 20;

/// Is `key` in the account's ~/.ssh/authorized_keys? Err says why the file or the line can't count,
/// under the rules sshd has for it: nobody else may be able to change the file.
fn own_authorized_keys(acct: &Account, key: &PublicKey) -> std::result::Result<bool, String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let ssh_dir = acct.home.join(".ssh");
    let path = ssh_dir.join("authorized_keys");
    let safe = |m: &std::fs::Metadata| (m.uid() == acct.uid || m.uid() == 0) && m.mode() & 0o022 == 0;
    // Non-blocking: as root this opens a path the user chose, which could be a pipe nobody writes to.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_NOCTTY)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };
    let meta = file.metadata().map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() || meta.len() > MAX_AUTHORIZED_KEYS {
        return Err(format!("{} is not a plain file of a sensible size", path.display()));
    }
    for (what, m) in [
        (path.as_path(), Ok(meta)),
        (ssh_dir.as_path(), std::fs::metadata(&ssh_dir)),
        (acct.home.as_path(), std::fs::metadata(&acct.home)),
    ] {
        match m {
            Ok(m) if safe(&m) => {}
            _ => {
                return Err(format!(
                    "{} is not used: others can write to {}",
                    path.display(),
                    what.display()
                ));
            }
        }
    }
    let mut text = String::new();
    file.take(MAX_AUTHORIZED_KEYS)
        .read_to_string(&mut text)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    match authorized_keys_lookup(&text, key) {
        Lookup::Listed => Ok(true),
        Lookup::Absent => Ok(false),
        Lookup::HasOptions => Err(format!(
            "this key has options in {}, which only sshd can apply",
            path.display()
        )),
    }
}

#[derive(Debug, PartialEq)]
enum Lookup {
    Listed,
    Absent,
    HasOptions,
}

/// Options (`command=`, `from=`, `restrict`...) limit what a key may do, and this server can't
/// apply them: such a key doesn't count, rather than getting more than it was given.
fn authorized_keys_lookup(text: &str, key: &PublicKey) -> Lookup {
    let same = |t: &str, b: &str| {
        let k = format!("{t} {b}");
        crate::proto::valid_ssh_key(&k) && PublicKey::from_openssh(&k).is_ok_and(|p| p.key_data() == key.key_data())
    };
    let mut with_options = false;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if crate::proto::looks_like_ssh_key(line) {
            if tokens.len() >= 2 && same(tokens[0], tokens[1]) {
                return Lookup::Listed;
            }
        } else if tokens.windows(2).any(|w| same(w[0], w[1])) {
            with_options = true;
        }
    }
    if with_options {
        Lookup::HasOptions
    } else {
        Lookup::Absent
    }
}

// ---------------------------------------------------------------------------------------------
// Connections

struct PtyReq {
    term: String,
    cols: u16,
    rows: u16,
}

#[derive(Default)]
struct Chan {
    channel: Option<Channel<Msg>>,
    pty: Option<PtyReq>,
    env: Vec<(String, String)>,
}

struct Conn {
    node: Arc<Node>,
    peer: SocketAddr,
    local: SocketAddr,
    account: Option<Account>,
    /// `user@node` of the key that logged in.
    who: String,
    channels: HashMap<ChannelId, Chan>,
    /// PTY masters by channel, for window size changes.
    ptys: Arc<Mutex<HashMap<ChannelId, Arc<OwnedFd>>>>,
    attempts: Arc<Mutex<Attempts>>,
}

enum What {
    Shell,
    Exec(String),
    Program(PathBuf, Vec<String>),
}

impl Conn {
    fn peer_ip(&self) -> Option<Ipv4Addr> {
        match self.peer.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(ip) => ip.to_ipv4_mapped(),
        }
    }

    fn allowed(&self, user: &str, key: &PublicKey) -> Option<String> {
        let Some(ip) = self.peer_ip() else {
            self.attempts
                .lock()
                .unwrap()
                .note(user, format!("{} is not a mesh address", self.peer.ip()));
            return None;
        };
        match self.node.ssh_login_check(user, ip, key) {
            Ok(who) => Some(who),
            Err(why) => {
                if let (Some(node), Some(acct)) = (self.node.ssh_own_keys_from(ip), account_for(user)) {
                    match own_authorized_keys(&acct, key) {
                        Ok(true) => return Some(format!("a key in {user}'s authorized_keys via {node}")),
                        Ok(false) => {}
                        Err(about_file) => {
                            self.attempts.lock().unwrap().note(user, format!("{why}; {about_file}"));
                            return None;
                        }
                    }
                }
                self.attempts.lock().unwrap().note(user, why);
                None
            }
        }
    }

    fn start(&mut self, id: ChannelId, what: What, session: &mut Session) -> Result<()> {
        let (Some(acct), Some(chan)) = (self.account.clone(), self.channels.get_mut(&id)) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let Some(channel) = chan.channel.take() else {
            session.channel_failure(id)?;
            return Ok(());
        };
        // Programs (sftp) never get a terminal.
        let pty = if matches!(what, What::Program(..)) {
            None
        } else {
            chan.pty.take()
        };
        let env = std::mem::take(&mut chan.env);
        let conn_env = format!(
            "{} {} {} {}",
            self.peer.ip(),
            self.peer.port(),
            self.local.ip(),
            self.local.port()
        );
        let label = match &what {
            What::Shell => "shell".to_string(),
            What::Exec(c) => format!("command {:?}", c.chars().take(80).collect::<String>()),
            What::Program(p, _) => p.display().to_string(),
        };
        debug!("ssh: {} as {}: {label}", self.who, acct.name);
        let ptys = self.ptys.clone();
        session.channel_success(id)?;
        tokio::spawn(async move {
            let result = match pty {
                Some(p) => run_pty(channel, &acct, what, env, &conn_env, p, ptys, id).await,
                None => run_pipes(channel, &acct, what, env, &conn_env).await,
            };
            if let Err(e) = result {
                warn!("ssh session as {}: {e:#}", acct.name);
            }
        });
        Ok(())
    }
}

impl russh::server::Handler for Conn {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if self.allowed(user, key).is_some() {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let Some(who) = self.allowed(user, key) else {
            return Ok(Auth::reject());
        };
        let Some(acct) = account_for(user) else {
            let why = if lookup(user).is_some() {
                format!("{who} may log in as {user}, but a rootless meshvpn can only log in its own user")
            } else {
                format!("{who} may log in as {user}, but there is no user {user} here")
            };
            self.attempts.lock().unwrap().note(user, why);
            return Ok(Auth::reject());
        };
        self.attempts.lock().unwrap().ok = true;
        info!("ssh: {who} logged in as {user}");
        self.who = who;
        self.account = Some(acct);
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.account.is_none() {
            reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        }
        self.channels.insert(
            channel.id(),
            Chan {
                channel: Some(channel),
                ..Default::default()
            },
        );
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(acct) = &self.account else {
            reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        };
        let Ok(port) = u16::try_from(port) else {
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        // Accounts that may not log in (nologin, false) forward nothing either.
        let shell = acct
            .shell
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if matches!(shell.as_str(), "nologin" | "false") {
            reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        }
        let Ok(exe) = crate::update::current_exe() else {
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        debug!("ssh: {} as {}: forwarding to {host}:{port}", self.who, acct.name);
        // The connection is made as the account, not as the daemon: what the account may reach
        // (firewall rules by user, e.g. no cloud metadata service) holds for its forwards too.
        let mut cmd = forward_command(acct, &exe, host, port);
        tokio::spawn(async move {
            let Ok(mut child) = cmd.spawn() else {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return;
            };
            let (Some(mut to), Some(mut from)) = (child.stdin.take(), child.stdout.take()) else {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return;
            };
            reply.accept().await;
            let stream = channel.into_stream();
            let (mut r, mut w) = tokio::io::split(stream);
            let up = async {
                let _ = tokio::io::copy(&mut r, &mut to).await;
                drop(to);
            };
            let down = async {
                let _ = tokio::io::copy(&mut from, &mut w).await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut w).await;
            };
            tokio::join!(up, down);
            let _ = child.kill().await;
        });
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.channels.get_mut(&channel) {
            Some(c) => {
                c.pty = Some(PtyReq {
                    term: term.to_string(),
                    cols: cols.clamp(1, 1000) as u16,
                    rows: rows.clamp(1, 1000) as u16,
                });
                session.channel_success(channel)?;
            }
            None => session.channel_failure(channel)?,
        }
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // What OpenSSH accepts by default (AcceptEnv LANG LC_*), plus COLORTERM.
        let ok = name == "LANG" || name.starts_with("LC_") || name == "COLORTERM";
        match self.channels.get_mut(&channel) {
            Some(c) if ok => {
                c.env.push((name.to_string(), value.to_string()));
                session.channel_success(channel)?;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.start(channel, What::Shell, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).into_owned();
        self.start(channel, What::Exec(cmd), session)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            session.channel_failure(channel)?;
            return Ok(());
        }
        // The system's sftp-server if there is one, else ours - both run as the user.
        let system = [
            "/usr/lib/openssh/sftp-server",
            "/usr/libexec/openssh/sftp-server",
            "/usr/lib/ssh/sftp-server",
            "/usr/libexec/sftp-server",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists());
        let what = match system {
            Some(p) => What::Program(p, vec![]),
            None => match crate::update::current_exe() {
                Ok(exe) => What::Program(exe, vec!["sftp-server".into()]),
                Err(_) => {
                    session.channel_failure(channel)?;
                    return Ok(());
                }
            },
        };
        self.start(channel, what, session)
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(fd) = self.ptys.lock().unwrap().get(&channel) {
            set_winsize(fd.as_raw_fd(), cols.clamp(1, 1000) as u16, rows.clamp(1, 1000) as u16);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Processes

pub(crate) fn set_winsize(fd: libc::c_int, cols: u16, rows: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
}

/// `meshvpn forward-tcp HOST PORT` as the account (its uid, gid and groups), pipes on both
/// ends: a port forward made by the account itself.
fn forward_command(acct: &Account, exe: &Path, host: &str, port: u16) -> tokio::process::Command {
    let mut c = tokio::process::Command::new(exe);
    c.args(["forward-tcp", "--", host, &port.to_string()])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let switch = unsafe { libc::geteuid() } == 0;
    let (uid, gid, groups) = (acct.uid, acct.gid, acct.groups.clone());
    unsafe {
        c.pre_exec(move || {
            if switch
                && (libc::setgroups(groups.len() as _, groups.as_ptr()) < 0
                    || libc::setgid(gid) < 0
                    || libc::setuid(uid) < 0)
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    c
}

/// Variables of the daemon's own environment that must not leak into sessions.
fn inherit(name: &str) -> bool {
    const DROP: &[&str] = &[
        "INVOCATION_ID",
        "JOURNAL_STREAM",
        "NOTIFY_SOCKET",
        "MAINPID",
        "MANAGERPID",
        "SYSTEMD_EXEC_PID",
        "RUST_LOG",
        "OLDPWD",
        "PWD",
        "MAIL",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "MESHVPN_DIR",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
    ];
    // Root's proxy settings (proxy.env is root's alone; they may hold a password).
    let from_proxy_file = crate::sys::FROM_PROXY_FILE.lock().unwrap().iter().any(|k| k == name);
    !DROP.contains(&name)
        && !from_proxy_file
        && !name.starts_with("SSH_")
        && !name.starts_with("SUDO_")
        && !name.starts_with("LISTEN_")
}

/// The command for a session: the user's shell (login shell, or `-c command`), with the
/// daemon's environment (in a container: the image's PATH, CUDA, conda...) and the user's
/// identity; it starts in a new session as the user.
fn command(
    acct: &Account,
    what: What,
    env: Vec<(String, String)>,
    conn_env: &str,
    term: Option<&str>,
    pty: bool,
) -> tokio::process::Command {
    let shell = match what {
        What::Shell => interactive_shell(&acct.shell),
        _ => acct.shell.clone(),
    };
    let mut cmd = match what {
        What::Shell => {
            let mut c = tokio::process::Command::new(&shell);
            let base = shell
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or("sh".into());
            c.arg0(format!("-{base}"));
            c
        }
        What::Exec(line) => {
            let mut c = tokio::process::Command::new(&acct.shell);
            c.arg("-c").arg(line);
            c
        }
        What::Program(p, args) => {
            let mut c = tokio::process::Command::new(p);
            c.args(args);
            c
        }
    };
    cmd.env_clear();
    for (k, v) in std::env::vars_os() {
        if k.to_str().is_some_and(inherit) {
            cmd.env(k, v);
        }
    }
    if std::env::var_os("PATH").is_none() {
        let path = if acct.uid == 0 {
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        } else {
            "/usr/local/bin:/usr/bin:/bin"
        };
        cmd.env("PATH", path);
    }
    cmd.env("HOME", &acct.home)
        .env("USER", &acct.name)
        .env("LOGNAME", &acct.name)
        .env("SHELL", &shell)
        .env("SSH_CONNECTION", conn_env);
    let mut parts = conn_env.split(' ');
    if let (Some(ip), Some(port), Some(_), Some(lport)) = (parts.next(), parts.next(), parts.next(), parts.next()) {
        cmd.env("SSH_CLIENT", format!("{ip} {port} {lport}"));
    }
    if let Some(t) = term {
        cmd.env("TERM", t);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let dir = if acct.home.is_dir() {
        acct.home.clone()
    } else {
        PathBuf::from("/")
    };
    cmd.current_dir(dir);
    let switch = unsafe { libc::geteuid() } == 0;
    let (uid, gid, groups) = (acct.uid, acct.gid, acct.groups.clone());
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if pty && libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if switch
                && (libc::setgroups(groups.len() as _, groups.as_ptr()) < 0
                    || libc::setgid(gid) < 0
                    || libc::setuid(uid) < 0)
            {
                return Err(std::io::Error::last_os_error());
            }
            libc::umask(0o022);
            Ok(())
        });
    }
    cmd.kill_on_drop(false);
    cmd
}

/// The shell for an interactive login: the account's, unless that is a bare `sh` (accounts
/// made with `useradd` in containers get dash: no history, no completion) and bash exists.
/// Commands keep the account's shell.
fn interactive_shell(account: &Path) -> PathBuf {
    let real = std::fs::canonicalize(account).unwrap_or_else(|_| account.to_path_buf());
    let bare = ["sh", "dash", "ash"]
        .iter()
        .any(|n| real.file_name().is_some_and(|f| f == *n));
    if bare
        && let Some(bash) = ["/bin/bash", "/usr/bin/bash"]
            .iter()
            .map(Path::new)
            .find(|p| p.is_file())
    {
        return bash.to_path_buf();
    }
    account.to_path_buf()
}

fn exit_code(status: std::process::ExitStatus) -> u32 {
    status
        .code()
        .map(|c| c as u32)
        .or_else(|| status.signal().map(|s| 128 + s as u32))
        .unwrap_or(255)
}

/// Without a terminal: stdin/stdout/stderr as pipes (commands, scp, sftp, `meshvpn exec`).
async fn run_pipes(
    channel: Channel<Msg>,
    acct: &Account,
    what: What,
    env: Vec<(String, String)>,
    conn_env: &str,
) -> Result<()> {
    use std::process::Stdio;
    let mut cmd = command(acct, what, env, conn_env, None, false);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let (mut rd, wr) = channel.split();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = wr
                .extended_data_bytes(1, format!("meshvpn: cannot start: {e}\r\n").into_bytes())
                .await;
            let _ = wr.exit_status(127).await;
            let _ = wr.eof().await;
            let _ = wr.close().await;
            return Ok(());
        }
    };
    drop(cmd);
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let input = tokio::spawn(async move {
        while let Some(msg) = rd.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    let Some(s) = stdin.as_mut() else { continue };
                    if s.write_all(&data).await.is_err() {
                        stdin = None;
                    }
                }
                ChannelMsg::Eof => stdin = None,
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    });
    let mut out_w = wr.make_writer();
    let mut err_w = wr.make_writer_ext(Some(1));
    let (_, _, status) = tokio::join!(
        async {
            let _ = tokio::io::copy(&mut stdout, &mut out_w).await;
            let _ = out_w.flush().await;
        },
        async {
            let _ = tokio::io::copy(&mut stderr, &mut err_w).await;
            let _ = err_w.flush().await;
        },
        child.wait()
    );
    input.abort();
    let code = status.map(exit_code).unwrap_or(255);
    let _ = wr.exit_status(code).await;
    let _ = wr.eof().await;
    let _ = wr.close().await;
    Ok(())
}

pub(crate) fn openpty(cols: u16, rows: u16) -> std::io::Result<(OwnedFd, OwnedFd)> {
    let (mut master, mut slave) = (0, 0);
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ws as *const _ as *mut _,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    unsafe {
        libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(slave, libc::F_SETFD, libc::FD_CLOEXEC);
        Ok((OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)))
    }
}

/// With a terminal: interactive shells and `ssh -t`.
#[allow(clippy::too_many_arguments)]
async fn run_pty(
    channel: Channel<Msg>,
    acct: &Account,
    what: What,
    env: Vec<(String, String)>,
    conn_env: &str,
    req: PtyReq,
    ptys: Arc<Mutex<HashMap<ChannelId, Arc<OwnedFd>>>>,
    id: ChannelId,
) -> Result<()> {
    use std::process::Stdio;
    let (master, slave) = openpty(req.cols, req.rows)?;
    let mut cmd = command(acct, what, env, conn_env, Some(&req.term), true);
    cmd.stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    let (mut rd, wr) = channel.split();
    let child = cmd.spawn();
    // The command holds copies of the terminal; the shell must be the only one left, or
    // reading the master never ends.
    drop(cmd);
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let _ = wr
                .data_bytes(format!("meshvpn: cannot start a shell: {e}\r\n").into_bytes())
                .await;
            let _ = wr.exit_status(127).await;
            let _ = wr.eof().await;
            let _ = wr.close().await;
            return Ok(());
        }
    };
    let pid = child.id().map(|p| p as i32);
    let master = Arc::new(master);
    ptys.lock().unwrap().insert(id, master.clone());
    let mut reader = tokio::fs::File::from_std(std::fs::File::from(master.try_clone()?));
    let mut writer = tokio::fs::File::from_std(std::fs::File::from(master.try_clone()?));
    let input = tokio::spawn(async move {
        while let Some(msg) = rd.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    if writer.write_all(&data).await.is_err() || writer.flush().await.is_err() {
                        break;
                    }
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        // The client went away: hang up like a closed terminal would.
        if let Some(pid) = pid {
            unsafe { libc::kill(-pid, libc::SIGHUP) };
        }
    });
    let mut out_w = wr.make_writer();
    let mut output = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut reader, &mut out_w).await;
        let _ = out_w.flush().await;
    });
    let status = child.wait().await;
    // Whatever the shell printed last; background jobs may keep the terminal open forever.
    if tokio::time::timeout(Duration::from_millis(500), &mut output)
        .await
        .is_err()
    {
        output.abort();
    }
    input.abort();
    ptys.lock().unwrap().remove(&id);
    let code = status.map(exit_code).unwrap_or(255);
    let _ = wr.exit_status(code).await;
    let _ = wr.eof().await;
    let _ = wr.close().await;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// `meshvpn sftp-server`: SFTP on stdin/stdout, started as the logged-in user.

pub fn sftp_server() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        let stdio = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        russh_sftp::server::run(
            stdio,
            Sftp {
                handles: HashMap::new(),
                next: 0,
                done: Some(done_tx),
            },
        )
        .await;
        let _ = done_rx.await;
    });
    Ok(())
}

enum Open {
    File(std::fs::File),
    Dir(Option<std::fs::ReadDir>),
}

struct Sftp {
    handles: HashMap<String, Open>,
    next: u64,
    /// Dropped with the handler when the stream ends.
    #[allow(dead_code)]
    done: Option<tokio::sync::oneshot::Sender<()>>,
}

use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version};

fn io_status(e: std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

fn apply_attrs(path: &Path, file: Option<&std::fs::File>, attrs: &FileAttributes) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(size) = attrs.size {
        match file {
            Some(f) => f.set_len(size)?,
            None => std::fs::OpenOptions::new().write(true).open(path)?.set_len(size)?,
        }
    }
    if let Some(mode) = attrs.permissions {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))?;
    }
    if let (Some(atime), Some(mtime)) = (attrs.atime, attrs.mtime) {
        let at = std::time::UNIX_EPOCH + Duration::from_secs(atime as u64);
        let mt = std::time::UNIX_EPOCH + Duration::from_secs(mtime as u64);
        let times = std::fs::FileTimes::new().set_accessed(at).set_modified(mt);
        match file {
            Some(f) => f.set_times(times)?,
            None => std::fs::File::options()
                .write(true)
                .open(path)
                .or_else(|_| std::fs::File::open(path))?
                .set_times(times)?,
        }
    }
    Ok(())
}

impl Sftp {
    fn add(&mut self, open: Open) -> String {
        self.next += 1;
        let h = self.next.to_string();
        self.handles.insert(h.clone(), open);
        h
    }
}

impl russh_sftp::server::Handler for Sftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _version: u32, _extensions: HashMap<String, String>) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut o = std::fs::OpenOptions::new();
        o.read(pflags.contains(OpenFlags::READ))
            .write(pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::APPEND))
            .append(pflags.contains(OpenFlags::APPEND))
            .truncate(pflags.contains(OpenFlags::TRUNCATE));
        if pflags.contains(OpenFlags::CREATE) {
            if pflags.contains(OpenFlags::EXCLUDE) {
                o.create_new(true);
            } else {
                o.create(true);
            }
            o.mode(attrs.permissions.map(|m| m & 0o7777).unwrap_or(0o644));
        }
        let f = o.open(&filename).map_err(io_status)?;
        Ok(Handle {
            id,
            handle: self.add(Open::File(f)),
        })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(ok(id))
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        use std::os::unix::fs::FileExt;
        let Some(Open::File(f)) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let mut buf = vec![0u8; len.min(256 * 1024) as usize];
        let n = f.read_at(&mut buf, offset).map_err(io_status)?;
        if n == 0 && len > 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        use std::os::unix::fs::FileExt;
        let Some(Open::File(f)) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        f.write_all_at(&data, offset).map_err(io_status)?;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let m = std::fs::symlink_metadata(&path).map_err(io_status)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let m = std::fs::metadata(&path).map_err(io_status)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let Some(Open::File(f)) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let m = f.metadata().map_err(io_status)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }

    async fn setstat(&mut self, id: u32, path: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        apply_attrs(Path::new(&path), None, &attrs).map_err(io_status)?;
        Ok(ok(id))
    }

    async fn fsetstat(&mut self, id: u32, handle: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        let Some(Open::File(f)) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        // Permissions and times by path are not available for a handle; set what the file allows.
        if let Some(size) = attrs.size {
            f.set_len(size).map_err(io_status)?;
        }
        if let Some(mode) = attrs.permissions {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))
                .map_err(io_status)?;
        }
        if let (Some(atime), Some(mtime)) = (attrs.atime, attrs.mtime) {
            let at = std::time::UNIX_EPOCH + Duration::from_secs(atime as u64);
            let mt = std::time::UNIX_EPOCH + Duration::from_secs(mtime as u64);
            f.set_times(std::fs::FileTimes::new().set_accessed(at).set_modified(mt))
                .map_err(io_status)?;
        }
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let rd = std::fs::read_dir(&path).map_err(io_status)?;
        Ok(Handle {
            id,
            handle: self.add(Open::Dir(Some(rd))),
        })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(Open::Dir(slot)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        let Some(rd) = slot.as_mut() else {
            return Err(StatusCode::Eof);
        };
        let mut files = vec![];
        for e in rd.by_ref().take(256).flatten() {
            let attrs = e
                .path()
                .symlink_metadata()
                .map(|m| FileAttributes::from(&m))
                .unwrap_or_default();
            files.push(File::new(e.file_name().to_string_lossy(), attrs));
        }
        if files.is_empty() {
            *slot = None;
            return Err(StatusCode::Eof);
        }
        Ok(Name { id, files })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        std::fs::remove_file(&filename).map_err(io_status)?;
        Ok(ok(id))
    }

    async fn mkdir(&mut self, id: u32, path: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(attrs.permissions.map(|m| m & 0o7777).unwrap_or(0o755))
            .create(&path)
            .map_err(io_status)?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        std::fs::remove_dir(&path).map_err(io_status)?;
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let p = if path.is_empty() { ".".to_string() } else { path };
        let abs = std::fs::canonicalize(&p)
            .or_else(|_| std::path::absolute(&p))
            .map_err(io_status)?;
        Ok(Name {
            id,
            files: vec![File::dummy(abs.to_string_lossy())],
        })
    }

    async fn rename(&mut self, id: u32, oldpath: String, newpath: String) -> Result<Status, Self::Error> {
        std::fs::rename(&oldpath, &newpath).map_err(io_status)?;
        Ok(ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let target = std::fs::read_link(&path).map_err(io_status)?;
        Ok(Name {
            id,
            files: vec![File::dummy(target.to_string_lossy())],
        })
    }

    async fn symlink(&mut self, id: u32, linkpath: String, targetpath: String) -> Result<Status, Self::Error> {
        // OpenSSH's sftp-server swaps the arguments compared to the draft; clients expect that.
        std::os::unix::fs::symlink(&linkpath, &targetpath).map_err(io_status)?;
        Ok(ok(id))
    }
}

#[cfg(test)]
mod authorized_keys_tests {
    use super::*;

    const A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    const B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";

    #[test]
    fn plain_lines_count_and_lines_with_options_do_not() {
        let a = PublicKey::from_openssh(A).unwrap();
        assert_eq!(
            authorized_keys_lookup(&format!("# me\n\n{B} b\n{A} a\n"), &a),
            Lookup::Listed
        );
        assert_eq!(authorized_keys_lookup(&format!("{B} b\n"), &a), Lookup::Absent);
        assert_eq!(authorized_keys_lookup("", &a), Lookup::Absent);
        assert_eq!(authorized_keys_lookup(&format!("# {A}\n"), &a), Lookup::Absent);
        for opts in [
            "command=\"/bin/backup\"",
            "restrict",
            "from=\"10.0.0.1\"",
            "cert-authority",
        ] {
            assert_eq!(
                authorized_keys_lookup(&format!("{opts} {A} a\n"), &a),
                Lookup::HasOptions,
                "{opts}"
            );
        }
        // Limited on one line, plain on another: the plain line is what sshd would use too.
        assert_eq!(
            authorized_keys_lookup(&format!("restrict {A}\n{A}\n"), &a),
            Lookup::Listed
        );
    }
}
