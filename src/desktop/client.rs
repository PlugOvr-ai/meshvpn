//! `meshvpn desktop <node>`: serves the viewer on 127.0.0.1 and connects each browser tab to
//! the node's desktop session through SSH (`meshvpn desktop attach` there), so the logins,
//! rules and keys of `meshvpn ssh` apply unchanged.

use anyhow::{Context, Result, bail};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::proto;
use crate::agent::{NodeView, Remote};

const PAGE: &str = include_str!("viewer.html");

pub struct Target {
    pub node: NodeView,
    pub remote: Remote,
    /// "auto" (the node's choice), "xfce", "mate", "cinnamon", "plain" or "screen".
    pub session: &'static str,
    /// A shared SSH connection (a login with a password: `Remote::login`).
    pub control: Option<std::path::PathBuf>,
}

impl Target {
    /// For MESHVPN_DESKTOP_BRIDGE: no mesh lookup.
    pub fn test(name: &str, user: Option<&str>) -> Self {
        Target {
            node: NodeView::named(name),
            remote: Remote {
                user: user.map(String::from).unwrap_or_else(Remote::default_user),
                socks: false,
                timeout: std::time::Duration::from_secs(30),
            },
            session: "auto",
            control: None,
        }
    }

    fn label(&self) -> String {
        format!("{}@{}", self.remote.user, self.node.name)
    }

    /// `meshvpn desktop attach` on the node. Tests can swap in another command with
    /// MESHVPN_DESKTOP_BRIDGE (e.g. `docker exec -i box meshvpn desktop attach`).
    fn command(&self) -> tokio::process::Command {
        if let Ok(cmd) = std::env::var("MESHVPN_DESKTOP_BRIDGE") {
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(cmd);
            return c;
        }
        let mut script =
            "exec \"$(command -v meshvpn || echo \"$HOME/.local/bin/meshvpn\")\" desktop attach".to_string();
        // Only when asked: nodes before 0.13 don't know the option.
        if self.session != "auto" {
            script.push_str(&format!(" --session {}", self.session));
        }
        self.remote
            .command_via(&self.node, &script, self.control.as_deref())
            .into()
    }
}

/// A running viewer: its link (with the access token) and port.
pub struct Viewer {
    pub url: String,
    pub port: u16,
}

/// Serves the viewer for `target` in the background and returns its link. In an SSH session
/// (port 0) a fixed port from 7880 on, so the forwarding command stays the same.
pub fn start(target: Target, port: u16) -> Result<Viewer> {
    let listener = if port == 0 && ssh_session().is_some() {
        (7880..7900)
            .find_map(|p| std::net::TcpListener::bind(("127.0.0.1", p)).ok())
            .map(Ok)
            .unwrap_or_else(|| std::net::TcpListener::bind(("127.0.0.1", 0)))
    } else {
        std::net::TcpListener::bind(("127.0.0.1", port))
    }
    .context("listening on 127.0.0.1")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let token: String = crate::keys::random32()[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let url = format!("http://127.0.0.1:{port}/#{token}");
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Runtime::new() else { return };
        rt.block_on(async move {
            let Ok(listener) = TcpListener::from_std(listener) else {
                return;
            };
            let target = Arc::new(target);
            let tokens = Arc::new(std::sync::Mutex::new(Tokens {
                link: Some(token),
                sessions: std::collections::HashSet::new(),
            }));
            while let Ok((stream, _)) = listener.accept().await {
                let (target, tokens) = (target.clone(), tokens.clone());
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, &target, &tokens).await {
                        tracing::debug!("viewer connection: {e:#}");
                    }
                });
            }
        });
    });
    Ok(Viewer { url, port })
}

/// `meshvpn desktop <node>`: print the link (clickable in the terminal), open a browser only
/// with `--open`, serve until Ctrl+C. Opening by default started an X browser under WSL.
pub fn run(mut target: Target, port: u16, open_browser: bool) -> Result<()> {
    let label = target.label();
    // No key for the node: log in once now (password), every tab uses that connection.
    if std::env::var_os("MESHVPN_DESKTOP_BRIDGE").is_none() && target.control.is_none() {
        target.control = target.remote.login(&target.node)?;
    }
    let v = start(target, port)?;
    println!("Desktop of {label}: {}", terminal_link(&v.url));
    match ssh_hint(v.port) {
        Some(lines) => {
            for l in lines {
                println!("{l}");
            }
        }
        None => {
            if !open_browser {
                println!("Ctrl+click the link (or copy it into a browser on this machine).");
            } else if !open_url(&v.url) {
                println!("(open it in a browser on this machine)");
            }
        }
    }
    println!("Press Ctrl+C to stop.");
    loop {
        std::thread::park();
    }
}

/// (server address, server port, user) when running inside an SSH login.
pub fn ssh_session() -> Option<(String, u16, String)> {
    let c = std::env::var("SSH_CONNECTION").ok()?;
    let f: Vec<&str> = c.split_whitespace().collect();
    let (ip, port) = (f.get(2)?.to_string(), f.get(3)?.parse().ok()?);
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| Remote::default_user());
    Some((ip, port, user))
}

/// How to reach a viewer on this machine from the computer the SSH login came from.
pub fn ssh_hint(port: u16) -> Option<Vec<String>> {
    let (ip, sport, user) = ssh_session()?;
    let host = if ip.contains(':') { format!("[{ip}]") } else { ip };
    let p = if sport == 22 {
        String::new()
    } else {
        format!(" -p {sport}")
    };
    Some(vec![
        "You are logged in over SSH, so open it on the computer you came from:".into(),
        format!("  ssh -L {port}:127.0.0.1:{port}{p} {user}@{host}"),
        "  (or in this SSH session: press Enter, type ~C, then".into(),
        format!("   -L {port}:127.0.0.1:{port} and Enter) - then open the link there."),
    ])
}

/// The URL as a terminal hyperlink (OSC 8) when stdout is a terminal; terminals without
/// hyperlinks ignore the escape and show the plain URL, which most of them link by themselves.
pub fn terminal_link(url: &str) -> String {
    use std::io::IsTerminal;
    // Windows: only Windows Terminal; the old console window would print the escape as text.
    let capable = if cfg!(windows) {
        std::env::var_os("WT_SESSION").is_some()
    } else {
        std::env::var("TERM").map_or(true, |t| t != "dumb")
    };
    if std::io::stdout().is_terminal() && capable {
        format!("\x1b]8;;{url}\x1b\\{url}\x1b]8;;\x1b\\")
    } else {
        url.to_string()
    }
}

pub fn open_url(url: &str) -> bool {
    for cmd in ["xdg-open", "open", "wslview"] {
        let ok = std::process::Command::new(cmd)
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .is_ok();
        if ok {
            return true;
        }
    }
    false
}

async fn read_head(stream: &mut TcpStream) -> Result<String> {
    let mut head = vec![];
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut b).await? == 0 || head.len() > 16384 {
            bail!("bad request");
        }
        head.push(b[0]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// Who may use the viewer: the link's token, once (it may show in the list of processes, as an
/// argument of the browser), swapped for a session token the page keeps.
struct Tokens {
    link: Option<String>,
    sessions: std::collections::HashSet<String>,
}

async fn handle(mut stream: TcpStream, target: &Target, tokens: &std::sync::Mutex<Tokens>) -> Result<()> {
    let head = read_head(&mut stream).await?;
    let mut lines = head.lines();
    let path = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let header = |name: &str| {
        head.lines()
            .skip(1)
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)))
            .map(|(_, v)| v.trim().to_string())
    };
    let given = path
        .split_once("token=")
        .map(|(_, t)| t.split('&').next().unwrap_or_default().to_string());
    // Only this page itself (same address and port; a POST from it), never another site.
    let own = format!(
        "http://127.0.0.1:{}",
        stream.local_addr().map(|a| a.port()).unwrap_or(0)
    );
    let same_origin =
        header("Origin").is_none_or(|o| o == own) && header("Host").is_some_and(|h| own.ends_with(&format!("//{h}")));
    let method = head.split_whitespace().next().unwrap_or_default().to_string();
    if path.starts_with("/session") {
        let session = (method == "POST" && same_origin)
            .then(|| {
                let mut t = tokens.lock().unwrap();
                match (&t.link, &given) {
                    (Some(l), Some(g)) if l == g => {
                        t.link = None;
                        let s: String = crate::keys::random32().iter().map(|b| format!("{b:02x}")).collect();
                        t.sessions.insert(s.clone());
                        Some(s)
                    }
                    _ => None,
                }
            })
            .flatten();
        let resp = match session {
            Some(s) => {
                let body = format!("{{\"session\":\"{s}\"}}");
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }
            None => "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        };
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }
    if !path.starts_with("/ws") {
        let body = PAGE.replace("__TITLE__", &html_escape(&target.label()));
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
             Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }
    // The page passes its session token; other sites can't know it.
    let ok_token = same_origin && given.is_some_and(|g| tokens.lock().unwrap().sessions.contains(&g));
    let (Some(key), true) = (header("Sec-WebSocket-Key"), ok_token) else {
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    };
    let accept = {
        use base64::Engine;
        use sha1::Digest;
        let mut h = sha1::Sha1::new();
        h.update(key.as_bytes());
        h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(h.finalize())
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    stream.set_nodelay(true).ok();
    bridge(stream, target).await
}

/// One browser tab <-> `meshvpn desktop attach` on the node.
async fn bridge(stream: TcpStream, target: &Target) -> Result<()> {
    let mut cmd = target.command();
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let (mut ws_r, ws_w) = stream.into_split();
    let ws_w = Arc::new(tokio::sync::Mutex::new(ws_w));
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = proto::frame(proto::S_NOTICE, format!("cannot run ssh: {e}").as_bytes());
            ws_send(&ws_w, &msg).await?;
            return Ok(());
        }
    };
    let mut to_remote = child.stdin.take().unwrap();
    let mut from_remote = child.stdout.take().unwrap();
    let mut errors = child.stderr.take().unwrap();

    // node -> browser: one WebSocket message per protocol message
    let w = ws_w.clone();
    let down = tokio::spawn(async move {
        let mut buf = vec![];
        let mut chunk = vec![0u8; 256 * 1024];
        loop {
            match from_remote.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    let Ok(msgs) = proto::split(&mut buf) else { break };
                    for m in msgs {
                        if ws_send(&w, &m).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    });
    // browser -> node
    let up = async {
        while let Ok(Some(m)) = ws_read(&mut ws_r, &ws_w).await {
            if to_remote.write_all(&m).await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    let _ = child.start_kill();
    // If ssh failed, tell the browser why.
    let mut err = String::new();
    let _ = tokio::time::timeout(std::time::Duration::from_millis(500), errors.read_to_string(&mut err)).await;
    if !err.trim().is_empty() {
        let msg = proto::frame(proto::S_NOTICE, format!("connection ended: {}", err.trim()).as_bytes());
        let _ = ws_send(&ws_w, &msg).await;
    }
    Ok(())
}

async fn ws_send(w: &tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>, data: &[u8]) -> Result<()> {
    let mut f = Vec::with_capacity(data.len() + 10);
    f.push(0x82); // FIN + binary
    match data.len() {
        n if n < 126 => f.push(n as u8),
        n if n < 65536 => {
            f.push(126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(data);
    w.lock().await.write_all(&f).await?;
    Ok(())
}

/// The next data message (continuations joined, pings answered); None when closed.
async fn ws_read(
    r: &mut tokio::net::tcp::OwnedReadHalf,
    w: &tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>,
) -> Result<Option<Vec<u8>>> {
    let mut msg = vec![];
    loop {
        let mut h = [0u8; 2];
        if r.read_exact(&mut h).await.is_err() {
            return Ok(None);
        }
        let (fin, op) = (h[0] & 0x80 != 0, h[0] & 0x0f);
        let masked = h[1] & 0x80 != 0;
        let mut len = (h[1] & 0x7f) as u64;
        if len == 126 {
            let mut b = [0u8; 2];
            r.read_exact(&mut b).await?;
            len = u16::from_be_bytes(b) as u64;
        } else if len == 127 {
            let mut b = [0u8; 8];
            r.read_exact(&mut b).await?;
            len = u64::from_be_bytes(b);
        }
        if len > proto::MAX_MESSAGE as u64 {
            bail!("message too large");
        }
        let mut mask = [0u8; 4];
        if masked {
            r.read_exact(&mut mask).await?;
        }
        let mut payload = vec![0u8; len as usize];
        r.read_exact(&mut payload).await?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        match op {
            0x8 => return Ok(None),
            0x9 => {
                let mut f = vec![0x8a, payload.len().min(125) as u8];
                f.extend_from_slice(&payload[..payload.len().min(125)]);
                w.lock().await.write_all(&f).await?;
            }
            0xa => {}
            _ => {
                msg.extend_from_slice(&payload);
                if fin {
                    return Ok(Some(msg));
                }
            }
        }
    }
}

/// Text for an HTML page.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    #[test]
    fn titles_are_escaped() {
        assert_eq!(super::html_escape("a<script>&\"'"), "a&lt;script&gt;&amp;&quot;&#39;");
    }
}
