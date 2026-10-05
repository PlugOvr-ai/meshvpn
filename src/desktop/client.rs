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
        let script = "exec \"$(command -v meshvpn || echo \"$HOME/.local/bin/meshvpn\")\" desktop attach";
        self.remote.command(&self.node, script).into()
    }
}

pub fn run(target: Target, port: u16, open_browser: bool) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .context("listening on 127.0.0.1")?;
        let addr = listener.local_addr()?;
        let token = crate::keys::random32()[..12]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let url = format!("http://{addr}/#{token}");
        println!("Desktop of {}: {url}", target.label());
        if open_browser && !open_url(&url) {
            println!(
                "(open it in a browser on this machine; from elsewhere: ssh -L {}:127.0.0.1:{} ...)",
                addr.port(),
                addr.port()
            );
        }
        println!("Press Ctrl+C to stop.");
        let target = Arc::new(target);
        let token = Arc::new(token);
        loop {
            let (stream, _) = listener.accept().await?;
            let (target, token) = (target.clone(), token.clone());
            tokio::spawn(async move {
                if let Err(e) = handle(stream, &target, &token).await {
                    tracing::debug!("viewer connection: {e:#}");
                }
            });
        }
    })
}

fn open_url(url: &str) -> bool {
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

async fn handle(mut stream: TcpStream, target: &Target, token: &str) -> Result<()> {
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
    if !path.starts_with("/ws") {
        let body = PAGE.replace("__TITLE__", &target.label());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
             Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }
    // The page passes the token from the URL fragment; other sites can't know it.
    let ok_token = path
        .split_once("token=")
        .is_some_and(|(_, t)| t.split('&').next() == Some(token));
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
