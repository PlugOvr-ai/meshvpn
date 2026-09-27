//! Local control socket used by `meshvpn status` / `meshvpn add-peer`.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::warn;

use crate::node::{Node, Status};

#[derive(Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    AddPeer {
        addr: String,
    },
    Update {
        check_only: bool,
        force: bool,
    },
    /// Forget an offline node by name or id; `None` = all offline nodes.
    Forget {
        who: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Status(Box<Status>),
    Ok,
    Message { text: String },
    Error { message: String },
}

pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join("meshvpn.sock")
}

pub async fn serve(node: Arc<Node>, path: PathBuf) {
    std::fs::remove_file(&path).ok();
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            warn!("control socket {}: {e}", path.display());
            return;
        }
    };
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
    while let Ok((stream, _)) = listener.accept().await {
        let node = node.clone();
        tokio::spawn(async move {
            let (r, mut w) = stream.into_split();
            let mut line = String::new();
            if BufReader::new(r).read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<Request>(&line) {
                Ok(Request::Status) => Response::Status(Box::new(node.status())),
                Ok(Request::AddPeer { addr }) => match node.add_peer(addr) {
                    Ok(()) => {
                        node.dial_now();
                        Response::Ok
                    }
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Ok(Request::Forget { who }) => match node.forget(who.as_deref()) {
                    Ok(text) => Response::Message { text },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Ok(Request::Update { check_only, force }) => match node.update_now(check_only, force).await {
                    Ok(text) => Response::Message { text },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Err(e) => Response::Error { message: e.to_string() },
            };
            let mut out = serde_json::to_vec(&resp).unwrap();
            out.push(b'\n');
            let _ = w.write_all(&out).await;
        });
    }
}

pub fn is_running(dir: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket_path(dir)).is_ok()
}

pub async fn request(dir: &Path, req: &Request) -> Result<Response> {
    let path = socket_path(dir);
    let stream = UnixStream::connect(&path).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            anyhow::anyhow!("meshvpn is not running - start it with `sudo meshvpn up` (or `sudo meshvpn install`)")
        }
        std::io::ErrorKind::PermissionDenied => anyhow::anyhow!("permission denied - try again with sudo"),
        _ => anyhow::Error::from(e),
    })?;
    let (r, mut w) = stream.into_split();
    let mut msg = serde_json::to_vec(req)?;
    msg.push(b'\n');
    w.write_all(&msg).await?;
    let mut line = String::new();
    BufReader::new(r).read_line(&mut line).await?;
    let resp: Response = serde_json::from_str(&line).context("bad response from daemon")?;
    if let Response::Error { message } = &resp {
        bail!("{message}");
    }
    Ok(resp)
}
