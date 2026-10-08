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
    /// For sshd's AuthorizedKeysCommand (runs as nobody).
    AuthorizedKeys {
        user: String,
    },
    SshList,
    SshOverview,
    SshSetRules {
        rules: Vec<crate::config::SshAllow>,
        #[serde(default)]
        allow_all: Vec<String>,
    },
    SshAllow {
        who: String,
        users: Vec<String>,
    },
    SshDeny {
        who: String,
        users: Vec<String>,
    },
    AddPeer {
        addr: String,
    },
    Update {
        check_only: bool,
        force: bool,
    },
    Ban {
        who: String,
    },
    Rename {
        name: String,
    },
    /// `meshvpn ssh default-user`: None clears it.
    LoginUser {
        user: Option<String>,
    },
    AdminStatus,
    /// GPU reservations on this node (allowed for every local user: they are advisory).
    GpuReserve {
        count: Option<u32>,
        indices: Option<Vec<u32>>,
        ttl_ms: u64,
        holder: String,
    },
    GpuRelease {
        id: String,
    },
    GpuRenew {
        id: String,
        ttl_ms: u64,
    },
    AdminEnable,
    AdminChange {
        who: String,
        add: bool,
    },
    /// A signed invite ticket (managed networks; admins only).
    IssueTicket {
        uses: u32,
        valid_ms: u64,
    },
    Tags {
        add: Vec<String>,
        remove: Vec<String>,
    },
    Share {
        path: String,
        name: Option<String>,
    },
    Fetch {
        id: String,
        dest: String,
        /// Give the files to this user (the one behind sudo).
        owner: Option<u32>,
    },
    Unshare {
        id: String,
    },
    /// Ask these nodes (hex ids) to measure towards each other now.
    Measure {
        nodes: Vec<String>,
        bytes: u64,
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
    SshOverview(Box<crate::node::SshOverview>),
    Ok,
    Message { text: String },
    Error { message: String },
}

/// The config directory is root-only (it holds the keys), so the default instance puts its
/// socket in /run where everyone can ask for the status. Everything else needs root; that is
/// checked per request with the caller's credentials.
pub fn socket_path(dir: &Path) -> PathBuf {
    if dir == Path::new("/etc/meshvpn") {
        PathBuf::from("/run/meshvpn.sock")
    } else {
        let path = dir.join("meshvpn.sock");
        // Unix socket paths are limited to ~108 bytes; a deep directory gets one in /tmp.
        if path.as_os_str().len() < 100 {
            return path;
        }
        let abs = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
        let hash = blake3::hash(abs.as_os_str().as_encoded_bytes()).to_hex();
        std::env::temp_dir().join(format!("meshvpn-{}.sock", &hash[..16]))
    }
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
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).ok();
    let me = unsafe { libc::geteuid() };
    while let Ok((stream, _)) = listener.accept().await {
        let node = node.clone();
        let privileged = stream.peer_cred().is_ok_and(|c| c.uid() == 0 || c.uid() == me);
        tokio::spawn(async move {
            let (r, mut w) = stream.into_split();
            let mut line = String::new();
            if BufReader::new(r).read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<Request>(&line) {
                Ok(Request::Status) => Response::Status(Box::new(node.status())),
                Ok(Request::AuthorizedKeys { user }) => Response::Message {
                    text: node.authorized_keys(&user),
                },
                Ok(Request::SshList) => Response::Message { text: node.ssh_list() },
                Ok(Request::GpuReserve {
                    count,
                    indices,
                    ttl_ms,
                    holder,
                }) => lease_reply(node.gpu_reserve(count, indices, ttl_ms, holder)),
                Ok(Request::GpuRelease { id }) => lease_reply(node.gpu_release(&id)),
                Ok(Request::GpuRenew { id, ttl_ms }) => lease_reply(node.gpu_renew(&id, ttl_ms)),
                Ok(Request::AdminStatus) => Response::Message {
                    text: node.admin_status().to_string(),
                },
                Ok(Request::SshOverview) => Response::SshOverview(Box::new(node.ssh_overview())),
                // Allowed for everyone: it only measures (agents usually run unprivileged).
                Ok(Request::Measure { nodes, bytes }) => {
                    use rand::RngCore;
                    let req = crate::proto::MeasureReq {
                        nonce: rand::rngs::OsRng.next_u64(),
                        nodes: nodes
                            .iter()
                            .filter_map(|n| crate::keys::Key32::from_hex(n).ok())
                            .collect(),
                        bytes,
                    };
                    node.start_measure(req, None);
                    Response::Ok
                }
                Ok(_) if !privileged => Response::Error {
                    message: "permission denied - try again with sudo".into(),
                },
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
                Ok(Request::SshAllow { who, users }) => match node.ssh_allow(&who, users) {
                    Ok(text) => Response::Message { text },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Ok(Request::SshDeny { who, users }) => match node.ssh_deny(&who, users) {
                    Ok(text) => Response::Message { text },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Ok(Request::SshSetRules { rules, allow_all }) => match node.ssh_set_rules(rules, allow_all) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Ok(Request::Tags { add, remove }) => match node.set_tags(add, remove) {
                    Ok(tags) => Response::Message { text: tags.join(",") },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Ok(Request::Share { path, name }) => {
                    let n = node.clone();
                    let res =
                        tokio::task::spawn_blocking(move || crate::share::share(&n.shares, Path::new(&path), name))
                            .await
                            .map_err(anyhow::Error::from)
                            .and_then(|r| r);
                    match res {
                        Ok(s) => {
                            node.objects_changed();
                            Response::Message {
                                text: serde_json::json!({
                                    "id": s.id, "name": s.manifest.name, "size": s.manifest.total,
                                    "files": s.manifest.files.len(),
                                })
                                .to_string(),
                            }
                        }
                        Err(e) => Response::Error {
                            message: format!("{e:#}"),
                        },
                    }
                }
                Ok(Request::Fetch { id, dest, owner }) => {
                    let holders = node.holders(&id);
                    match crate::share::fetch(node.clone(), &id, Path::new(&dest), owner, holders).await {
                        Ok(r) => Response::Message {
                            text: serde_json::to_string(&r).unwrap(),
                        },
                        Err(e) => Response::Error {
                            message: format!("{e:#}"),
                        },
                    }
                }
                Ok(Request::Unshare { id }) => {
                    if node.shares.remove(&id) {
                        node.objects_changed();
                        Response::Ok
                    } else {
                        Response::Error {
                            message: format!("object {id} not found here"),
                        }
                    }
                }
                Ok(Request::AdminEnable) => match node.admin_enable() {
                    Ok(text) => Response::Message { text },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Ok(Request::AdminChange { who, add }) => match node.admin_change(&who, add) {
                    Ok(text) => Response::Message { text },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Ok(Request::IssueTicket { uses, valid_ms }) => match node.issue_ticket(uses, valid_ms) {
                    Ok((ticket, admins)) => Response::Message {
                        text: serde_json::json!({ "ticket": ticket, "admins": admins }).to_string(),
                    },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Ok(Request::LoginUser { user }) => match node.set_login_user(user) {
                    Ok(text) => Response::Message { text },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Ok(Request::Rename { name }) => match node.rename(&name) {
                    Ok(text) => Response::Message { text },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Ok(Request::Ban { who }) => match node.ban(&who) {
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

fn lease_reply(r: anyhow::Result<crate::proto::Lease>) -> Response {
    match r {
        Ok(l) => Response::Message {
            text: serde_json::to_string(&l).unwrap(),
        },
        Err(e) => Response::Error {
            message: format!("{e:#}"),
        },
    }
}

pub fn is_running(dir: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket_path(dir)).is_ok()
}

pub async fn request(dir: &Path, req: &Request) -> Result<Response> {
    let path = socket_path(dir);
    let stream = UnixStream::connect(&path).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            anyhow::anyhow!(
                "meshvpn is not running - start it with `{}` (or `{}`)",
                crate::config::hint("sudo meshvpn up"),
                crate::config::hint("sudo meshvpn install")
            )
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
