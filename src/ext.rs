//! Extensions: what a build of meshvpn with more features plugs in (`cli::main_with`).
//!
//! The open-source meshvpn knows nothing about any particular extension. It offers:
//! - signed documents that admins publish and every node stores and gossips (`Ctx::publish`),
//!   also nodes without the extension, so they work across a mixed network,
//! - messages from node to node (`Ctx::send`, `Extension::message`), relayed like data,
//! - decisions: extra SSH login rules and limits (`Extension::ssh_access`), and which incoming
//!   packets reach this node (`Extension::allow_inbound`),
//! - commands (`meshvpn <cmd> ...` that meshvpn doesn't know), control requests, status, and a
//!   tick every few seconds.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, OnceLock};

pub use crate::keys::NodeId;

/// A node as an extension sees it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub id: NodeId,
    pub name: String,
    pub tags: Vec<String>,
    pub ip: Ipv4Addr,
    pub online: bool,
    pub admin: bool,
    /// Users of the node that publish an SSH key.
    pub ssh_users: Vec<String>,
    /// meshvpn version the node runs.
    pub version: String,
    /// Hardware and load as the node publishes it (CPU, memory, disk, GPUs with utilization).
    pub inventory: serde_json::Value,
    /// Seconds since the node was last heard of (None: never, or this node).
    pub last_seen_secs: Option<u64>,
}

/// The network right now (a copy: extensions never hold meshvpn's locks).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct View {
    pub me: Peer,
    /// The network is managed (has admins); in an open network every node counts as admin.
    pub managed: bool,
    /// The network's id (the same on every node; e.g. to bind a license to the network).
    #[serde(default)]
    pub network: String,
    pub peers: Vec<Peer>,
    pub now_ms: u64,
}

impl View {
    pub fn peer(&self, id: &NodeId) -> Option<&Peer> {
        if self.me.id == *id {
            return Some(&self.me);
        }
        self.peers.iter().find(|p| p.id == *id)
    }

    /// All nodes, this one included.
    pub fn nodes(&self) -> impl Iterator<Item = &Peer> {
        std::iter::once(&self.me).chain(self.peers.iter())
    }
}

/// A document published by an admin, as every node has it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Doc {
    pub kind: String,
    pub version: u64,
    pub author: NodeId,
    pub at_ms: u64,
    pub data: String,
}

/// A key that may log in as local account `user`, from the mesh addresses `from` only (e.g. a
/// gateway the logins come through). `options` are sshd's authorized_keys options, such as
/// `restrict` or `permitopen="host:22"`; keys with options only work with sshd (the built-in
/// SSH server can't apply them and skips them).
#[derive(Clone, Debug)]
pub struct AuthorizedKey {
    pub user: String,
    /// "ssh-ed25519 AAAA..."
    pub key: String,
    pub from: Vec<Ipv4Addr>,
    pub options: Vec<String>,
    pub comment: String,
}

/// What an extension says about SSH logins into this machine.
#[derive(Clone, Debug, Default)]
pub struct SshAccess {
    /// Keys on top of this machine's own rules.
    pub keys: Vec<AuthorizedKey>,
    /// If set, this machine's own rules only apply to these nodes.
    pub only: Option<HashSet<NodeId>>,
}

/// An incoming IP packet from the mesh, to this node.
pub struct Inbound<'a> {
    pub from: &'a NodeId,
    /// 6 TCP, 17 UDP, 1 ICMP, ...
    pub protocol: u8,
    /// Destination port for TCP and UDP.
    pub port: Option<u16>,
}

/// Who sent a control request: root / the owner of a rootless install, and the local account
/// as the operating system tells it (not as the request claims).
#[derive(Clone, Debug)]
pub struct Caller {
    pub privileged: bool,
    pub user: Option<String>,
}

pub trait Extension: Send + Sync {
    /// "meshvpn enterprise 1.2.0" - shown in status.
    fn name(&self) -> String;

    /// `meshvpn <args...>` for a command meshvpn doesn't have. None: not ours either.
    fn command(&self, _dir: &Path, _json: bool, _args: &[String]) -> Option<Result<i32>> {
        None
    }

    /// The GitHub repository whose releases `meshvpn update` installs ("owner/name").
    fn release_repo(&self) -> Option<String> {
        None
    }

    /// Lines for `meshvpn --help`.
    fn help(&self) -> String {
        String::new()
    }

    /// The daemon started (or the documents changed): set up, recompute.
    fn start(&self, _ctx: &Ctx) {}
    fn docs_changed(&self, _ctx: &Ctx) {}
    /// Every few seconds.
    fn tick(&self, _ctx: &Ctx) {}

    /// A request from the command line (`ext::request`), from `caller`.
    fn control(&self, _ctx: &Ctx, _body: serde_json::Value, _caller: &Caller) -> Result<serde_json::Value> {
        anyhow::bail!("not supported")
    }

    /// A message from another node (`Ctx::send`); the sender is authenticated.
    fn message(&self, _ctx: &Ctx, _from: NodeId, _body: serde_json::Value) {}

    fn ssh_access(&self, _view: &View) -> SshAccess {
        SshAccess::default()
    }

    /// More `<name>.mesh` names for /etc/hosts and meshvpn's known_hosts, e.g. a name that
    /// follows a job to whichever node runs it. Names of nodes win over these; names must be
    /// lower case letters, digits and `-`. Asked when meshvpn writes those files (after every
    /// tick, among others): keep it fast.
    fn host_names(&self, _view: &View) -> Vec<(String, Ipv4Addr)> {
        vec![]
    }

    /// Called for every packet: keep it fast (decide from state prepared in tick/docs_changed).
    fn allow_inbound(&self, _packet: &Inbound) -> bool {
        true
    }

    /// For `meshvpn status --json` (and a line each in the text output).
    fn status(&self, _ctx: &Ctx) -> Option<serde_json::Value> {
        None
    }
    fn status_lines(&self, _status: &serde_json::Value) -> Vec<String> {
        vec![]
    }
}

static EXTENSION: OnceLock<Arc<dyn Extension>> = OnceLock::new();

/// Called once by `cli::main_with`.
pub(crate) fn install(ext: Arc<dyn Extension>) {
    let _ = EXTENSION.set(ext);
}

pub(crate) fn get() -> Option<&'static Arc<dyn Extension>> {
    EXTENSION.get()
}

/// The running node, for an extension.
pub struct Ctx {
    pub(crate) node: Arc<crate::node::Node>,
}

impl Ctx {
    pub fn view(&self) -> View {
        self.node.ext_view()
    }

    /// The newest document of `kind`.
    pub fn doc(&self, kind: &str) -> Option<Doc> {
        self.node.ext_doc(kind)
    }

    /// Publishes a new version of document `kind` (this node must be an admin).
    pub fn publish(&self, kind: &str, data: String) -> Result<Doc> {
        self.node.ext_publish(kind, data)
    }

    /// Sends `body` to node `to` (relayed if needed; dropped if it can't be reached).
    pub fn send(&self, to: &NodeId, body: &serde_json::Value) -> bool {
        self.node.ext_send(to, body)
    }

    /// The configuration directory (e.g. for a license file).
    pub fn dir(&self) -> &Path {
        self.node.ext_dir()
    }
}

/// From the command line: a request to the extension in the running daemon.
pub fn request(dir: &Path, body: serde_json::Value) -> Result<serde_json::Value> {
    let resp = tokio::runtime::Runtime::new()?
        .block_on(crate::control::request(dir, &crate::control::Request::Ext { body }))?;
    match resp {
        crate::control::Response::Message { text } => Ok(serde_json::from_str(&text)?),
        _ => anyhow::bail!("unexpected answer from meshvpn"),
    }
}

/// Root or the owner of a rootless install, for commands that change things.
pub fn require_owner() -> Result<()> {
    crate::cli::require_owner()
}

/// The configuration directory the command line uses (`--dir`, or the default).
pub fn default_dir() -> std::path::PathBuf {
    crate::config::default_dir()
}

/// "2h", "30m", "1d" in milliseconds.
pub fn parse_duration_ms(s: &str) -> Result<u64> {
    crate::cli::parse_duration_ms(s)
}

/// Ed25519 signature check, for extensions' own signed data (e.g. licenses).
pub fn verify_ed25519(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let (Ok(key), Ok(sig)) = (VerifyingKey::from_bytes(public_key), Signature::from_slice(signature)) else {
        return false;
    };
    key.verify(message, &sig).is_ok()
}

pub fn now_ms() -> u64 {
    crate::node::now_ms()
}

/// torchrun's rendezvous arguments (`--nnodes`, `--node_rank`, `--master_addr`,
/// `--master_port`, `--nproc_per_node` from MESHVPN_GPUS) added to `cmd` from `env`, unless
/// given already - as `meshvpn launch` does.
pub fn add_torchrun_args(cmd: &[String], env: &std::collections::HashMap<String, String>) -> Vec<String> {
    crate::launch::add_torchrun_args(cmd, env)
}

/// The configured name of the mesh network interface (`mesh0` by default, on Linux).
pub fn interface_name(dir: &Path) -> Option<String> {
    crate::config::Config::load(dir).ok().map(|c| c.interface)
}
