//! On-disk configuration, persisted peer state and invite codes.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::keys::{b64, random32, unb64};
use crate::proto::{Forget, SignedInfo};

pub const DEFAULT_PORT: u16 = 7870;
pub const DEFAULT_SOCKS_PORT: u16 = 1081;
const INVITE_PREFIX: &str = "mesh1-";

/// Where a root install keeps its config (and finds its socket in /run).
#[cfg(unix)]
pub const SYSTEM_DIR: &str = "/etc/meshvpn";
#[cfg(windows)]
pub const SYSTEM_DIR: &str = r"C:\ProgramData\meshvpn";

/// The config directory of a rootless install: `$XDG_CONFIG_HOME/meshvpn` or `~/.config/meshvpn`.
pub fn user_dir() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(x) => PathBuf::from(x),
        None => PathBuf::from(std::env::var_os("HOME").filter(|v| !v.is_empty())?).join(".config"),
    };
    Some(base.join("meshvpn"))
}

/// The directory to use when none is given. Root always uses the system install. Other users
/// use their own rootless install if they have one, else the machine's system install (so
/// `meshvpn status` works without sudo), and set up a new rootless install if neither exists.
pub fn default_dir() -> PathBuf {
    if crate::sys::is_root() {
        return PathBuf::from(SYSTEM_DIR);
    }
    match user_dir() {
        Some(u) if u.join("config.toml").exists() || !Path::new(SYSTEM_DIR).exists() => u,
        _ => PathBuf::from(SYSTEM_DIR),
    }
}

static ROOTLESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Decided once at startup: a non-root user working with a directory other than the system one.
pub fn set_rootless(dir: &Path) {
    let rootless = !crate::sys::is_root() && !dir.starts_with(SYSTEM_DIR);
    ROOTLESS.store(rootless, std::sync::atomic::Ordering::Relaxed);
}

/// Runs without root: userspace networking, no /etc/hosts, a systemd user service.
pub fn rootless() -> bool {
    ROOTLESS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Adapts a command suggestion to the install: no sudo and user services when rootless.
pub fn hint(text: &str) -> String {
    // Windows: an administrator terminal instead of sudo.
    if cfg!(windows) {
        return text
            .replace("try again with sudo", "run it in an administrator terminal")
            .replace("with sudo", "in an administrator terminal")
            .replace("sudo meshvpn", "meshvpn");
    }
    if !rootless() {
        return text.to_string();
    }
    text.replace("sudo systemctl ", "systemctl --user ")
        .replace("journalctl -u", "journalctl --user -u")
        .replace("sudo meshvpn", "meshvpn")
        .replace("sudo pkill", "pkill")
}

fn default_iface() -> String {
    "mesh0".into()
}
fn default_stun() -> Vec<String> {
    vec!["stun.l.google.com:19302".into(), "stun.cloudflare.com:3478".into()]
}

fn default_true() -> bool {
    true
}
fn default_ssh_port() -> u16 {
    22
}
fn default_socks_port() -> u16 {
    DEFAULT_SOCKS_PORT
}
fn default_mtu() -> u16 {
    1400
}

/// Reverse SSH tunnel for nodes that cannot accept (or even make) direct connections.
///
/// The daemon runs `ssh -N -R <remote_port>:127.0.0.1:<listen> -D <socks_port> server`
/// and keeps it alive. Other nodes reach us through `public_host:remote_port`, and we
/// reach them through the SOCKS proxy that ssh provides over the same connection.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SshTunnel {
    /// `user@host` of the SSH server that has internet access.
    pub server: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// Port opened on the SSH server that forwards to this node (0 = none: this node only
    /// connects out through the SOCKS proxy, and is reached through other nodes).
    pub remote_port: u16,
    /// Hostname other nodes use to reach `remote_port` (defaults to the host of `server`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    /// Local SOCKS port for outgoing connections through the tunnel (0 = disabled).
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,
}

impl SshTunnel {
    pub fn host(&self) -> &str {
        self.server.rsplit('@').next().unwrap_or(&self.server)
    }
    pub fn public_endpoint(&self) -> String {
        format!(
            "{}:{}",
            self.public_host.as_deref().unwrap_or(self.host()),
            self.remote_port
        )
    }
}

/// Password-less SSH login rule: `node` (optionally only its user `from_user`) may log in
/// here as any of `users`. Bound to the node's id, so a name can't be hijacked.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SshAllow {
    pub node: crate::keys::NodeId,
    /// Node name when the rule was made (for display).
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_user: Option<String>,
    pub users: Vec<String>,
}

/// `meshvpn ssh allow "ssh-ed25519 AAAA..."`: whoever holds this key may log in, from any node of
/// the network. Names can be taken by another device; a key can't.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SshAllowKey {
    /// `type base64`, checked: nothing else ever reaches an authorized_keys line from here.
    pub key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
    pub users: Vec<String>,
}

impl SshAllowKey {
    /// A line of a `.pub` file. Refuses authorized_keys options and more than one key.
    pub fn parse(line: &str) -> Result<(String, String)> {
        let line = line.trim();
        let mut parts = line.split_whitespace();
        let key = format!("{} {}", parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        if line.contains(['\n', '\r'])
            || !crate::proto::valid_ssh_key(&key)
            || russh::keys::PublicKey::from_openssh(&key).is_err()
        {
            bail!("that is not one SSH public key (expected a line of a .pub file: ssh-ed25519 AAAA... comment)");
        }
        let comment: String = parts
            .collect::<Vec<_>>()
            .join("_")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "@._-".contains(*c))
            .take(64)
            .collect();
        Ok((key, comment))
    }

    pub fn allow(rules: &mut Vec<SshAllowKey>, line: &str, users: &[String]) -> Result<String> {
        let (key, comment) = Self::parse(line)?;
        match rules.iter_mut().find(|r| r.key == key) {
            Some(r) => {
                for u in users {
                    if !r.users.contains(u) {
                        r.users.push(u.clone());
                    }
                }
                if !comment.is_empty() {
                    r.comment = comment;
                }
            }
            None => rules.push(SshAllowKey {
                key,
                comment,
                users: users.to_vec(),
            }),
        }
        Ok(format!(
            "this key may log in here as {} from any node of the network, without a password",
            users.join(", ")
        ))
    }

    /// Takes accounts away from a key (none named: all of them).
    pub fn deny(rules: &mut Vec<SshAllowKey>, line: &str, users: &[String]) -> Result<String> {
        let (key, _) = Self::parse(line)?;
        let Some(rule) = rules.iter_mut().find(|r| r.key == key) else {
            bail!("no rule for this key (see meshvpn ssh list)");
        };
        if users.is_empty() {
            rule.users.clear();
        } else {
            rule.users.retain(|u| !users.contains(u));
        }
        rules.retain(|r| !r.users.is_empty());
        Ok("updated password-less logins with this key".into())
    }
}

/// A network key used before the current one (see `meshvpn ban`).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OldKey {
    pub version: u32,
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BannedNode {
    pub id: crate::keys::NodeId,
    pub name: String,
}

/// Whether to run without a TUN device (TCP/IP stack in meshvpn itself).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Userspace {
    /// Kernel TUN device if available, userspace otherwise (e.g. containers without NET_ADMIN).
    #[default]
    Auto,
    Always,
    Never,
}

/// The built-in SSH server (`ssh user@node.mesh` without an sshd on this machine).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SshServer {
    /// When no sshd serves port 22 here: in userspace mode if nothing listens on port 22,
    /// in kernel mode if no sshd is installed.
    #[default]
    Auto,
    Always,
    Never,
}

fn default_socks_listen() -> String {
    "127.0.0.1:1055".into()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    /// Human readable node name (becomes `<name>.mesh` in /etc/hosts).
    pub name: String,
    /// Label of the network, purely informational.
    pub network: String,
    /// Shared secret of the network. Everybody holding it is a member.
    pub network_key: String,
    /// Stable id of the network; stays the same when the key is rotated. Empty = derived
    /// from `network_key` (networks created before key rotation existed).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network_id: String,
    /// Incremented each time the network key is rotated (on a ban).
    #[serde(default)]
    pub key_version: u32,
    pub signing_key: String,
    pub noise_key: String,
    /// TCP address to accept peer connections on. None = never accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Addresses (`host:port`) other nodes can use to reach us.
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// Also advertise automatically detected addresses (LAN IP, public IP as seen by peers).
    #[serde(default = "default_true")]
    pub auto_endpoints: bool,
    /// Addresses of nodes to connect to at startup.
    #[serde(default)]
    pub bootstrap: Vec<String>,
    #[serde(default = "default_iface")]
    pub interface: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Maintain `<name>.mesh` entries in /etc/hosts.
    #[serde(default = "default_true")]
    pub manage_hosts: bool,
    /// An IPv6 address in the mesh besides the IPv4 one (kernel mode on Linux). Off: IPv4 only,
    /// e.g. where firewall rules for the mesh interface exist only for IPv4.
    #[serde(default = "default_true")]
    pub ipv6: bool,
    /// Publish the SSH public keys of this machine's users, so other nodes can allow them to
    /// log in without a password.
    #[serde(default = "default_true")]
    pub publish_ssh_keys: bool,
    #[serde(default)]
    pub userspace: Userspace,
    /// Built-in SSH server: also accept the keys in the account's own ~/.ssh/authorized_keys, as
    /// sshd does (from mesh nodes only; never with an extension, whose rules decide who logs in).
    #[serde(default = "default_true")]
    pub ssh_authorized_keys: bool,
    /// Built-in SSH server: "auto" (where there is no sshd), "always" or "never".
    #[serde(default)]
    pub ssh_server: SshServer,
    /// Direct UDP paths between nodes, also through NATs (falls back to TCP/relays).
    #[serde(default = "default_true")]
    pub udp: bool,
    /// Behind a home router: open the listen port on it (UPnP IGD, PCP, NAT-PMP), so other
    /// nodes can connect to this one from the internet.
    #[serde(default = "default_true")]
    pub port_mapping: bool,
    /// STUN servers that tell this node its public UDP address (also while no other node is
    /// connected). Empty: none.
    #[serde(default = "default_stun")]
    pub stun: Vec<String>,
    /// Find nodes again whose address changed through BitTorrent's Mainline DHT (encrypted
    /// entries only members can read): no server or DynDNS needed. Off by default: firewalls
    /// in company networks may take the traffic for BitTorrent.
    #[serde(default)]
    pub dht: bool,
    /// Hole punching over IPv6 towards nodes we have no link to (both sides behind firewalls,
    /// no port forward): connection attempts to their IPv6 addresses, for up to a day.
    #[serde(default = "default_true")]
    pub punch: bool,
    /// From the invite: where to meet the inviting node (until the first link).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join: Option<JoinHint>,
    /// Labels other nodes and agents can select this node by (`tag:gpu`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// In userspace mode: SOCKS5 proxy through which programs here reach the mesh.
    #[serde(default = "default_socks_listen")]
    pub socks_listen: String,
    /// Make all outgoing connections through this SOCKS5 proxy (`host:port`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_proxy: Option<String>,
    /// Never open outgoing connections; wait for others to connect to us.
    #[serde(default)]
    pub no_outbound: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_tunnel: Option<SshTunnel>,
    /// Earlier network keys, so members that were offline during a ban can still connect
    /// once and receive the new key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub old_keys: Vec<OldKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub banned: Vec<BannedNode>,
    /// Managed networks: admins to trust (from the invite), the invite's ticket, and this
    /// node's admission made from it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_admins: Vec<crate::keys::NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<crate::proto::SignedDoc>,
    /// The invite's one-time key for the ticket (see `Ticket::key`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<crate::proto::ClaimMsg>,
    /// Who may log in here over SSH without a password (see `meshvpn ssh`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_allow: Vec<SshAllow>,
    /// The account others log in as by default (console, desktop), announced to the network.
    /// Unset: the --ssh-allow-all account if there is exactly one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_default_user: Option<String>,
    /// Offer this node's internet connection to the mesh (`meshvpn exit offer`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exit_offer: bool,
    /// Send internet traffic through this node (hex id; `meshvpn exit use`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<String>,
    /// Local accounts that every node of the network (any of its users) may log in as
    /// without a password - e.g. for cluster machines everybody works on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_allow_all: Vec<String>,
    /// SSH keys that may log in, whichever node they come from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_allow_keys: Vec<SshAllowKey>,
}

impl Config {
    pub fn new(name: String, network: String, network_key: [u8; 32]) -> Self {
        Config {
            name,
            network,
            network_key: b64(&network_key),
            signing_key: b64(&random32()),
            noise_key: b64(&random32()),
            listen: Some(format!("0.0.0.0:{DEFAULT_PORT}")),
            endpoints: vec![],
            auto_endpoints: true,
            bootstrap: vec![],
            interface: default_iface(),
            mtu: default_mtu(),
            manage_hosts: !rootless(),
            ipv6: true,
            publish_ssh_keys: true,
            ssh_authorized_keys: true,
            userspace: if rootless() { Userspace::Always } else { Userspace::Auto },
            ssh_server: SshServer::Auto,
            udp: true,
            port_mapping: true,
            stun: default_stun(),
            dht: false,
            punch: true,
            join: None,
            tags: vec![],
            socks_listen: default_socks_listen(),
            ssh_allow: vec![],
            trusted_admins: vec![],
            ticket: None,
            ticket_key: None,
            claim: None,
            ssh_allow_all: vec![],
            ssh_allow_keys: vec![],
            ssh_default_user: None,
            exit_offer: false,
            exit_node: None,
            socks_proxy: None,
            no_outbound: false,
            ssh_tunnel: None,
            network_id: String::new(),
            key_version: 0,
            old_keys: vec![],
            banned: vec![],
        }
    }

    pub fn path(dir: &Path) -> PathBuf {
        dir.join("config.toml")
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let path = Self::path(dir);
        let text = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "no configuration at {} - create a network with `meshvpn init` or join one with `meshvpn join <invite>`",
                path.display()
            ),
            std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
                "permission denied reading {} - try again with sudo",
                path.display()
            ),
            _ => anyhow::Error::from(e),
        })?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let text = format!(
            "# meshvpn configuration - contains secret keys, keep it private.\n{}",
            toml::to_string_pretty(self)?
        );
        write_private(&Self::path(dir), text.as_bytes())
    }

    pub fn network_key(&self) -> Result<[u8; 32]> {
        crate::keys::unb64_32(&self.network_key).context("network_key")
    }

    pub fn network_id(&self) -> String {
        if self.network_id.is_empty() {
            self.network_key()
                .map(|k| crate::keys::network_tag(&k))
                .unwrap_or_default()
        } else {
            self.network_id.clone()
        }
    }

    /// All network keys this node knows, by version.
    pub fn all_keys(&self) -> Result<std::collections::HashMap<u32, [u8; 32]>> {
        let mut m = std::collections::HashMap::new();
        for k in &self.old_keys {
            m.insert(k.version, crate::keys::unb64_32(&k.key).context("old_keys")?);
        }
        m.insert(self.key_version, self.network_key()?);
        Ok(m)
    }

    pub fn listen_port(&self) -> Option<u16> {
        let l = self.listen.as_ref()?;
        l.rsplit(':').next()?.parse().ok()
    }

    /// Where outgoing connections go through, if anywhere.
    pub fn effective_socks(&self) -> Option<String> {
        if let Some(p) = &self.socks_proxy {
            return Some(p.clone());
        }
        match &self.ssh_tunnel {
            Some(t) if t.socks_port != 0 => Some(format!("127.0.0.1:{}", t.socks_port)),
            _ => None,
        }
    }

    /// Endpoints known from configuration alone (without asking peers).
    pub fn static_endpoints(&self) -> Vec<String> {
        let mut v = self.endpoints.clone();
        if let Some(t) = &self.ssh_tunnel
            && t.remote_port != 0
        {
            v.push(t.public_endpoint());
        }
        v
    }
}

/// Writes a file readable only by its owner, creating the parent directory.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir(parent)?;
    }
    // A unique temporary file: several threads may save the same file at the same time.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{n}", std::process::id()));
    let mut f = crate::sys::private(std::fs::OpenOptions::new().write(true).create(true).truncate(true))
        .open(&tmp)
        .map_err(|e| permission_hint(e, &tmp))?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn create_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| permission_hint(e, dir))?;
    crate::sys::set_mode(dir, 0o700).ok();
    #[cfg(windows)]
    if dir.starts_with(SYSTEM_DIR) {
        // ProgramData lets every user read, and create folders: once per run, the folder and
        // everything in it becomes the administrators' and SYSTEM's only (see sys).
        static DONE: std::sync::Once = std::sync::Once::new();
        DONE.call_once(|| {
            if let Err(e) = crate::sys::secure_system_dir(Path::new(SYSTEM_DIR)) {
                tracing::warn!("restricting access to {SYSTEM_DIR}: {e:#}");
            }
        });
    }
    Ok(())
}

fn permission_hint(e: std::io::Error, path: &Path) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        let rootless = match user_dir() {
            Some(u) if path.starts_with(SYSTEM_DIR) => {
                format!(
                    " (or, without root, set up a rootless install with --dir {})",
                    u.display()
                )
            }
            _ => String::new(),
        };
        anyhow::anyhow!(
            "permission denied writing {} - try again with sudo{rootless}",
            path.display()
        )
    } else {
        anyhow::Error::from(e).context(format!("writing {}", path.display()))
    }
}

/// What the daemon persists between runs, so the mesh survives the loss of bootstrap nodes.
#[derive(Serialize, Deserialize, Default)]
pub struct SavedState {
    pub me: Option<SignedInfo>,
    pub peers: Vec<SignedInfo>,
    #[serde(default)]
    pub forgotten: Vec<Forget>,
    /// The latest ban / key rotation, relayed to members that were offline.
    #[serde(default)]
    pub rotation: Option<crate::proto::SignedRotation>,
    /// Managed networks: the admin roster and the admissions of invited nodes.
    #[serde(default)]
    pub roster: Option<crate::proto::SignedDoc>,
    #[serde(default)]
    pub claims: Vec<crate::proto::ClaimMsg>,
    /// GPU reservations on this node.
    #[serde(default)]
    pub leases: Vec<crate::proto::Lease>,
    /// Admin-signed documents for extensions.
    #[serde(default)]
    pub docs: Vec<crate::proto::SignedDoc>,
    /// Open invites that may be joined through hole punching.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub join_slots: Vec<JoinSlot>,
}

impl SavedState {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("state.json")
    }
    pub fn load(dir: &Path) -> SavedState {
        std::fs::read(Self::path(dir))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, dir: &Path) -> Result<()> {
        write_private(&Self::path(dir), &serde_json::to_vec_pretty(self)?)
    }
}

/// Everything a new node needs to join: the network secret and a few addresses to dial.
#[derive(Serialize, Deserialize)]
pub struct Invite {
    pub network: String,
    pub key: String,
    pub bootstrap: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default)]
    pub v: u32,
    /// Managed networks: the admission ticket, and the admins to trust.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<crate::proto::SignedDoc>,
    /// The secret of the ticket's one-time key: only in the invite, never in the mesh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admins: Vec<crate::keys::NodeId>,
    /// Where to meet the inviting node if neither can reach the other (hole punching).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join: Option<JoinHint>,
}

/// A join through hole punching: the new node puts its IPv6 addresses into the DHT at a place
/// derived from `slot` (a secret of the invite) and tries the inviting node's addresses; the
/// inviting node looks there while the invite is open and tries back.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct JoinHint {
    pub slot: String,
    pub node: crate::keys::NodeId,
    pub v6: Vec<String>,
    pub until: u64,
}

/// An open invite's place, kept by the inviting node.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct JoinSlot {
    pub slot: String,
    pub from: u64,
    pub until: u64,
}

impl Invite {
    pub fn encode(&self) -> String {
        format!("{INVITE_PREFIX}{}", b64(&serde_json::to_vec(self).unwrap()))
    }
    pub fn decode(s: &str) -> Result<Self> {
        let s = s.trim();
        let Some(body) = s.strip_prefix(INVITE_PREFIX) else {
            bail!("this does not look like a meshvpn invite (it should start with `{INVITE_PREFIX}`)");
        };
        let inv: Invite = serde_json::from_slice(&unb64(body)?).context("corrupt invite")?;
        crate::keys::unb64_32(&inv.key).context("corrupt invite")?;
        Ok(inv)
    }
}

pub fn default_node_name() -> String {
    let raw = crate::sys::hostname();
    sanitize_name(if raw.is_empty() { "node" } else { &raw })
}

/// Names end up in DNS-like host names, so keep them to `[a-z0-9-]`.
pub fn sanitize_name(raw: &str) -> String {
    let s: String = raw
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        "node".into()
    } else {
        s.chars().take(40).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_roundtrip() {
        let inv = Invite {
            network: "home".into(),
            key: b64(&random32()),
            bootstrap: vec!["a.example:7870".into()],
            id: "abc".into(),
            v: 3,
            ticket: None,
            ticket_key: None,
            admins: vec![],
            join: None,
        };
        let back = Invite::decode(&format!("  {}\n", inv.encode())).unwrap();
        assert_eq!(back.key, inv.key);
        assert_eq!((back.id.as_str(), back.v), ("abc", 3));
        assert_eq!(back.bootstrap, inv.bootstrap);
        assert!(Invite::decode("hello").is_err());
    }

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize_name("My Laptop!\n"), "my-laptop");
        assert_eq!(sanitize_name("---"), "node");
    }
}

#[cfg(test)]
mod ssh_key_rule_tests {
    use super::SshAllowKey;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    #[test]
    fn only_a_plain_key_gets_through() {
        let (key, comment) = SshAllowKey::parse(&format!("  {KEY} alice@laptop (work)\n")).unwrap();
        assert_eq!(key, KEY);
        assert_eq!(comment, "alice@laptop_work");
        // Options would run a command at login; a second line would be a second key.
        assert!(SshAllowKey::parse(&format!("command=\"sh\" {KEY}")).is_err());
        assert!(SshAllowKey::parse(&format!("{KEY} a\n{KEY} b")).is_err());
        assert!(SshAllowKey::parse("ssh-ed25519 AAAAnotakeyatallnotakey").is_err());
        assert!(SshAllowKey::parse("ssh-ed25519").is_err());
    }

    #[test]
    fn allow_adds_and_deny_takes_away() {
        let mut rules = vec![];
        let users = |u: &[&str]| u.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        SshAllowKey::allow(&mut rules, KEY, &users(&["a"])).unwrap();
        SshAllowKey::allow(&mut rules, &format!("{KEY} other-comment"), &users(&["a", "b"])).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].users, ["a", "b"]);
        SshAllowKey::deny(&mut rules, KEY, &users(&["a"])).unwrap();
        assert_eq!(rules[0].users, ["b"]);
        SshAllowKey::deny(&mut rules, KEY, &[]).unwrap();
        assert!(rules.is_empty());
        assert!(SshAllowKey::deny(&mut rules, KEY, &[]).is_err());
    }
}
