//! On-disk configuration, persisted peer state and invite codes.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::keys::{b64, random32, unb64};
use crate::proto::{Forget, SignedInfo};

pub const DEFAULT_PORT: u16 = 7870;
pub const DEFAULT_SOCKS_PORT: u16 = 1081;
const INVITE_PREFIX: &str = "mesh1-";

fn default_iface() -> String {
    "mesh0".into()
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
    /// Install new releases from GitHub automatically (checked every 6 hours).
    #[serde(default = "default_true")]
    pub auto_update: bool,
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
            manage_hosts: true,
            auto_update: true,
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
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| permission_hint(e, &tmp))?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn create_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| permission_hint(e, dir))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok();
    Ok(())
}

fn permission_hint(e: std::io::Error, path: &Path) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        anyhow::anyhow!("permission denied writing {} - try again with sudo", path.display())
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
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_else(|_| "node".into());
    sanitize_name(&raw)
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
