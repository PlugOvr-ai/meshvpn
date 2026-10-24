//! The built-in SSH server: `ssh user@node.mesh` works on machines without an sshd (typically
//! containers). Only reachable through the mesh; logins follow the same rules as the sshd
//! integration (`meshvpn ssh allow`), with the keys the nodes publish, each only from its own
//! node. Shells with a terminal, commands, sftp/scp and `-L` port forwarding.
//!
//! As root it logs users in as themselves (setgroups/setgid/setuid in the child); a rootless
//! meshvpn can only log in its own user.

use russh::keys::{PrivateKey, ssh_key};
use russh::{MethodKind, MethodSet, SshId};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::keys::Identity;

// Sessions: Unix only (pseudo-terminals, logging users in as themselves).
#[cfg(unix)]
mod server;
#[cfg(unix)]
pub use server::*;

/// Windows: no built-in SSH server (yet) - other nodes log in through the mesh where an sshd runs.
#[cfg(windows)]
pub async fn serve<S>(
    _node: Arc<crate::node::Node>,
    _stream: S,
    _peer: std::net::SocketAddr,
    _local: std::net::SocketAddr,
) {
}

#[cfg(windows)]
pub async fn listen(_node: Arc<crate::node::Node>, _listener: tokio::net::TcpListener) {}

#[cfg(windows)]
pub fn sftp_server() -> anyhow::Result<()> {
    anyhow::bail!("the built-in SSH server isn't available on Windows")
}

/// The SSH host key, derived from the node identity: stable across restarts and the same
/// key every other node already knows (they get it with the node's record).
pub fn host_key(ident: &Identity) -> PrivateKey {
    let seed = blake3::derive_key("meshvpn ssh host key v1", &ident.signing.to_bytes());
    let pair = ssh_key::private::Ed25519Keypair::from_seed(&seed);
    PrivateKey::from(pair)
}

/// `ssh-ed25519 AAAA...` of the host key.
pub fn host_key_line(ident: &Identity) -> String {
    host_key(ident).public_key().to_openssh().unwrap_or_default()
}

pub fn config(ident: &Identity) -> Arc<russh::server::Config> {
    Arc::new(russh::server::Config {
        server_id: SshId::Standard(format!("SSH-2.0-meshvpn_{}", env!("CARGO_PKG_VERSION")).into()),
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: Duration::from_millis(300),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![host_key(ident)],
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 4,
        nodelay: true,
        ..Default::default()
    })
}

/// Paths where a system sshd would live: if one is installed, kernel mode leaves port 22 to it.
pub fn sshd_installed() -> bool {
    ["/usr/sbin/sshd", "/usr/bin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"]
        .iter()
        .any(|p| Path::new(p).exists())
}

/// The host key a running sshd presents (published so other nodes can verify it).
pub fn sshd_host_key() -> Option<String> {
    let text = std::fs::read_to_string("/etc/ssh/ssh_host_ed25519_key.pub").ok()?;
    let mut parts = text.split_whitespace();
    Some(format!("{} {}", parts.next()?, parts.next()?))
}
