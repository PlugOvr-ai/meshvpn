//! Messages exchanged between nodes (inside the encrypted link).

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::keys::{Identity, Key32, NodeId, b64, unb64, verify};

pub const T_HELLO: u8 = 1;
pub const T_GOSSIP: u8 = 2;
pub const T_DATA: u8 = 3;
pub const T_PING: u8 = 4;
pub const T_PONG: u8 = 5;
pub const T_FORGET: u8 = 6;
pub const T_ROTATE: u8 = 7;
/// Throughput test over a link: start, test data, end, and the receiver's result.
pub const T_BENCH_START: u8 = 8;
pub const T_BENCH_DATA: u8 = 9;
pub const T_BENCH_END: u8 = 10;
pub const T_BENCH_RESULT: u8 = 11;
/// "Please measure now" for a set of nodes (flooded).
pub const T_MEASURE: u8 = 12;

#[derive(Serialize, Deserialize)]
pub struct BenchMsg {
    pub id: u64,
    #[serde(default)]
    pub mbps: f32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MeasureReq {
    pub nonce: u64,
    pub nodes: Vec<NodeId>,
    pub bytes: u64,
}

/// Header of a data frame: dst(32) src(32) ttl(1) nonce(24), followed by the sealed IP packet.
pub const DATA_HDR: usize = 32 + 32 + 1 + 24;
pub const DEFAULT_TTL: u8 = 8;

/// What a node tells the world about itself. Signed by the node, gossiped by everyone.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeInfo {
    pub id: NodeId,
    pub noise_pub: Key32,
    pub name: String,
    /// `host:port` addresses where the node accepts connections.
    pub endpoints: Vec<String>,
    /// Nodes this node currently has a direct link to (used for relay routing).
    pub neighbors: Vec<NodeId>,
    /// Monotonic version, newer wins.
    pub seq: u64,
    /// Network this record belongs to (see `keys::network_tag`).
    #[serde(default)]
    pub net: String,
    #[serde(default)]
    pub version: String,
    /// SSH public keys of this node's users, for password-less logins that other nodes
    /// may allow (`meshvpn ssh allow`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_keys: Vec<SshKey>,
    /// Free-form labels (`gpu`, `trainer`, `cluster-a`) for addressing groups of nodes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Hardware and load, so agents can pick suitable machines without logging in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<Inventory>,
    /// Physical networks (`ip/prefix`) this node is on, for direct LAN paths between nodes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lan: Vec<String>,
    /// This node's measurements towards other nodes (one row of the network matrix).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub perf: Vec<Perf>,
    /// UDP address candidates (`ip:port`) for direct paths through NATs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp: Vec<String>,
    /// When this node last finished a requested measurement (ms since epoch).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub measured: u64,
    /// Shared datasets/checkpoints this node has completely and serves to others.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<ObjectAd>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Inventory {
    pub os: String,
    pub arch: String,
    pub kernel: String,
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub load1: f32,
    pub mem_total_mb: u64,
    pub mem_avail_mb: u64,
    pub disk_total_gb: u64,
    pub disk_free_gb: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gpus: Vec<Gpu>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gpu_driver: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cuda: String,
    /// Running without a TUN device (programs here reach the mesh via SOCKS only).
    #[serde(default)]
    pub userspace: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Gpu {
    pub index: u32,
    pub name: String,
    pub mem_total_mb: u64,
    pub mem_used_mb: u64,
    pub util_pct: u32,
}

/// What a node measured towards `peer`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Perf {
    pub peer: NodeId,
    /// Round trip over the mesh link, microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_us: Option<u32>,
    /// Measured throughput over the mesh, Mbit/s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_mbps: Option<f32>,
    /// `peer`'s address on a LAN both share, verified reachable from here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_ip: Option<String>,
    /// When it was measured (ms since epoch).
    pub at: u64,
}

/// A shared dataset or checkpoint (see `meshvpn share`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ObjectAd {
    pub id: String,
    pub name: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SshKey {
    /// Account on the publishing node.
    pub user: String,
    /// `<type> <base64>`, without comment.
    pub key: String,
}

/// Text from other nodes that ends up on terminals: short, no control characters.
fn is_zero(v: &u64) -> bool {
    *v == 0
}

pub fn clean_text(t: &str) -> bool {
    t.len() <= 128 && !t.chars().any(char::is_control)
}

pub fn valid_tag(t: &str) -> bool {
    (1..=48).contains(&t.len())
        && t.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.=".contains(c))
}

pub fn valid_object_id(id: &str) -> bool {
    id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

pub fn valid_user(u: &str) -> bool {
    (1..=32).contains(&u.len())
        && !u.starts_with('-')
        && u.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-".contains(c))
}

pub fn valid_ssh_key(k: &str) -> bool {
    const TYPES: &[&str] = &[
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    ];
    let mut parts = k.split(' ');
    let (Some(t), Some(b), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    TYPES.contains(&t)
        && (16..=4096).contains(&b.len())
        && b.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedInfo {
    pub data: String,
    pub sig: String,
}

impl SignedInfo {
    pub fn sign(info: &NodeInfo, ident: &Identity) -> Self {
        let data = serde_json::to_string(info).unwrap();
        let sig = b64(&ident.sign(data.as_bytes()));
        SignedInfo { data, sig }
    }

    /// Checks the signature and that the record belongs to network `net`.
    pub fn verify(&self, net: &str) -> Result<NodeInfo> {
        let info: NodeInfo = serde_json::from_str(&self.data)?;
        verify(&info.id, self.data.as_bytes(), &unb64(&self.sig)?)?;
        if info.net != net {
            bail!(
                "node {} belongs to a different network or runs an older meshvpn version (update it)",
                info.name
            );
        }
        if info.endpoints.len() > 32 || info.neighbors.len() > 4096 {
            bail!("oversized node info");
        }
        // Names end up in /etc/hosts and on terminals: only accept what we would generate.
        if info.name != crate::config::sanitize_name(&info.name) {
            bail!("invalid node name");
        }
        if info
            .endpoints
            .iter()
            .any(|e| e.len() > 262 || e.chars().any(|c| c.is_control() || c.is_whitespace()))
        {
            bail!("invalid endpoint");
        }
        if !info.tags.iter().all(|t| valid_tag(t)) || info.tags.len() > 32 {
            bail!("invalid tags");
        }
        if let Some(inv) = &info.inventory {
            let texts = [
                &inv.os,
                &inv.arch,
                &inv.kernel,
                &inv.cpu_model,
                &inv.gpu_driver,
                &inv.cuda,
            ];
            if inv.gpus.len() > 32
                || !texts
                    .into_iter()
                    .chain(inv.gpus.iter().map(|g| &g.name))
                    .all(|t| clean_text(t))
            {
                bail!("invalid inventory");
            }
        }
        if info.udp.len() > 8 || info.udp.iter().any(|a| a.parse::<std::net::SocketAddrV4>().is_err()) {
            bail!("invalid udp candidates");
        }
        if info.lan.len() > 16 || info.lan.iter().any(|l| crate::net::parse_cidr(l).is_none()) {
            bail!("invalid lan");
        }
        if info.perf.len() > 1024
            || info.perf.iter().any(|p| {
                p.lan_ip
                    .as_ref()
                    .is_some_and(|ip| ip.parse::<std::net::Ipv4Addr>().is_err())
            })
        {
            bail!("invalid perf");
        }
        if info.objects.len() > 256
            || info
                .objects
                .iter()
                .any(|o| !valid_object_id(&o.id) || !clean_text(&o.name))
        {
            bail!("invalid objects");
        }
        // These end up in sshd's authorized keys: accept nothing but plain keys.
        if info.ssh_keys.len() > 64
            || info
                .ssh_keys
                .iter()
                .any(|k| !valid_user(&k.user) || !valid_ssh_key(&k.key))
        {
            bail!("invalid ssh key");
        }
        Ok(info)
    }
}

/// "Forget node `id` up to version `seq`": removes an offline node everywhere. A node that is
/// actually alive comes back with its next (newer) record.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Forget {
    pub id: NodeId,
    pub seq: u64,
    /// When it was issued (ms since epoch), so it can expire.
    pub at: u64,
}

/// The new network key, sealed for one member.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    pub to: NodeId,
    pub nonce: String,
    pub sealed: String,
}

/// A ban: the listed nodes are out, and every other member gets a new network key so the
/// banned ones cannot come back under a new identity.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Rotation {
    pub net: String,
    pub version: u32,
    pub issuer: NodeId,
    pub issuer_noise: Key32,
    /// All nodes banned so far (so members that were away learn about every ban).
    pub banned: Vec<(NodeId, String)>,
    pub envelopes: Vec<Envelope>,
    pub at: u64,
}

/// A rotation signed by the member that issued it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedRotation {
    pub data: String,
    pub sig: String,
}

impl SignedRotation {
    pub fn sign(r: &Rotation, ident: &Identity) -> Self {
        let data = serde_json::to_string(r).unwrap();
        let sig = b64(&ident.sign(data.as_bytes()));
        SignedRotation { data, sig }
    }

    pub fn verify(&self, net: &str) -> Result<Rotation> {
        let r: Rotation = serde_json::from_str(&self.data)?;
        verify(&r.issuer, self.data.as_bytes(), &unb64(&self.sig)?)?;
        if r.net != net {
            bail!("key rotation of another network");
        }
        Ok(r)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Hello {
    pub info: SignedInfo,
    /// The address we see the other side connecting from (helps it learn its public IP).
    pub observed: String,
    /// Random per-connection value; used to pick the same link on both sides when two race.
    #[serde(default)]
    pub nonce: u64,
}

pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 1);
    v.push(kind);
    v.extend_from_slice(payload);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn ident() -> Identity {
        Identity::from_config(&Config::new("n".into(), "net".into(), crate::keys::random32())).unwrap()
    }

    fn info(id: &Identity, name: &str) -> NodeInfo {
        NodeInfo {
            id: id.id,
            noise_pub: id.noise_pub,
            name: name.into(),
            endpoints: vec!["1.2.3.4:7870".into()],
            neighbors: vec![],
            seq: 1,
            net: "n1".into(),
            ssh_keys: vec![],
            tags: vec![],
            inventory: None,
            lan: vec![],
            perf: vec![],
            udp: vec![],
            measured: 0,
            objects: vec![],
            version: String::new(),
        }
    }

    #[test]
    fn signed_info_roundtrip_and_tamper() {
        let id = ident();
        let s = SignedInfo::sign(&info(&id, "alpha"), &id);
        assert_eq!(s.verify("n1").unwrap().name, "alpha");
        assert!(s.verify("other-network").is_err());
        let tampered = SignedInfo {
            data: s.data.replace("1.2.3.4", "6.6.6.6"),
            sig: s.sig.clone(),
        };
        assert!(tampered.verify("n1").is_err());
    }

    #[test]
    fn ssh_keys_are_validated() {
        assert!(valid_ssh_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
        ));
        assert!(!valid_ssh_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl comment"
        ));
        assert!(!valid_ssh_key("command=\"sh\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"));
        assert!(!valid_ssh_key("ssh-ed25519 AAAAC3Nza\nssh-rsa AAAAB3NzaC1yc2E"));
        assert!(valid_user("cornelius") && valid_user("svc_backup-1"));
        assert!(!valid_user("-oProxyCommand") && !valid_user("Root") && !valid_user("a b"));
        let id = ident();
        let mut i = info(&id, "alpha");
        i.ssh_keys = vec![SshKey {
            user: "bob".into(),
            key: "ssh-rsa AAAA\nevil".into(),
        }];
        assert!(SignedInfo::sign(&i, &id).verify("n1").is_err());
    }

    #[test]
    fn rejects_hostile_names() {
        let id = ident();
        let s = SignedInfo::sign(&info(&id, "evil\n1.2.3.4 bank.com"), &id);
        assert!(s.verify("n1").is_err());
    }
}
