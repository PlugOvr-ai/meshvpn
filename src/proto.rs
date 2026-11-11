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
/// Measurement requests of other nodes: ignored since 0.30.1 (`Node::start_measure`).
pub const T_MEASURE: u8 = 12;
/// The admin roster (managed networks), and admissions of new nodes (flooded).
pub const T_ROSTER: u8 = 13;
pub const T_CLAIM: u8 = 14;
/// Why a node was turned away (sent to it right before the connection is closed).
pub const T_REJECT: u8 = 15;
/// An admin-signed document for extensions (gossiped, kept by every node).
pub const T_DOC: u8 = 16;
/// A signed message from one node's extension to another's (routed like data).
pub const T_EXT: u8 = 17;
/// `meshvpn net why`: test the direct path together, and what each side saw.
pub const T_WHY: u8 = 18;
pub const T_WHY_REPLY: u8 = 19;
/// Which records a node has: (node id, seq) pairs, 40 bytes each, to one neighbor at a time.
/// The neighbor sends back what is newer on its side and asks (`T_WANT`) for what is newer here.
pub const T_DIGEST: u8 = 20;
/// The records of these node ids, please (32 bytes each).
pub const T_WANT: u8 = 21;
/// Details of nodes (`SignedDetails`, a JSON list): sent apart from the records, like them.
pub const T_DETAILS: u8 = 22;
/// The details of these node ids, please (32 bytes each).
pub const T_WANT_DETAILS: u8 = 23;
/// `T_DIGEST` with liveness, to nodes that take details apart: (node id, seq, seconds since
/// the sender last heard from that node, `u16::MAX` for never), 42 bytes each.
pub const T_DIGEST2: u8 = 24;

/// A JSON document signed by a node.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SignedDoc {
    pub data: String,
    pub sig: String,
}

impl SignedDoc {
    pub fn sign<T: Serialize>(value: &T, ident: &Identity) -> Self {
        let data = serde_json::to_string(value).unwrap();
        let sig = b64(&ident.sign(data.as_bytes()));
        SignedDoc { data, sig }
    }

    /// Parses and checks the signature of the node `signer` names in the document.
    pub fn open<T: serde::de::DeserializeOwned>(&self, signer: impl Fn(&T) -> NodeId) -> Result<T> {
        let v: T = serde_json::from_str(&self.data)?;
        verify(&signer(&v), self.data.as_bytes(), &unb64(&self.sig)?)?;
        Ok(v)
    }
}

/// Who runs a managed network: only admins invite, ban and change the roster. Every version is
/// signed by an admin of the previous one. `members` are the nodes admitted without a ticket
/// (those that were there when the network became managed).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Roster {
    pub net: String,
    pub version: u32,
    pub admins: Vec<NodeId>,
    pub members: Vec<NodeId>,
    pub issuer: NodeId,
    pub at: u64,
}

/// An invitation ticket, signed by an admin: good for `uses` new nodes until `expires`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Ticket {
    pub net: String,
    pub id: String,
    pub expires: u64,
    pub uses: u32,
    pub issuer: NodeId,
    /// A client, not a node: a user's computer, a member until `ClientGrant::until` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientGrant>,
    /// The public half of a one-time key whose secret is only in the invite: a claim must be
    /// signed with it too, so members who see the ticket in claims can't use it themselves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<NodeId>,
}

/// What makes a member a client: whose computer it is, and until when it may be one. Clients
/// relay nothing for others and nobody routes through them; extensions may treat them apart
/// (e.g. not count them, or let them reach only some nodes).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClientGrant {
    pub user: String,
    pub until: u64,
}

/// A new node binding a ticket to itself (signed by that node).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Claim {
    pub net: String,
    pub ticket: SignedDoc,
    pub node: NodeId,
    pub at: u64,
    /// With a bound ticket (`Ticket::key`): the invite's one-time key signs `proof_bytes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

impl Claim {
    /// What the invite's one-time key signs: this node, this time, this ticket.
    pub fn proof_bytes(net: &str, ticket_id: &str, node: &NodeId, at: u64) -> Vec<u8> {
        format!("meshvpn ticket proof v1\n{net}\n{ticket_id}\n{node}\n{at}").into_bytes()
    }
}

/// A claim as it travels, with the countersignature of the member that first saw it while
/// the ticket was still valid - so nodes that were offline then can still accept it later.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClaimMsg {
    pub claim: SignedDoc,
    #[serde(default)]
    pub witness: Option<(NodeId, String)>,
}

#[derive(Serialize, Deserialize)]
pub struct BenchMsg {
    pub id: u64,
    #[serde(default)]
    pub mbps: f32,
}

/// `meshvpn net why`, flooded: `to` tests its direct path to `from` together with it.
#[derive(Serialize, Deserialize, Clone)]
pub struct WhyReq {
    pub nonce: u64,
    pub from: NodeId,
    pub to: NodeId,
}

/// What one side of a direct path saw during `meshvpn net why`.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WhySide {
    pub nonce: u64,
    pub name: String,
    pub udp_on: bool,
    /// See `NatKind::code`.
    pub nat: String,
    pub nat_text: String,
    pub ipv6: Vec<String>,
    /// The other side's addresses this side tries.
    pub candidates: Vec<String>,
    /// Probes this side sent during the test.
    pub sent: u32,
    /// Probes from the other side that arrived here.
    pub heard: u32,
    /// Answers to this side's probes that arrived here.
    pub answers: u32,
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
    /// IPv6 candidates (`[ip]:port`), separate so that nodes from before IPv6 accept the record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp6: Vec<String>,
    /// When this node last finished a requested measurement (ms since epoch).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub measured: u64,
    /// Shared datasets/checkpoints this node has completely and serves to others.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<ObjectAd>,
    /// GPU reservations on this node (granted by this node, so they can't collide).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leases: Vec<Lease>,
    /// Host key of the SSH server answering on port 22 here (`ssh-ed25519 AAAA...`), so other
    /// nodes can trust it without asking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_host_key: Option<String>,
    /// The account to log in as by default (`meshvpn ssh default-user`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_user: Option<String>,
    /// Offers its internet connection to the mesh (an exit node).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exit: bool,
    /// Has its IPv6 address in the mesh: others send it IPv6 (older nodes have none).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ipv6: bool,
    /// Exchanges digests (`T_DIGEST`): records are forwarded to it by a few nodes only, not by
    /// every node that has them (older nodes get every record from everyone, as before).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub digest: bool,
    /// How many links this node has; `neighbors` names only some of them in a big mesh.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub links: u64,
    /// The details (inventory, perf, measured, objects, leases) are not in this record but in
    /// a `NodeDetails` of version `details`. Nodes without this flag send and get full records.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub split: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub details: u64,
    /// Which candidate address this node uses (`keys::overlay_ip_at`): not 0 after it moved
    /// away from an address another node has too.
    #[serde(default, skip_serializing_if = "is_zero8")]
    pub ip_index: u8,
}

impl NodeInfo {
    /// The node's IPv4 mesh address (the one it claims; see `assign_ips` for who gets it).
    pub fn ip(&self) -> std::net::Ipv4Addr {
        crate::keys::overlay_ip_at(&self.id, self.ip_index)
    }

    /// The details of this record as a document of their own.
    pub fn details_doc(&self, seq: u64) -> NodeDetails {
        NodeDetails {
            kind: DETAILS_KIND.into(),
            id: self.id,
            net: self.net.clone(),
            seq,
            inventory: self.inventory.clone(),
            perf: self.perf.clone(),
            measured: self.measured,
            objects: self.objects.clone(),
            leases: self.leases.clone(),
        }
    }

    /// This record without its details, which go apart (version `details`).
    pub fn core(&self, details: u64) -> NodeInfo {
        NodeInfo {
            inventory: None,
            perf: vec![],
            measured: 0,
            objects: vec![],
            leases: vec![],
            split: true,
            details,
            ..self.clone()
        }
    }

    /// The details of `d` put into this record.
    pub fn apply(&mut self, d: &NodeDetails) {
        self.inventory = d.inventory.clone();
        self.perf = d.perf.clone();
        self.measured = d.measured;
        self.objects = d.objects.clone();
        self.leases = d.leases.clone();
    }
}

const DETAILS_KIND: &str = "details";

/// What changes often and only some commands need (`nodes`, `gpu list`, `net matrix`,
/// `objects`, reservations): signed apart from the record, so that the record stays small and
/// these go only when they change.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NodeDetails {
    /// Always "details": a signature over one kind of document is never one over another.
    pub kind: String,
    pub id: NodeId,
    pub net: String,
    /// Monotonic version, newer wins (separate from the record's).
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<Inventory>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub perf: Vec<Perf>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub measured: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<ObjectAd>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leases: Vec<Lease>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedDetails {
    pub data: String,
    pub sig: String,
}

impl SignedDetails {
    pub fn sign(d: &NodeDetails, ident: &Identity) -> Self {
        let data = serde_json::to_string(d).unwrap();
        let sig = b64(&ident.sign(data.as_bytes()));
        SignedDetails { data, sig }
    }

    /// Node id and seq without checking the signature (see `SignedInfo::peek`).
    pub fn peek(&self) -> Option<(NodeId, u64)> {
        #[derive(Deserialize)]
        struct Peek {
            id: NodeId,
            seq: u64,
        }
        let p: Peek = serde_json::from_str(&self.data).ok()?;
        Some((p.id, p.seq))
    }

    pub fn verify(&self, net: &str) -> Result<NodeDetails> {
        let d: NodeDetails = serde_json::from_str(&self.data)?;
        if d.kind != DETAILS_KIND {
            bail!("not a node's details");
        }
        verify(&d.id, self.data.as_bytes(), &unb64(&self.sig)?)?;
        if d.net != net {
            bail!("details of a node of another network");
        }
        check_details(&d.inventory, &d.perf, &d.leases, &d.objects)?;
        Ok(d)
    }
}

/// GPUs of a node reserved for someone until `expires` (ms since epoch).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Lease {
    pub id: String,
    pub gpus: Vec<u32>,
    pub holder: String,
    pub expires: u64,
    /// The local user who reserved them: only they (or root) may release or renew it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
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
    /// Measured throughput over that LAN path (straight, not through the mesh), Mbit/s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_mbps: Option<f32>,
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
fn is_zero8(v: &u8) -> bool {
    *v == 0
}

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

/// A host key as published for known_hosts: `<type> <base64>` of a type sshd uses.
pub fn valid_host_key(k: &str) -> bool {
    let mut parts = k.split(' ');
    let (Some(t), Some(b), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    [
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ]
    .contains(&t)
        && (16..=4096).contains(&b.len())
        && b.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
}

const SSH_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Does this start like an SSH public key (as opposed to a node name)?
pub fn looks_like_ssh_key(s: &str) -> bool {
    s.split_whitespace().next().is_some_and(|t| SSH_KEY_TYPES.contains(&t))
}

pub fn valid_ssh_key(k: &str) -> bool {
    let mut parts = k.split(' ');
    let (Some(t), Some(b), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    SSH_KEY_TYPES.contains(&t)
        && (16..=4096).contains(&b.len())
        && b.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedInfo {
    pub data: String,
    pub sig: String,
}

/// What a record's details (in it, or apart: `NodeDetails`) may hold.
fn check_details(inventory: &Option<Inventory>, perf: &[Perf], leases: &[Lease], objects: &[ObjectAd]) -> Result<()> {
    if let Some(inv) = inventory {
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
    if perf.len() > 1024
        || perf.iter().any(|p| {
            p.lan_ip
                .as_ref()
                .is_some_and(|ip| ip.parse::<std::net::Ipv4Addr>().is_err())
        })
    {
        bail!("invalid perf");
    }
    if leases.len() > 64
        || leases
            .iter()
            .any(|l| !clean_text(&l.holder) || l.id.len() > 16 || l.gpus.len() > 64)
    {
        bail!("invalid leases");
    }
    if objects.len() > 256 || objects.iter().any(|o| !valid_object_id(&o.id) || !clean_text(&o.name)) {
        bail!("invalid objects");
    }
    Ok(())
}

impl SignedInfo {
    pub fn sign(info: &NodeInfo, ident: &Identity) -> Self {
        let data = serde_json::to_string(info).unwrap();
        let sig = b64(&ident.sign(data.as_bytes()));
        SignedInfo { data, sig }
    }

    /// Checks the signature and that the record belongs to network `net`.
    /// Node id and seq, read without checking the signature: only to skip records that are
    /// not newer than what we have before the costly part.
    pub fn peek(&self) -> Option<(NodeId, u64)> {
        #[derive(Deserialize)]
        struct Peek {
            id: NodeId,
            seq: u64,
        }
        let p: Peek = serde_json::from_str(&self.data).ok()?;
        Some((p.id, p.seq))
    }

    pub fn verify(&self, net: &str) -> Result<NodeInfo> {
        let info: NodeInfo = serde_json::from_str(&self.data)?;
        verify(&info.id, self.data.as_bytes(), &unb64(&self.sig)?)?;
        if info.net != net {
            bail!(
                "node {} belongs to a different network or runs an older meshvpn version (update it)",
                info.name
            );
        }
        if info.endpoints.len() > 32 || info.neighbors.len() > 4096 || info.ip_index >= crate::keys::IP_CANDIDATES {
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
        if info.udp.len() > 8 || info.udp.iter().any(|a| a.parse::<std::net::SocketAddrV4>().is_err()) {
            bail!("invalid udp candidates");
        }
        if info.udp6.len() > 4 || info.udp6.iter().any(|a| a.parse::<std::net::SocketAddrV6>().is_err()) {
            bail!("invalid udp6 candidates");
        }
        if info.lan.len() > 16 || info.lan.iter().any(|l| crate::net::parse_cidr(l).is_none()) {
            bail!("invalid lan");
        }
        check_details(&info.inventory, &info.perf, &info.leases, &info.objects)?;
        // Shown on terminals and compared as a version.
        if info.version.len() > 32
            || !info
                .version
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c))
        {
            bail!("invalid version");
        }
        // Goes into ssh command lines as `user@host`: anything but a plain user name could be
        // read as an option by ssh.
        if info.login_user.as_ref().is_some_and(|u| !valid_user(u)) {
            bail!("invalid login user");
        }
        // Written to the known hosts file.
        if info.ssh_host_key.as_ref().is_some_and(|k| !valid_host_key(k)) {
            bail!("invalid ssh host key");
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
///
/// Signed by the node that issued it (`by`): only a member may ask the others to forget a node,
/// in a managed network only an admin (`crate::node`).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Forget {
    pub id: NodeId,
    pub seq: u64,
    /// When it was issued (ms since epoch), so it can expire.
    pub at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<NodeId>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig: String,
}

impl Forget {
    fn message(&self) -> Vec<u8> {
        format!("meshvpn forget v1 {} {} {}", self.id.hex(), self.seq, self.at).into_bytes()
    }

    pub fn sign(id: NodeId, seq: u64, at: u64, ident: &Identity) -> Self {
        let mut f = Forget {
            id,
            seq,
            at,
            by: Some(ident.id),
            sig: String::new(),
        };
        f.sig = b64(&ident.sign(&f.message()));
        f
    }

    /// Who signed it, if the signature is good.
    pub fn signer(&self) -> Option<NodeId> {
        let by = self.by?;
        verify(&by, &self.message(), &unb64(&self.sig).ok()?).ok()?;
        Some(by)
    }
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
    /// A new node's admission (managed networks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<ClaimMsg>,
    /// The record without details (`NodeInfo::split`), newer than `info`, which is the full
    /// one for older nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core: Option<SignedInfo>,
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

    #[test]
    fn forgets_are_signed() {
        let (a, b) = (ident(), ident());
        let f = Forget::sign(b.id, 7, 1000, &a);
        assert_eq!(f.signer(), Some(a.id));
        let mut changed = f.clone();
        changed.seq = u64::MAX;
        assert_eq!(changed.signer(), None, "the version is signed");
        let mut other = f.clone();
        other.by = Some(b.id);
        assert_eq!(other.signer(), None, "the signer is the one named");
        let old: Forget = serde_json::from_str(&format!(r#"{{"id":"{}","seq":1,"at":2}}"#, b.id.hex())).unwrap();
        assert_eq!(old.signer(), None, "unsigned (older versions)");
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
            udp6: vec![],
            measured: 0,
            objects: vec![],
            leases: vec![],
            ssh_host_key: None,
            login_user: None,
            exit: false,
            ipv6: false,
            digest: false,
            links: 0,
            version: String::new(),
            split: false,
            details: 0,
            ip_index: 0,
        }
    }

    #[test]
    fn details_apart_from_the_record() {
        let id = ident();
        let mut full = info(&id, "alpha");
        full.leases = vec![Lease {
            id: "r1".into(),
            gpus: vec![0],
            holder: "bob".into(),
            expires: 9,
            owner: None,
        }];
        full.measured = 7;
        let core = full.core(5);
        assert!(core.split && core.details == 5 && core.leases.is_empty() && core.measured == 0);
        let d = SignedDetails::sign(&full.details_doc(5), &id);
        let got = d.verify("n1").unwrap();
        let mut merged = SignedInfo::sign(&core, &id).verify("n1").unwrap();
        merged.apply(&got);
        assert_eq!(merged.leases, full.leases);
        assert_eq!(merged.measured, 7);
        assert_eq!(d.peek(), Some((id.id, 5)));
        assert!(d.verify("other-network").is_err());
        // Neither signature stands for the other kind of document.
        let as_info = SignedInfo {
            data: d.data.clone(),
            sig: d.sig.clone(),
        };
        assert!(as_info.verify("n1").is_err());
        let r = SignedInfo::sign(&full, &id);
        assert!(
            SignedDetails {
                data: r.data.clone(),
                sig: r.sig.clone()
            }
            .verify("n1")
            .is_err()
        );
        let tampered = SignedDetails {
            data: d.data.replace("bob", "eve"),
            sig: d.sig.clone(),
        };
        assert!(tampered.verify("n1").is_err());
        // Older nodes read a core record as one without details.
        let old: serde_json::Value = serde_json::from_str(&SignedInfo::sign(&core, &id).data).unwrap();
        assert_eq!(old["split"], true);
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
    fn record_fields_are_validated() {
        let id = ident();
        let check = |f: &dyn Fn(&mut NodeInfo)| {
            let mut i = info(&id, "alpha");
            f(&mut i);
            SignedInfo::sign(&i, &id).verify("n1").is_ok()
        };
        assert!(check(&|i| i.version = "0.13.4".into()));
        assert!(!check(&|i| i.version = "1.0\u{1b}[2J".into()));
        assert!(check(&|i| i.login_user = Some("ubuntu".into())));
        assert!(!check(&|i| i.login_user = Some("-oProxyCommand=sh".into())));
        assert!(!check(&|i| i.login_user = Some("a;b".into())));
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        assert!(check(&|i| i.ssh_host_key = Some(key.into())));
        assert!(!check(&|i| i.ssh_host_key = Some(format!("{key}\n* ssh-rsa AAAA"))));
        assert!(!check(
            &|i| i.ssh_host_key = Some("@cert-authority * ssh-ed25519 AAAA".into())
        ));
    }

    #[test]
    fn rejects_hostile_names() {
        let id = ident();
        let s = SignedInfo::sign(&info(&id, "evil\n1.2.3.4 bank.com"), &id);
        assert!(s.verify("n1").is_err());
    }
}
