//! The mesh daemon: links, gossip, routing and the packet path between TUN and peers.

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::{Config, SavedState, Userspace};
use crate::keys::{Identity, NodeId, OVERLAY_NETMASK, overlay_ip};
use crate::link::{self, Cipher, LinkReader, LinkWriter};
use crate::proto::*;

mod admin;
mod gpu;
mod udp;

/// Where IP packets for this node go: the kernel, or the TCP/IP stack in this process.
enum PacketIo {
    Tun(Arc<tun::AsyncDevice>),
    Userspace(crate::userspace::StackTx),
}

const OVERLAY_PREFIX: u8 = 10;

const TICK: Duration = Duration::from_secs(10);
const REANNOUNCE: Duration = Duration::from_secs(30);
/// A node we have not heard a fresh record from within this window is offline.
const ONLINE_WINDOW: Duration = Duration::from_secs(95);
/// Links that are silent this long are dead (we ping every TICK).
const LINK_TIMEOUT: Duration = Duration::from_secs(45);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// Forget nodes we have not heard of for a week.
const FORGET_AFTER_MS: u64 = 7 * 24 * 3600 * 1000;
/// Gossip messages stay well below the 64 KB link frame limit.
const GOSSIP_BYTES: usize = 48 * 1024;
/// An offline node whose name is now used by a newer, online node (typically the same machine
/// set up again) is forgotten automatically after this long.
const AUTO_FORGET_AFTER: Duration = Duration::from_secs(600);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Other interfaces holding addresses in our overlay range. Their routes and firewall rules
/// win over ours: e.g. Tailscale drops every packet from 100.64.0.0/10 not arriving on
/// tailscale0, which silently breaks all incoming mesh traffic.
pub fn range_conflicts(own_iface: &str) -> Vec<String> {
    let mut out = vec![];
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return out;
    }
    let mut cur = addrs;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || unsafe { (*ifa.ifa_addr).sa_family } as i32 != libc::AF_INET {
            continue;
        }
        let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if name == own_iface || !is_overlay(IpAddr::V4(ip)) {
            continue;
        }
        let hint = if name.starts_with("tailscale") {
            " - Tailscale's firewall drops all mesh traffic arriving on other interfaces; \
             uninstall Tailscale (or run `sudo tailscale down`) on this machine"
        } else {
            " - traffic to or from mesh IPs may be dropped or misrouted"
        };
        out.push(format!(
            "interface {name} ({ip}) uses the same address range as meshvpn (100.64.0.0/10){hint}"
        ));
    }
    unsafe { libc::freeifaddrs(addrs) };
    out
}

fn is_overlay(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) & u32::from(OVERLAY_NETMASK) == 0x6440_0000,
        _ => false,
    }
}

struct Record {
    info: NodeInfo,
    signed: SignedInfo,
    /// When we last received a *newer* version of the record (None = loaded from disk).
    last_heard: Option<Instant>,
}

struct LinkEntry {
    link_id: u64,
    tx: mpsc::Sender<Vec<u8>>,
    /// Lower is better; both ends compute the same value for the same connection.
    rank: (bool, u64),
    kill: Arc<Notify>,
    addr: String,
    rtt: Option<Duration>,
}

struct Backoff {
    next: Instant,
    delay: Duration,
}

#[derive(Default)]
struct State {
    records: HashMap<NodeId, Record>,
    links: HashMap<NodeId, LinkEntry>,
    ip_map: HashMap<Ipv4Addr, NodeId>,
    /// destination -> first hop
    routes: HashMap<NodeId, NodeId>,
    ciphers: HashMap<NodeId, XChaCha20Poly1305>,
    observed_ips: Vec<IpAddr>,
    backoff: HashMap<String, Backoff>,
    dialing: HashSet<String>,
    bootstrap_ids: HashMap<String, NodeId>,
    extra_bootstrap: Vec<String>,
    my_seq: u64,
    my_signed: Option<SignedInfo>,
    my_endpoints: Vec<String>,
    hosts_written: String,
    known_hosts_written: String,
    /// Host key of whatever answers SSH here (published in our record).
    my_ssh_host_key: Option<String>,
    update_available: Option<String>,
    forgotten: HashMap<NodeId, Forget>,
    /// Network keys by version; `key_version` is the current one.
    keys: HashMap<u32, [u8; 32]>,
    key_version: u32,
    rotation: Option<(SignedRotation, Rotation)>,
    banned: HashMap<NodeId, String>,
    ssh_allow: Vec<crate::config::SshAllow>,
    ssh_allow_all: Vec<String>,
    /// This node's name (can change at runtime: `meshvpn rename`).
    my_name: String,
    my_tags: Vec<String>,
    inventory: Option<Inventory>,
    /// Measurements towards other nodes (our row of the network matrix).
    perf: HashMap<NodeId, Perf>,
    /// Shared objects we serve completely.
    objects_ad: Vec<ObjectAd>,
    /// Throughput tests: being received (per peer), and waiting for their result.
    bench_rx: HashMap<NodeId, (u64, Instant, u64)>,
    bench_wait: HashMap<u64, tokio::sync::oneshot::Sender<f32>>,
    measure_seen: HashSet<u64>,
    measured: u64,
    udp_paths: HashMap<NodeId, udp::UdpPath>,
    udp_probing: HashMap<NodeId, udp::Probing>,
    /// Our public UDP address(es) as other nodes see them.
    udp_reflexive: Vec<SocketAddr>,
    udp_keys: HashMap<NodeId, [u8; 32]>,
    /// First 8 bytes of node ids, for the compact UDP data format.
    id_prefix: HashMap<[u8; 8], NodeId>,
    my_udp: Vec<String>,
    /// Managed networks (see node/admin.rs).
    roster: Option<(SignedDoc, Roster)>,
    claims: HashMap<NodeId, admin::Admitted>,
    trusted_admins: Vec<NodeId>,
    my_claim: Option<ClaimMsg>,
    leases: Vec<Lease>,
}

pub struct Node {
    cfg: Config,
    dir: PathBuf,
    ident: Identity,
    net: String,
    my_ip: Ipv4Addr,
    io: PacketIo,
    state: Mutex<State>,
    next_link_id: AtomicU64,
    started: Instant,
    socks: Option<String>,
    /// Datasets/checkpoints this node shares (`meshvpn share`).
    pub shares: crate::share::Store,
    /// Direct UDP paths (None: disabled, or no way out over UDP).
    udp: Option<Arc<tokio::net::UdpSocket>>,
    /// The built-in SSH server (see sshserver.rs).
    ssh_cfg: Arc<russh::server::Config>,
    /// Kernel mode: the built-in SSH server listens on the mesh address.
    ssh_listening: std::sync::atomic::AtomicBool,
}

/// A link that finished the handshake and hello exchange and is registered.
struct Established {
    peer: NodeId,
    link_id: u64,
    kill: Arc<Notify>,
    reader: LinkReader,
    writer: LinkWriter,
    rx: mpsc::Receiver<Vec<u8>>,
}

// ---------------------------------------------------------------------------------------------
// Status (shared with the CLI through the control socket)

#[derive(Serialize, Deserialize, Debug)]
pub struct Status {
    pub name: String,
    pub network: String,
    pub id: String,
    pub ip: Ipv4Addr,
    pub interface: String,
    pub endpoints: Vec<String>,
    pub ssh_tunnel: Option<String>,
    pub outbound_via: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub update_available: Option<String>,
    #[serde(default)]
    pub banned: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub inventory: Option<Inventory>,
    #[serde(default)]
    pub lan: Vec<String>,
    #[serde(default)]
    pub perf: Vec<Perf>,
    #[serde(default)]
    pub measured: u64,
    /// Objects this node shares.
    #[serde(default)]
    pub objects: Vec<ObjectAd>,
    #[serde(default)]
    pub leases: Vec<Lease>,
    /// Userspace mode: the SOCKS proxy programs use to reach the mesh.
    #[serde(default)]
    pub socks: Option<String>,
    /// Who answers `ssh user@<this node>.mesh`: "built-in", "sshd" or none.
    #[serde(default)]
    pub ssh_server: Option<String>,
    pub peers: Vec<PeerStatus>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SshSource {
    pub id: NodeId,
    pub name: String,
    pub online: bool,
    /// Users that publish an SSH key.
    pub users: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SshOverview {
    pub hostname: String,
    pub nodes: Vec<SshSource>,
    pub rules: Vec<crate::config::SshAllow>,
    #[serde(default)]
    pub allow_all: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PeerStatus {
    pub name: String,
    pub id: String,
    pub ip: Ipv4Addr,
    pub online: bool,
    pub path: String,
    pub rtt_ms: Option<u64>,
    pub endpoints: Vec<String>,
    pub last_seen_secs: Option<u64>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub inventory: Option<Inventory>,
    #[serde(default)]
    pub objects: Vec<ObjectAd>,
    #[serde(default)]
    pub lan: Vec<String>,
    #[serde(default)]
    pub perf: Vec<Perf>,
    #[serde(default)]
    pub measured: u64,
    #[serde(default)]
    pub leases: Vec<Lease>,
}

// ---------------------------------------------------------------------------------------------

pub async fn run(dir: PathBuf, cfg: Config) -> Result<()> {
    let ident = Identity::from_config(&cfg)?;
    let keys = cfg.all_keys()?;
    let my_ip = overlay_ip(&ident.id);

    // Kernel TUN device if possible; otherwise (containers without /dev/net/tun or NET_ADMIN)
    // a TCP/IP stack in this process.
    let mut tun_dev = None;
    let mut userspace_reason = None;
    if cfg.userspace == Userspace::Always {
        userspace_reason = Some("userspace = \"always\" in the config".to_string());
    } else {
        match create_tun(&cfg, my_ip) {
            Ok(t) => tun_dev = Some(t),
            Err(msg) if cfg.userspace == Userspace::Auto && tun_unavailable(&msg) => userspace_reason = Some(msg),
            Err(msg) => return Err(tun_error(&cfg, &msg)),
        }
    }
    let userspace = tun_dev.is_none();
    let inventory = tokio::task::spawn_blocking(move || crate::inventory::collect(userspace)).await?;
    let (io, start_stack) = match tun_dev {
        Some(t) => (PacketIo::Tun(Arc::new(t)), None),
        None => {
            let (tx, start) = crate::userspace::start(my_ip, OVERLAY_PREFIX, cfg.mtu as usize);
            (PacketIo::Userspace(tx), Some(start))
        }
    };

    let socks = cfg.effective_socks();
    let udp = udp::bind(&cfg).await;
    let ident_for_ssh = Identity::from_config(&cfg)?;
    let node = Arc::new(Node {
        dir: dir.clone(),
        ident,
        net: cfg.network_id(),
        my_ip,
        io,
        state: Mutex::new(State::default()),
        next_link_id: AtomicU64::new(1),
        started: Instant::now(),
        socks,
        shares: crate::share::Store::load(&dir),
        udp,
        ssh_cfg: crate::sshserver::config(&ident_for_ssh),
        ssh_listening: std::sync::atomic::AtomicBool::new(false),
        cfg,
    });

    {
        let saved = SavedState::load(&dir);
        let mut st = node.state.lock().unwrap();
        if let Some(me) = saved.me.and_then(|m| m.verify(&node.net).ok()) {
            st.my_seq = me.seq;
        }
        st.keys = keys;
        st.key_version = node.cfg.key_version;
        st.banned = node.cfg.banned.iter().map(|b| (b.id, b.name.clone())).collect();
        st.my_name = node.cfg.name.clone();
        st.my_tags = node.cfg.tags.clone();
        st.inventory = Some(inventory);
        st.objects_ad = node.shares.ads();
        st.ssh_allow = node.cfg.ssh_allow.clone();
        st.ssh_allow_all = node.cfg.ssh_allow_all.clone();
        st.trusted_admins = node.cfg.trusted_admins.clone();
        st.leases = saved.leases.clone();
        st.my_claim = node.own_claim();
        if let Some(r) = saved.roster.clone() {
            node.apply_roster(&mut st, r);
        }
        for c in saved.claims.clone() {
            if let Err(e) = node.accept_claim(&mut st, c) {
                debug!("dropping saved admission: {e:#}");
            }
        }
        if let Some(r) = saved.rotation
            && let Ok(body) = r.verify(&node.net)
            && body.version == st.key_version
        {
            st.rotation = Some((r, body));
        }
        let cutoff = now_ms().saturating_sub(FORGET_AFTER_MS);
        for f in saved.forgotten.into_iter().filter(|f| f.at > cutoff) {
            node.apply_forget(&mut st, f);
        }
        for s in saved.peers {
            node.ingest(&mut st, s, false);
        }
        node.resign(&mut st);
        node.rebuild(&mut st);
    }

    info!(
        "meshvpn up: {} is {} on {} (network \"{}\", node id {})",
        node.cfg.name, my_ip, node.cfg.interface, node.cfg.network, node.ident.id
    );

    if !node.cfg.ssh_allow.is_empty() || !node.cfg.ssh_allow_all.is_empty() {
        match crate::sshd::enable_if_installed() {
            Ok(true) => info!(
                "enabled password-less SSH logins from mesh nodes in sshd ({})",
                crate::sshd::DROPIN
            ),
            Ok(false) => {}
            Err(e) => warn!("password-less SSH logins are configured but not active: {e:#}"),
        }
    }
    for w in range_conflicts(&node.cfg.interface) {
        warn!("{w}");
    }
    if let Some(listen) = node.cfg.listen.clone() {
        let listener = TcpListener::bind(&listen)
            .await
            .with_context(|| format!("cannot listen on {listen}"))?;
        info!("accepting peers on {listen}");
        tokio::spawn(node.clone().accept_loop(listener));
    }
    if let Some(t) = node.cfg.ssh_tunnel.clone() {
        let port = node.cfg.listen_port().context("ssh_tunnel needs `listen` to be set")?;
        let label = if t.remote_port == 0 {
            format!("ssh tunnel to {}", t.server)
        } else {
            format!("ssh tunnel to {} (public endpoint {})", t.server, t.public_endpoint())
        };
        tokio::spawn(crate::ssh::supervise(label, crate::ssh::tunnel_args(&t, port)));
    }
    if let Some(s) = &node.socks {
        info!("outgoing connections go through SOCKS proxy {s}");
    }
    match (&node.io, start_stack) {
        (PacketIo::Userspace(tx), Some(start)) => {
            if crate::config::rootless() {
                info!(
                    "rootless: userspace mode - mesh connections to this node reach the services listening \
                     here; programs reach the mesh through socks5h://{}",
                    node.cfg.socks_listen
                );
            } else {
                warn!(
                    "no TUN device ({}): running in userspace mode - mesh connections to this node reach \
                     the services listening here; programs reach the mesh through socks5h://{}",
                    userspace_reason.unwrap_or_default(),
                    node.cfg.socks_listen
                );
            }
            start(node.clone());
            tokio::spawn(crate::userspace::socks_server(
                node.clone(),
                tx.clone(),
                node.cfg.socks_listen.clone(),
            ));
            if crate::config::rootless() {
                user_ssh_config(&node.dir, true);
            } else {
                ssh_client_config(true);
            }
        }
        _ => {
            tokio::spawn(node.clone().tun_loop());
            ssh_client_config(false);
        }
    }
    if node.cfg.ssh_server != crate::config::SshServer::Never && matches!(node.io, PacketIo::Tun(_)) {
        tokio::spawn(node.clone().ssh_listen_loop());
    }
    node.ssh_check();
    tokio::spawn(node.clone().tick_loop());
    tokio::spawn(node.clone().update_loop());
    tokio::spawn(node.clone().inventory_loop());
    tokio::spawn(crate::share::serve(node.clone()));
    if node.udp.is_some() {
        tokio::spawn(node.clone().udp_loop());
        let n = node.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                n.udp_probe_round();
            }
        });
    }
    tokio::spawn(crate::control::serve(node.clone(), crate::control::socket_path(&dir)));

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    info!("shutting down");
    node.save_state();
    if node.cfg.manage_hosts
        && let Err(e) = crate::hosts::write(None)
    {
        warn!("cleaning /etc/hosts: {e}");
    }
    std::fs::remove_file(crate::control::socket_path(&dir)).ok();
    Ok(())
}

impl Node {
    // ----------------------------------------------------------------------------- own record

    fn endpoints(&self, st: &State) -> Vec<String> {
        let mut eps = self.cfg.static_endpoints();
        let listen_port = self.cfg.listen_port();
        let listens_publicly = self
            .cfg
            .listen
            .as_ref()
            .and_then(|l| l.parse::<SocketAddr>().ok())
            .is_some_and(|a| !a.ip().is_loopback());
        if self.cfg.auto_endpoints && listens_publicly {
            let port = listen_port.unwrap();
            let mut ips: Vec<IpAddr> = st.observed_ips.clone();
            if let Some(ip) = primary_ip() {
                ips.push(ip);
            }
            for ip in ips {
                eps.push(SocketAddr::new(ip, port).to_string());
            }
        }
        let mut seen = HashSet::new();
        eps.retain(|e| seen.insert(e.clone()));
        eps.truncate(16);
        eps
    }

    fn resign(&self, st: &mut State) {
        let mut neighbors: Vec<NodeId> = st.links.keys().copied().collect();
        neighbors.sort();
        st.my_endpoints = self.endpoints(st);
        st.my_udp = self.udp_candidates(st);
        st.my_seq = now_ms().max(st.my_seq + 1);
        let info = NodeInfo {
            id: self.ident.id,
            noise_pub: self.ident.noise_pub,
            name: st.my_name.clone(),
            endpoints: st.my_endpoints.clone(),
            neighbors,
            seq: st.my_seq,
            net: self.net.clone(),
            version: env!("CARGO_PKG_VERSION").into(),
            tags: st.my_tags.clone(),
            inventory: st.inventory.clone(),
            lan: crate::net::local_lans()
                .into_iter()
                .map(|(_, ip, p)| format!("{ip}/{p}"))
                .take(16)
                .collect(),
            perf: {
                // Bounded, so a record always fits into one link message: closest peers first.
                let mut p: Vec<Perf> = st.perf.values().cloned().collect();
                p.sort_by_key(|x| (x.lan_ip.is_none(), x.rtt_us.unwrap_or(u32::MAX)));
                p.truncate(128);
                p.sort_by_key(|x| x.peer);
                p
            },
            objects: st.objects_ad.clone(),
            udp: st.my_udp.clone(),
            leases: st.leases.clone(),
            ssh_host_key: st.my_ssh_host_key.clone(),
            measured: st.measured,
            ssh_keys: if self.cfg.publish_ssh_keys {
                local_ssh_keys()
            } else {
                vec![]
            },
        };
        st.my_signed = Some(SignedInfo::sign(&info, &self.ident));
    }

    /// Re-sign our record and push it to all neighbors.
    fn announce(&self, st: &mut State) {
        self.resign(st);
        let signed = st.my_signed.clone().unwrap();
        let f = frame(T_GOSSIP, &serde_json::to_vec(&vec![signed]).unwrap());
        self.broadcast(st, &f, None);
    }

    fn broadcast(&self, st: &State, f: &[u8], except: Option<NodeId>) {
        for (id, l) in &st.links {
            if Some(*id) != except {
                let _ = l.tx.try_send(f.to_vec());
            }
        }
    }

    // ----------------------------------------------------------------------------- gossip

    /// Accepts a record if it is valid and newer than what we have. Returns true if it changed.
    fn ingest(&self, st: &mut State, signed: SignedInfo, live: bool) -> bool {
        let info = match signed.verify(&self.net) {
            Ok(i) => i,
            Err(e) => {
                debug!("dropping invalid record: {e}");
                return false;
            }
        };
        if info.id == self.ident.id {
            // An old incarnation of ourselves is still floating around; outrun it.
            if info.seq >= st.my_seq {
                st.my_seq = info.seq + 1;
            }
            return false;
        }
        if let Some(old) = st.records.get(&info.id)
            && old.info.seq >= info.seq
        {
            return false;
        }
        if st.forgotten.get(&info.id).is_some_and(|f| f.seq >= info.seq) {
            return false;
        }
        if st.banned.contains_key(&info.id) {
            return false;
        }
        if !Self::admitted(st, &info.id) {
            return false; // managed network, and this node has no admission (yet)
        }
        if live && info.seq > now_ms() + 3_600_000 {
            debug!("dropping record from the future for {}", info.id);
            return false;
        }
        if !st.records.contains_key(&info.id) {
            info!(
                "discovered node {} ({}) at {}",
                info.name,
                info.id,
                overlay_ip(&info.id)
            );
        }
        st.ciphers.remove(&info.id);
        st.udp_keys.remove(&info.id);
        let id = info.id;
        // A record we see for the first time may be stale (relayed from someone's memory), so
        // it only proves the node is alive once a newer version follows (every REANNOUNCE).
        // Directly linked nodes count as online anyway. This does not depend on clocks.
        let seen_before = st.records.contains_key(&id);
        st.records.insert(
            id,
            Record {
                info,
                signed,
                last_heard: (live && seen_before).then(Instant::now),
            },
        );
        true
    }

    fn handle_gossip(&self, from: NodeId, payload: &[u8]) {
        let Ok(list) = serde_json::from_slice::<Vec<SignedInfo>>(payload) else {
            return;
        };
        let mut st = self.state.lock().unwrap();
        let mut changed = vec![];
        for s in list {
            if self.ingest(&mut st, s.clone(), true) {
                changed.push(s);
            }
        }
        if !changed.is_empty() {
            self.rebuild(&mut st);
            // Flood onwards; the seq check above stops loops.
            for f in gossip_frames(&changed) {
                self.broadcast(&st, &f, Some(from));
            }
            drop(st);
            self.update_hosts();
        }
    }

    fn full_table(&self, st: &State) -> Vec<Vec<u8>> {
        let mut all: Vec<SignedInfo> = st.records.values().map(|r| r.signed.clone()).collect();
        all.extend(st.my_signed.clone());
        // Roster and admissions first: the records of invited nodes depend on them.
        let mut frames = self.admin_frames(st);
        frames.extend(gossip_frames(&all));
        if let Some((r, _)) = &st.rotation {
            frames.insert(0, frame(T_ROTATE, &serde_json::to_vec(r).unwrap()));
        }
        let forgotten: Vec<Forget> = st.forgotten.values().copied().collect();
        for c in forgotten.chunks(256) {
            frames.push(frame(T_FORGET, &serde_json::to_vec(c).unwrap()));
        }
        frames
    }

    // ----------------------------------------------------------------------------- ssh logins

    /// Settings of the built-in SSH server.
    pub fn ssh_config(&self) -> Arc<russh::server::Config> {
        self.ssh_cfg.clone()
    }

    /// Userspace mode: whether the built-in SSH server takes connections to port 22 (decided
    /// per connection: an sshd that starts later takes over).
    pub fn ssh_builtin_userspace(&self) -> bool {
        use crate::config::SshServer;
        match self.cfg.ssh_server {
            SshServer::Always => true,
            SshServer::Auto => !crate::userspace::listening_locally(22),
            SshServer::Never => false,
        }
    }

    /// Who answers port 22 here, published with our record (host key) - checked regularly.
    fn ssh_check(&self) {
        let builtin = match self.io {
            PacketIo::Userspace(_) => self.ssh_builtin_userspace(),
            PacketIo::Tun(_) => self.ssh_listening.load(Ordering::Relaxed),
        };
        let key = if builtin {
            Some(crate::sshserver::host_key_line(&self.ident))
        } else if crate::userspace::listening_locally(22) {
            crate::sshserver::sshd_host_key()
        } else {
            None
        };
        let mut st = self.state.lock().unwrap();
        if st.my_ssh_host_key != key {
            if builtin && st.my_ssh_host_key.is_none() {
                info!(
                    "built-in SSH server active: ssh <user>@{}.mesh (logins as set with meshvpn ssh allow)",
                    st.my_name
                );
            }
            st.my_ssh_host_key = key;
            if st.my_signed.is_some() {
                self.announce(&mut st);
            }
        }
    }

    /// Kernel mode: listen on the mesh address, port 22, if there is no sshd to do it (auto)
    /// or always (if the port is free). Retried, e.g. until the interface has its address.
    async fn ssh_listen_loop(self: Arc<Self>) {
        use crate::config::SshServer;
        let mut warned = false;
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            let wanted = match self.cfg.ssh_server {
                SshServer::Always => true,
                // An sshd starting after us would fail to bind 0.0.0.0:22: never take the port
                // where one is installed.
                _ => !crate::sshserver::sshd_installed() && !crate::userspace::listening_locally(22),
            };
            if wanted {
                match tokio::net::TcpListener::bind((self.my_ip, 22)).await {
                    Ok(l) => {
                        self.ssh_listening.store(true, Ordering::Relaxed);
                        self.ssh_check();
                        crate::sshserver::listen(self.clone(), l).await;
                    }
                    Err(e) if !warned => {
                        let msg = format!("built-in SSH server: cannot listen on {}:22: {e} (retrying)", self.my_ip);
                        if self.cfg.ssh_server == SshServer::Always {
                            warn!("{msg}");
                        } else {
                            info!("{msg}");
                        }
                        warned = true;
                    }
                    Err(_) => {}
                }
            }
            let pause = if attempts < 12 { 5 } else { 30 };
            tokio::time::sleep(Duration::from_secs(pause)).await;
        }
    }

    /// May the key `key` log in as `user`, coming from mesh address `ip`? Same rules as for
    /// sshd (authorized_keys below). Returns `user@node` of the matching key.
    pub fn ssh_login_allowed(&self, user: &str, ip: Ipv4Addr, key: &russh::keys::PublicKey) -> Option<String> {
        let st = self.state.lock().unwrap();
        let everyone = st.ssh_allow_all.iter().any(|u| u == user);
        let rec = st.records.values().find(|r| overlay_ip(&r.info.id) == ip)?;
        if st.banned.contains_key(&rec.info.id) {
            return None;
        }
        let rules: Vec<_> = st
            .ssh_allow
            .iter()
            .filter(|r| r.node == rec.info.id && r.users.iter().any(|u| u == user))
            .collect();
        for k in &rec.info.ssh_keys {
            if !(everyone || rules.iter().any(|r| r.from_user.as_ref().is_none_or(|u| *u == k.user))) {
                continue;
            }
            if let Ok(pk) = russh::keys::PublicKey::from_openssh(&k.key)
                && pk.key_data() == key.key_data()
            {
                return Some(format!("{}@{}", k.user, rec.info.name));
            }
        }
        None
    }

    /// What sshd asks (AuthorizedKeysCommand): keys that may log in as local `user`, each
    /// pinned to its node's mesh IP (which meshvpn guarantees can't be spoofed).
    pub fn authorized_keys(&self, user: &str) -> String {
        let st = self.state.lock().unwrap();
        let everyone = st.ssh_allow_all.iter().any(|u| u == user);
        let mut lines: Vec<String> = vec![];
        for rec in st.records.values() {
            let rules: Vec<_> = st
                .ssh_allow
                .iter()
                .filter(|r| r.node == rec.info.id && r.users.iter().any(|u| u == user))
                .collect();
            let ip = overlay_ip(&rec.info.id);
            for k in &rec.info.ssh_keys {
                if everyone || rules.iter().any(|r| r.from_user.as_ref().is_none_or(|u| *u == k.user)) {
                    let line = format!("from=\"{ip}\" {} meshvpn:{}@{}\n", k.key, k.user, rec.info.name);
                    if !lines.contains(&line) {
                        lines.push(line);
                    }
                }
            }
        }
        lines.concat()
    }

    /// Resolves `[user@]node` to a rule key.
    fn resolve_ssh_source(&self, st: &State, who: &str) -> Result<(NodeId, String, Option<String>)> {
        let (user, node) = match who.split_once('@') {
            Some((u, n)) => (Some(u.to_string()), n),
            None => (None, who),
        };
        if let Some(u) = &user
            && !crate::proto::valid_user(u)
        {
            bail!("invalid user name {u:?}");
        }
        let node = node.trim().to_lowercase();
        let mut matches: Vec<&Record> = st
            .records
            .values()
            .filter(|r| r.info.name == node || (node.len() >= 4 && r.info.id.hex().starts_with(&node)))
            .collect();
        // Same name twice (e.g. a re-installed machine): the online, newest one is meant.
        matches.sort_by_key(|r| (!self.is_online(st, &r.info.id), std::cmp::Reverse(r.info.seq)));
        let Some(rec) = matches.first() else {
            bail!("no node named {node:?} (see meshvpn status)");
        };
        Ok((rec.info.id, rec.info.name.clone(), user))
    }

    fn save_ssh_rules(&self, st: &State) -> Result<()> {
        let mut cfg = Config::load(&self.dir)?;
        cfg.ssh_allow = st.ssh_allow.clone();
        cfg.ssh_allow_all = st.ssh_allow_all.clone();
        cfg.save(&self.dir)
    }

    /// `meshvpn ssh allow [user@]node --as local-user...`
    pub fn ssh_allow(&self, who: &str, users: Vec<String>) -> Result<String> {
        if let Some(u) = users.iter().find(|u| !crate::proto::valid_user(u)) {
            bail!("invalid user name {u:?}");
        }
        let mut st = self.state.lock().unwrap();
        if is_everyone(who) {
            for u in &users {
                if !st.ssh_allow_all.contains(u) {
                    st.ssh_allow_all.push(u.clone());
                }
            }
            self.save_ssh_rules(&st)?;
            return Ok(format!(
                "every node of the network may now log in here as {} without a password \
                 (also nodes that join later)",
                users.join(", ")
            ));
        }
        let (node, name, from_user) = self.resolve_ssh_source(&st, who)?;
        let keys = st.records[&node]
            .info
            .ssh_keys
            .iter()
            .filter(|k| from_user.as_ref().is_none_or(|u| *u == k.user))
            .count();
        match st
            .ssh_allow
            .iter_mut()
            .find(|r| r.node == node && r.from_user == from_user)
        {
            Some(rule) => {
                for u in &users {
                    if !rule.users.contains(u) {
                        rule.users.push(u.clone());
                    }
                }
                rule.name = name.clone();
            }
            None => st.ssh_allow.push(crate::config::SshAllow {
                node,
                name: name.clone(),
                from_user: from_user.clone(),
                users: users.clone(),
            }),
        }
        self.save_ssh_rules(&st)?;
        let src = from_user
            .map(|u| format!("{u}@{name}"))
            .unwrap_or_else(|| format!("any user on {name}"));
        let mut msg = format!("{src} may now log in here as {} without a password", users.join(", "));
        if keys == 0 {
            msg.push_str(&format!(
                "\nnote: {name} publishes no SSH key for that user yet - create one there with `ssh-keygen` \
                 (it is picked up within a minute)"
            ));
        }
        Ok(msg)
    }

    /// `meshvpn ssh deny [user@]node [--as local-user...]` (no users = remove the rule).
    pub fn ssh_deny(&self, who: &str, users: Vec<String>) -> Result<String> {
        let mut st = self.state.lock().unwrap();
        if is_everyone(who) {
            let before = st.ssh_allow_all.len();
            if users.is_empty() {
                st.ssh_allow_all.clear();
            } else {
                st.ssh_allow_all.retain(|u| !users.contains(u));
            }
            if st.ssh_allow_all.len() == before {
                bail!("no rule for everyone (see meshvpn ssh list)");
            }
            self.save_ssh_rules(&st)?;
            return Ok("updated password-less logins for everyone".into());
        }
        let (node, name, from_user) = match self.resolve_ssh_source(&st, who) {
            Ok(r) => r,
            // The node may be gone already: match the rules by name.
            Err(_) => {
                let (u, n) = match who.split_once('@') {
                    Some((u, n)) => (Some(u.to_string()), n.to_string()),
                    None => (None, who.to_string()),
                };
                let rule = st.ssh_allow.iter().find(|r| r.name == n && r.from_user == u);
                let rule = rule.ok_or_else(|| anyhow!("no rule for {who} (see meshvpn ssh list)"))?;
                (rule.node, n, u)
            }
        };
        let before = st.ssh_allow.clone();
        for rule in st
            .ssh_allow
            .iter_mut()
            .filter(|r| r.node == node && r.from_user == from_user)
        {
            if users.is_empty() {
                rule.users.clear();
            } else {
                rule.users.retain(|u| !users.contains(u));
            }
        }
        st.ssh_allow.retain(|r| !r.users.is_empty());
        if st.ssh_allow == before {
            bail!("no rule for {who} (see meshvpn ssh list)");
        }
        self.save_ssh_rules(&st)?;
        Ok(format!("updated password-less logins from {name}"))
    }

    pub fn ssh_list(&self) -> String {
        let st = self.state.lock().unwrap();
        let mut out = String::from("Password-less SSH logins into this machine:\n");
        if !st.ssh_allow_all.is_empty() {
            out.push_str(&format!(
                "  {:<32} -> {}\n",
                "everyone (all nodes)",
                st.ssh_allow_all.join(", ")
            ));
        }
        if st.ssh_allow.is_empty() && st.ssh_allow_all.is_empty() {
            out.push_str("  (none) - allow some with: sudo meshvpn ssh allow [user@]node --as <local user>\n");
        }
        for r in &st.ssh_allow {
            // Rules follow the node, also when it was renamed.
            let name = st.records.get(&r.node).map(|x| &x.info.name).unwrap_or(&r.name);
            let src = r
                .from_user
                .as_ref()
                .map(|u| format!("{u}@{name}"))
                .unwrap_or(format!("{name} (any user)"));
            let gone = if st.records.contains_key(&r.node) {
                ""
            } else {
                "  [node unknown/offline]"
            };
            out.push_str(&format!("  {src:<32} -> {}{gone}\n", r.users.join(", ")));
        }
        out.push_str("\nSSH keys this machine offers to other nodes:\n");
        let keys = if self.cfg.publish_ssh_keys {
            local_ssh_keys()
        } else {
            vec![]
        };
        if keys.is_empty() {
            out.push_str("  (none)\n");
        }
        for k in keys {
            out.push_str(&format!("  {:<16} {}\n", k.user, k.key.split(' ').next().unwrap_or("")));
        }
        out
    }

    /// Everything the SSH permission editor needs.
    pub fn ssh_overview(&self) -> SshOverview {
        let st = self.state.lock().unwrap();
        let mut nodes: Vec<SshSource> = st
            .records
            .values()
            .map(|r| {
                let mut users: Vec<String> = r.info.ssh_keys.iter().map(|k| k.user.clone()).collect();
                users.dedup();
                SshSource {
                    id: r.info.id,
                    name: r.info.name.clone(),
                    online: self.is_online(&st, &r.info.id),
                    users,
                }
            })
            .collect();
        nodes.sort_by(|a, b| b.online.cmp(&a.online).then(a.name.cmp(&b.name)));
        SshOverview {
            hostname: st.my_name.clone(),
            nodes,
            rules: st.ssh_allow.clone(),
            allow_all: st.ssh_allow_all.clone(),
        }
    }

    /// Replaces all rules (the permission editor saves everything at once).
    pub fn ssh_set_rules(&self, rules: Vec<crate::config::SshAllow>, allow_all: Vec<String>) -> Result<()> {
        for r in &rules {
            if r.users.iter().chain(&r.from_user).any(|u| !crate::proto::valid_user(u)) {
                bail!("invalid user name in rule for {}", r.name);
            }
        }
        if allow_all.iter().any(|u| !crate::proto::valid_user(u)) {
            bail!("invalid user name in the rule for everyone");
        }
        let mut st = self.state.lock().unwrap();
        st.ssh_allow_all = allow_all;
        st.ssh_allow = rules.into_iter().filter(|r| !r.users.is_empty()).collect();
        self.save_ssh_rules(&st)
    }

    // ----------------------------------------------------------------------------- banning

    /// Drops a banned node: its record, its link and its address.
    fn ban_local(&self, st: &mut State, id: NodeId, name: &str) {
        if id == self.ident.id || st.banned.contains_key(&id) {
            return;
        }
        st.banned.insert(id, name.to_string());
        st.records.remove(&id);
        st.ciphers.remove(&id);
        if let Some(l) = st.links.remove(&id) {
            l.kill.notify_one();
        }
        warn!("banned node {name} ({id})");
    }

    /// Accepts a (newer) rotation: applies its bans and unseals our copy of the new key.
    fn apply_rotation(&self, st: &mut State, signed: SignedRotation) -> bool {
        let r = match signed.verify(&self.net) {
            Ok(r) => r,
            Err(e) => {
                debug!("dropping key rotation: {e}");
                return false;
            }
        };
        if st.banned.contains_key(&r.issuer) || !Self::is_admin(st, &r.issuer) {
            return false; // in managed networks only admins ban
        }
        let current = st.rotation.as_ref().map(|(_, c)| (c.version, c.issuer));
        let newer =
            r.version > st.key_version || (r.version == st.key_version && current < Some((r.version, r.issuer)));
        if !newer {
            return false;
        }
        for (id, name) in &r.banned {
            if *id == self.ident.id {
                warn!("this node was banned from the network");
            }
            self.ban_local(st, *id, name);
        }
        if r.issuer != self.ident.id {
            let Some(env) = r.envelopes.iter().find(|e| e.to == self.ident.id) else {
                warn!("the network key was changed and this node did not get the new one (banned?)");
                return true;
            };
            match self.unseal(&r, env) {
                Some(key) => {
                    st.keys.insert(r.version, key);
                    st.key_version = r.version;
                    info!("network key changed to version {} (after a ban)", r.version);
                }
                None => {
                    warn!("could not open the new network key");
                    return true;
                }
            }
        }
        st.rotation = Some((signed, r));
        self.save_keys(st);
        self.rebuild(st);
        true
    }

    fn unseal(&self, r: &Rotation, env: &Envelope) -> Option<[u8; 32]> {
        let key = self.ident.envelope_key(&r.issuer_noise, r.version);
        let nonce: [u8; 24] = crate::keys::unb64(&env.nonce).ok()?.try_into().ok()?;
        let sealed = crate::keys::unb64(&env.sealed).ok()?;
        let plain = XChaCha20Poly1305::new(&key.into())
            .decrypt(&XNonce::from(nonce), sealed.as_slice())
            .ok()?;
        plain.try_into().ok()
    }

    /// Persists keys and bans, so they survive restarts and new invites carry the new key.
    fn save_keys(&self, st: &State) {
        let res = (|| -> Result<()> {
            let mut cfg = Config::load(&self.dir)?;
            if cfg.network_id.is_empty() {
                cfg.network_id = self.net.clone();
            }
            let current = st.keys.get(&st.key_version).context("current key missing")?;
            cfg.network_key = crate::keys::b64(current);
            cfg.key_version = st.key_version;
            let mut old: Vec<_> = st.keys.iter().filter(|(v, _)| **v != st.key_version).collect();
            old.sort_by_key(|(v, _)| **v);
            cfg.old_keys = old
                .into_iter()
                .map(|(v, k)| crate::config::OldKey {
                    version: *v,
                    key: crate::keys::b64(k),
                })
                .collect();
            cfg.banned = st
                .banned
                .iter()
                .map(|(id, name)| crate::config::BannedNode {
                    id: *id,
                    name: name.clone(),
                })
                .collect();
            cfg.save(&self.dir)
        })();
        if let Err(e) = res {
            warn!("saving the new network key: {e:#}");
        }
    }

    fn handle_rotation(&self, from: NodeId, payload: &[u8]) {
        let Ok(signed) = serde_json::from_slice::<SignedRotation>(payload) else {
            return;
        };
        let mut st = self.state.lock().unwrap();
        if self.apply_rotation(&mut st, signed.clone()) {
            self.broadcast(&st, &frame(T_ROTATE, &serde_json::to_vec(&signed).unwrap()), Some(from));
            drop(st);
            self.save_state();
            self.update_hosts();
        }
    }

    /// `meshvpn ban NAME|ID`: bans the node everywhere and gives everyone else a new key.
    pub fn ban(&self, who: &str) -> Result<String> {
        let mut st = self.state.lock().unwrap();
        if !Self::is_admin(&st, &self.ident.id) {
            bail!("only admins can ban in this managed network (see meshvpn admin status)");
        }
        let w = who.trim().to_lowercase();
        if w == st.my_name || (w.len() >= 4 && self.ident.id.hex().starts_with(&w)) {
            bail!("{w} is this node");
        }
        let targets: Vec<(NodeId, String)> = st
            .records
            .values()
            .filter(|r| r.info.name == w || (w.len() >= 4 && r.info.id.hex().starts_with(&w)))
            .map(|r| (r.info.id, r.info.name.clone()))
            .collect();
        if targets.is_empty() {
            bail!("no node named {w:?} (see meshvpn status)");
        }
        for (id, name) in &targets {
            self.ban_local(&mut st, *id, name);
        }

        let version = st.key_version + 1;
        let new_key = crate::keys::random32();
        let envelopes: Vec<Envelope> = st
            .records
            .values()
            .map(|r| {
                let key = self.ident.envelope_key(&r.info.noise_pub, version);
                let mut nonce = [0u8; 24];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                let sealed = XChaCha20Poly1305::new(&key.into())
                    .encrypt(&XNonce::from(nonce), new_key.as_slice())
                    .expect("sealing");
                Envelope {
                    to: r.info.id,
                    nonce: crate::keys::b64(&nonce),
                    sealed: crate::keys::b64(&sealed),
                }
            })
            .collect();
        let members = envelopes.len();
        let rotation = Rotation {
            net: self.net.clone(),
            version,
            issuer: self.ident.id,
            issuer_noise: self.ident.noise_pub,
            banned: st.banned.iter().map(|(id, n)| (*id, n.clone())).collect(),
            envelopes,
            at: now_ms(),
        };
        let signed = SignedRotation::sign(&rotation, &self.ident);
        st.keys.insert(version, new_key);
        st.key_version = version;
        st.rotation = Some((signed.clone(), rotation));
        self.save_keys(&st);
        self.rebuild(&mut st);
        self.broadcast(&st, &frame(T_ROTATE, &serde_json::to_vec(&signed).unwrap()), None);
        drop(st);
        self.save_state();
        self.update_hosts();
        let names: Vec<_> = targets.into_iter().map(|(_, n)| n).collect();
        Ok(format!(
            "banned {}. The network key was changed and sent to the other {members} member(s); \
             members that are offline now get it when they reconnect. Old invites no longer work - \
             create new ones with `meshvpn invite`.",
            names.join(", ")
        ))
    }

    // ----------------------------------------------------------------------------- forgetting

    /// Records a tombstone and drops the node if we only know that version or older.
    fn apply_forget(&self, st: &mut State, f: Forget) -> bool {
        if f.id == self.ident.id || st.forgotten.get(&f.id).is_some_and(|old| old.seq >= f.seq) {
            return false;
        }
        st.forgotten.insert(f.id, f);
        if st.records.get(&f.id).is_some_and(|r| r.info.seq <= f.seq) && !st.links.contains_key(&f.id) {
            let r = st.records.remove(&f.id).unwrap();
            st.ciphers.remove(&f.id);
            info!("forgot node {} ({})", r.info.name, f.id);
        }
        true
    }

    fn handle_forget(&self, from: NodeId, payload: &[u8]) {
        let Ok(list) = serde_json::from_slice::<Vec<Forget>>(payload) else {
            return;
        };
        let mut st = self.state.lock().unwrap();
        let changed: Vec<Forget> = list.into_iter().filter(|f| self.apply_forget(&mut st, *f)).collect();
        if !changed.is_empty() {
            self.rebuild(&mut st);
            self.broadcast(
                &st,
                &frame(T_FORGET, &serde_json::to_vec(&changed).unwrap()),
                Some(from),
            );
            drop(st);
            self.update_hosts();
        }
    }

    /// Forgets offline nodes everywhere in the network. Returns their names.
    fn forget_ids(&self, st: &mut State, ids: &[NodeId]) -> Vec<String> {
        let mut names = vec![];
        let mut sent = vec![];
        for id in ids {
            let Some(r) = st.records.get(id) else { continue };
            let f = Forget {
                id: *id,
                seq: r.info.seq,
                at: now_ms(),
            };
            names.push(r.info.name.clone());
            if self.apply_forget(st, f) {
                sent.push(f);
            }
        }
        if !sent.is_empty() {
            self.rebuild(st);
            self.broadcast(st, &frame(T_FORGET, &serde_json::to_vec(&sent).unwrap()), None);
        }
        names
    }

    /// How long a node has been offline (None = online).
    fn offline_for(&self, st: &State, id: &NodeId) -> Option<Duration> {
        if self.is_online(st, id) {
            return None;
        }
        let heard = st.records.get(id)?.last_heard.map(|t| t.elapsed());
        Some(heard.unwrap_or(self.started.elapsed()).saturating_sub(ONLINE_WINDOW))
    }

    /// `meshvpn forget NAME|ID` or `meshvpn forget --offline`.
    pub fn forget(&self, who: Option<&str>) -> Result<String> {
        let mut st = self.state.lock().unwrap();
        let ids: Vec<NodeId> = match who {
            None => st
                .records
                .keys()
                .copied()
                .filter(|id| !self.is_online(&st, id))
                .collect(),
            Some(w) => {
                let w = w.trim().to_lowercase();
                let matches: Vec<NodeId> = st
                    .records
                    .values()
                    .filter(|r| r.info.name == w || (w.len() >= 4 && r.info.id.hex().starts_with(&w)))
                    .map(|r| r.info.id)
                    .collect();
                if matches.is_empty() && w == st.my_name {
                    bail!("{w} is this node");
                }
                if matches.is_empty() {
                    bail!("no node named {w:?} (see meshvpn status)");
                }
                let offline: Vec<NodeId> = matches.iter().copied().filter(|id| !self.is_online(&st, id)).collect();
                if offline.is_empty() {
                    bail!("{w} is online - it would come right back (stop meshvpn on it first)");
                }
                offline
            }
        };
        let names = self.forget_ids(&mut st, &ids);
        drop(st);
        self.update_hosts();
        Ok(match names.len() {
            0 => "no offline nodes to forget".into(),
            _ => format!("forgot {} (on every node of the network)", names.join(", ")),
        })
    }

    /// A machine that was set up again leaves its old identity behind under the same name.
    fn auto_forget(&self, st: &mut State) {
        let me = st.my_name.clone();
        let mut newest: HashMap<&str, u64> = HashMap::new();
        newest.insert(&me, u64::MAX);
        for r in st.records.values() {
            if self.is_online(st, &r.info.id) {
                let e = newest.entry(&r.info.name).or_default();
                *e = (*e).max(r.info.seq);
            }
        }
        let stale: Vec<NodeId> = st
            .records
            .values()
            .filter(|r| newest.get(r.info.name.as_str()).is_some_and(|&s| s > r.info.seq))
            .filter(|r| self.offline_for(st, &r.info.id).is_some_and(|d| d > AUTO_FORGET_AFTER))
            .map(|r| r.info.id)
            .collect();
        if !stale.is_empty() {
            let names = self.forget_ids(st, &stale);
            info!("forgot replaced node(s): {}", names.join(", "));
        }
    }

    fn is_online(&self, st: &State, id: &NodeId) -> bool {
        st.links.contains_key(id)
            || st
                .udp_paths
                .get(id)
                .is_some_and(|p| p.last_rx.elapsed() < udp::PATH_TIMEOUT)
            || st
                .records
                .get(id)
                .and_then(|r| r.last_heard)
                .is_some_and(|t| t.elapsed() < ONLINE_WINDOW)
    }

    /// Rebuilds the IP map and the routing table.
    fn rebuild(&self, st: &mut State) {
        let mut ids: Vec<&NodeId> = st.records.keys().collect();
        ids.sort();
        let mut ip_map = HashMap::new();
        for id in ids {
            let ip = overlay_ip(id);
            if ip != self.my_ip {
                ip_map.entry(ip).or_insert(*id);
            }
        }
        st.ip_map = ip_map;
        st.id_prefix = st
            .records
            .keys()
            .map(|id| (id.0[..8].try_into().unwrap(), *id))
            .collect();

        // Breadth-first search over the neighbor lists of online nodes.
        let mut routes: HashMap<NodeId, NodeId> = HashMap::new();
        let mut queue = VecDeque::new();
        for n in st.links.keys() {
            routes.insert(*n, *n);
            queue.push_back(*n);
        }
        while let Some(cur) = queue.pop_front() {
            let first = routes[&cur];
            let Some(rec) = st.records.get(&cur) else { continue };
            if !self.is_online(st, &cur) {
                continue;
            }
            for nb in &rec.info.neighbors {
                if *nb != self.ident.id && !routes.contains_key(nb) {
                    routes.insert(*nb, first);
                    queue.push_back(*nb);
                }
            }
        }
        st.routes = routes;
    }

    // ----------------------------------------------------------------------------- data path

    fn cipher_for(&self, st: &mut State, peer: &NodeId) -> Option<XChaCha20Poly1305> {
        if let Some(c) = st.ciphers.get(peer) {
            return Some(c.clone());
        }
        let rec = st.records.get(peer)?;
        let key = self.ident.e2e_key(&rec.info.noise_pub, &self.net);
        let c = XChaCha20Poly1305::new(&key.into());
        st.ciphers.insert(*peer, c.clone());
        Some(c)
    }

    /// Encrypts an IP packet end-to-end for `dst` and hands it to the first hop.
    pub(crate) fn send_packet(&self, dst_ip: Ipv4Addr, pkt: &[u8]) {
        // Straight over UDP if there is a direct path.
        let direct = {
            let mut st = self.state.lock().unwrap();
            let Some(&dst) = st.ip_map.get(&dst_ip) else { return };
            st.udp_paths
                .get(&dst)
                .is_some_and(|p| p.usable())
                .then(|| self.cipher_for(&mut st, &dst).map(|c| (dst, c)))
                .flatten()
        };
        if let Some((dst, cipher)) = direct
            && self.udp_send(&dst, &cipher, pkt)
        {
            return;
        }
        let (dst, tx, cipher) = {
            let mut st = self.state.lock().unwrap();
            let Some(&dst) = st.ip_map.get(&dst_ip) else { return };
            let Some(hop) = st.routes.get(&dst).copied() else {
                return;
            };
            let Some(tx) = st.links.get(&hop).map(|l| l.tx.clone()) else {
                return;
            };
            let Some(cipher) = self.cipher_for(&mut st, &dst) else {
                return;
            };
            (dst, tx, cipher)
        };
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let Ok(ct) = cipher.encrypt(&XNonce::from(nonce), pkt) else {
            return;
        };
        let mut f = Vec::with_capacity(1 + DATA_HDR + ct.len());
        f.push(T_DATA);
        f.extend_from_slice(&dst.0);
        f.extend_from_slice(&self.ident.id.0);
        f.push(DEFAULT_TTL);
        f.extend_from_slice(&nonce);
        f.extend_from_slice(&ct);
        let _ = tx.try_send(f); // drop on congestion, like a real network
    }

    /// Handles a data frame: returns the IP packet if it is for us, otherwise relays it.
    fn handle_data(&self, mut f: Vec<u8>) -> Option<Vec<u8>> {
        if f.len() < 1 + DATA_HDR {
            return None;
        }
        let dst = NodeId::from_slice(&f[1..33]).ok()?;
        let src = NodeId::from_slice(&f[33..65]).ok()?;
        if dst != self.ident.id {
            // Relay for others. Contents are end-to-end encrypted; we can't read them.
            let ttl = f[65];
            if ttl <= 1 {
                return None;
            }
            f[65] = ttl - 1;
            let st = self.state.lock().unwrap();
            let hop = st.routes.get(&dst)?;
            let _ = st.links.get(hop)?.tx.try_send(f);
            return None;
        }
        let cipher = {
            let mut st = self.state.lock().unwrap();
            self.cipher_for(&mut st, &src)?
        };
        let nonce: [u8; 24] = f[66..90].try_into().ok()?;
        let pkt = cipher.decrypt(&XNonce::from(nonce), &f[1 + DATA_HDR..]).ok()?;
        // Anti-spoofing: the inner source address must belong to the sender.
        if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[12..16] != overlay_ip(&src).octets() {
            return None;
        }
        Some(pkt)
    }

    /// Hands an IP packet for this node to the kernel or the userspace stack.
    async fn deliver(&self, pkt: Vec<u8>) {
        match &self.io {
            PacketIo::Tun(tun) => {
                let _ = tun.send(&pkt).await;
            }
            PacketIo::Userspace(tx) => {
                let _ = tx.send(crate::userspace::Cmd::Packet(pkt));
            }
        }
    }

    pub fn my_ip(&self) -> Ipv4Addr {
        self.my_ip
    }

    /// Mesh address of `host` (`name`, `name.mesh` or a mesh IP); None if it isn't in the mesh.
    pub fn resolve(&self, host: &str) -> Option<Ipv4Addr> {
        let h = host.trim_end_matches('.').to_lowercase();
        let h = h.strip_suffix(".mesh").unwrap_or(&h);
        if let Ok(ip) = h.parse::<Ipv4Addr>() {
            return is_overlay(IpAddr::V4(ip)).then_some(ip);
        }
        let st = self.state.lock().unwrap();
        if h == st.my_name {
            return Some(self.my_ip);
        }
        let mut matches: Vec<&Record> = st.records.values().filter(|r| r.info.name == h).collect();
        matches.sort_by_key(|r| (!self.is_online(&st, &r.info.id), std::cmp::Reverse(r.info.seq)));
        matches.first().map(|r| overlay_ip(&r.info.id))
    }

    async fn tun_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 65536];
        loop {
            let PacketIo::Tun(tun) = &self.io else { return };
            let n = match tun.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    warn!("reading from {}: {e}", self.cfg.interface);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let pkt = &buf[..n];
            if n < 20 || pkt[0] >> 4 != 4 {
                continue; // IPv4 only
            }
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            self.send_packet(dst, pkt);
        }
    }

    // ----------------------------------------------------------------------------- links

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let node = self.clone();
                    tokio::spawn(async move {
                        match node.establish(stream, false, addr.to_string()).await {
                            Ok(est) => node.serve(est).await,
                            Err(e)
                                if ["banned", "outdated network key", "not admitted"]
                                    .iter()
                                    .any(|k| e.to_string().contains(k)) =>
                            {
                                warn!("rejected connection from {addr}: {e:#}")
                            }
                            Err(e) => debug!("incoming connection from {addr}: {e:#}"),
                        }
                    });
                }
                Err(e) => {
                    warn!("accept: {e}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    async fn connect(&self, addr: &str) -> Result<TcpStream> {
        let fut = async {
            match &self.socks {
                Some(proxy) => link::socks5_connect(proxy, addr).await,
                None => {
                    // Never run a link through the mesh itself: a name like `hub` may resolve to
                    // a mesh address via the /etc/hosts entries meshvpn maintains.
                    let targets: Vec<SocketAddr> = tokio::net::lookup_host(addr)
                        .await?
                        .filter(|a| !is_overlay(a.ip()))
                        .collect();
                    if targets.is_empty() {
                        bail!("{addr} only resolves to mesh addresses");
                    }
                    Ok(TcpStream::connect(&targets[..]).await?)
                }
            }
        };
        timeout(CONNECT_TIMEOUT, fut).await.map_err(|_| anyhow!("timed out"))?
    }

    /// Handshake + hello exchange + registration.
    async fn establish(self: &Arc<Self>, mut stream: TcpStream, initiator: bool, addr: String) -> Result<Established> {
        stream.set_nodelay(true).ok();
        let observed = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        let (my_version, keys) = {
            let st = self.state.lock().unwrap();
            (st.key_version, st.keys.clone())
        };
        let (transport, remote_static, version) = timeout(
            HANDSHAKE_TIMEOUT,
            link::handshake(&mut stream, initiator, &self.ident.noise_secret, my_version, &keys),
        )
        .await
        .map_err(|_| anyhow!("handshake timed out"))??;
        let cipher = Cipher::new(transport);
        let (r, w) = stream.into_split();
        let mut reader = LinkReader::new(r, cipher.clone());
        let mut writer = LinkWriter::new(w, cipher);

        let my_signed = self.state.lock().unwrap().my_signed.clone().unwrap();
        let my_nonce = rand::rngs::OsRng.next_u64();
        let my_claim = self.state.lock().unwrap().my_claim.clone();
        let hello = Hello {
            info: my_signed,
            observed,
            nonce: my_nonce,
            claim: my_claim,
        };
        writer.send(&frame(T_HELLO, &serde_json::to_vec(&hello)?)).await?;
        let msg = timeout(HANDSHAKE_TIMEOUT, reader.recv())
            .await
            .map_err(|_| anyhow!("hello timed out"))??;
        if msg.first() != Some(&T_HELLO) {
            bail!("expected hello");
        }
        let hello: Hello = serde_json::from_slice(&msg[1..])?;
        let info = hello.info.verify(&self.net)?;
        if info.noise_pub != remote_static {
            bail!("record does not match link key");
        }
        let peer = info.id;
        if peer == self.ident.id {
            bail!("connected to myself");
        }
        {
            let mut st = self.state.lock().unwrap();
            if st.banned.contains_key(&peer) {
                bail!("{} ({peer}) is banned", info.name);
            }
            // Managed network: the network key is not enough, the node needs an admission.
            if !Self::admitted(&st, &peer) {
                let Some(c) = hello.claim.clone() else {
                    bail!(
                        "{} ({peer}) is not admitted to this managed network (it needs an invite from an \
                         admin: meshvpn invite on an admin node)",
                        info.name
                    );
                };
                match self.accept_claim(&mut st, c) {
                    Ok(Some(m)) => self.broadcast(&st, &frame(T_CLAIM, &serde_json::to_vec(&m).unwrap()), None),
                    Ok(None) => {}
                    Err(e) => bail!("{} ({peer}) is not admitted: {e:#}", info.name),
                }
            }
            // An old network key is only good for members that got the new one sealed for
            // them; they receive it right after connecting.
            if version < st.key_version
                && !st
                    .rotation
                    .as_ref()
                    .is_some_and(|(_, r)| r.envelopes.iter().any(|e| e.to == peer))
            {
                bail!(
                    "{} ({peer}) uses an outdated network key and was not a member when it changed \
                     (banned, or it joined with an old invite - give it a new one)",
                    info.name
                );
            }
        }

        let (tx, rx) = mpsc::channel(1024);
        let link_id = self.next_link_id.fetch_add(1, Ordering::Relaxed);
        let kill = Arc::new(Notify::new());
        // Only one link per pair. When connections race, both ends keep the one with the
        // lowest rank: prefer links opened by the smaller id, then the lower nonce.
        let initiator_id = if initiator { self.ident.id } else { peer };
        let rank = (initiator_id != self.ident.id.min(peer), my_nonce ^ hello.nonce);
        {
            let mut st = self.state.lock().unwrap();
            if let Some(existing) = st.links.get(&peer) {
                if existing.rank <= rank {
                    bail!("duplicate link");
                }
                existing.kill.notify_one();
            }
            let entry = LinkEntry {
                link_id,
                tx,
                rank,
                kill: kill.clone(),
                addr: addr.clone(),
                rtt: None,
            };
            st.links.insert(peer, entry);
            self.ingest(&mut st, hello.info.clone(), true);
            if let Ok(obs) = hello.observed.parse::<SocketAddr>() {
                let ip = obs.ip();
                if !ip.is_loopback() && !ip.is_unspecified() && !is_overlay(ip) && !st.observed_ips.contains(&ip) {
                    st.observed_ips.insert(0, ip);
                    st.observed_ips.truncate(3);
                }
            }
            self.announce(&mut st);
            self.rebuild(&mut st);
            // Tell the new neighbor everything we know.
            let link = st.links.get(&peer).unwrap();
            for f in self.full_table(&st) {
                let _ = link.tx.try_send(f);
            }
        }
        info!("link up: {} ({}) via {}", info.name, peer, addr);
        Ok(Established {
            peer,
            link_id,
            kill,
            reader,
            writer,
            rx,
        })
    }

    async fn serve(self: Arc<Self>, est: Established) {
        let Established {
            peer,
            link_id,
            kill,
            mut reader,
            mut writer,
            mut rx,
        } = est;
        let writer_task = tokio::spawn(async move {
            while let Some(f) = rx.recv().await {
                if writer.send(&f).await.is_err() {
                    break;
                }
            }
        });
        let reason = loop {
            let msg = tokio::select! {
                r = timeout(LINK_TIMEOUT, reader.recv()) => match r {
                    Err(_) => break "timeout".to_string(),
                    Ok(Err(e)) => break e.to_string(),
                    Ok(Ok(m)) => m,
                },
                _ = kill.notified() => break "replaced by a better connection".to_string(),
            };
            let Some((&kind, payload)) = msg.split_first() else {
                continue;
            };
            match kind {
                T_DATA => {
                    if let Some(pkt) = self.handle_data(msg) {
                        self.deliver(pkt).await;
                    }
                }
                T_GOSSIP => self.handle_gossip(peer, payload),
                T_FORGET => self.handle_forget(peer, payload),
                T_MEASURE => self.handle_measure(peer, payload),
                T_ROSTER | T_CLAIM => {
                    self.dispatch_admin(kind, peer, payload);
                }
                T_BENCH_START => {
                    if let Ok(m) = serde_json::from_slice::<BenchMsg>(payload) {
                        self.state
                            .lock()
                            .unwrap()
                            .bench_rx
                            .insert(peer, (m.id, Instant::now(), 0));
                    }
                }
                T_BENCH_DATA => {
                    if let Some(b) = self.state.lock().unwrap().bench_rx.get_mut(&peer) {
                        b.2 += payload.len() as u64;
                    }
                }
                T_BENCH_END => {
                    let mut st = self.state.lock().unwrap();
                    if let Some((id, started, bytes)) = st.bench_rx.remove(&peer) {
                        let secs = started.elapsed().as_secs_f64().max(1e-6);
                        let mbps = (bytes as f64 * 8.0 / secs / 1e6) as f32;
                        if let Some(l) = st.links.get(&peer) {
                            let _ = l.tx.try_send(frame(
                                T_BENCH_RESULT,
                                &serde_json::to_vec(&BenchMsg { id, mbps }).unwrap(),
                            ));
                        }
                    }
                }
                T_BENCH_RESULT => {
                    if let Ok(m) = serde_json::from_slice::<BenchMsg>(payload)
                        && let Some(w) = self.state.lock().unwrap().bench_wait.remove(&m.id)
                    {
                        let _ = w.send(m.mbps);
                    }
                }
                T_ROTATE => self.handle_rotation(peer, payload),
                T_PING => {
                    let st = self.state.lock().unwrap();
                    if let Some(l) = st.links.get(&peer) {
                        let _ = l.tx.try_send(frame(T_PONG, payload));
                    }
                }
                T_PONG => {
                    if let Ok(b) = <[u8; 8]>::try_from(payload) {
                        let sent = Duration::from_micros(u64::from_be_bytes(b));
                        let rtt = self.started.elapsed().saturating_sub(sent);
                        let mut st = self.state.lock().unwrap();
                        if let Some(l) = st.links.get_mut(&peer)
                            && l.link_id == link_id
                        {
                            l.rtt = Some(rtt);
                        }
                    }
                }
                _ => {}
            }
        };
        writer_task.abort();
        let mut st = self.state.lock().unwrap();
        if st.links.get(&peer).is_some_and(|l| l.link_id == link_id) {
            st.links.remove(&peer);
            let name = st.records.get(&peer).map(|r| r.info.name.clone()).unwrap_or_default();
            info!("link down: {name} ({peer}): {reason}");
            self.announce(&mut st);
            self.rebuild(&mut st);
            drop(st);
            // Try to get it back right away instead of waiting for the next tick.
            let node = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                node.dial_now();
            });
        }
    }

    // ----------------------------------------------------------------------------- dialing

    fn dial_candidates(&self, st: &mut State) -> Vec<(String, Vec<String>, Option<String>)> {
        let mut out = vec![];
        if self.cfg.no_outbound {
            return out;
        }
        let now = Instant::now();
        let ready =
            |st: &State, key: &str| !st.dialing.contains(key) && st.backoff.get(key).is_none_or(|b| b.next <= now);
        for (id, rec) in &st.records {
            let key = id.hex();
            if st.links.contains_key(id) || rec.info.endpoints.is_empty() || !ready(st, &key) {
                continue;
            }
            out.push((key, rec.info.endpoints.clone(), None));
        }
        let boots: Vec<String> = self.cfg.bootstrap.iter().chain(&st.extra_bootstrap).cloned().collect();
        let known: HashSet<&String> = st.records.values().flat_map(|r| &r.info.endpoints).collect();
        for addr in boots {
            let key = format!("boot:{addr}");
            // Addresses of nodes we already know are dialed through their record instead.
            if known.contains(&addr) {
                continue;
            }
            if let Some(id) = st.bootstrap_ids.get(&addr)
                && (*id == self.ident.id || st.links.contains_key(id))
            {
                continue;
            }
            if ready(st, &key) {
                out.push((key, vec![addr.clone()], Some(addr)));
            }
        }
        for (key, _, _) in &out {
            st.dialing.insert(key.clone());
        }
        out
    }

    async fn dial(self: Arc<Self>, key: String, addrs: Vec<String>, bootstrap: Option<String>) {
        let mut last_err = None;
        for addr in &addrs {
            let res = match self.connect(addr).await {
                Ok(stream) => self.establish(stream, true, addr.clone()).await,
                Err(e) => Err(e),
            };
            match res {
                Ok(est) => {
                    {
                        let mut st = self.state.lock().unwrap();
                        st.dialing.remove(&key);
                        st.backoff.remove(&key);
                        if let Some(b) = &bootstrap {
                            st.bootstrap_ids.insert(b.clone(), est.peer);
                        }
                    }
                    self.serve(est).await;
                    return;
                }
                Err(e) => {
                    if e.to_string().contains("myself")
                        && let Some(b) = &bootstrap
                    {
                        let mut st = self.state.lock().unwrap();
                        st.bootstrap_ids.insert(b.clone(), self.ident.id);
                    }
                    debug!("dial {addr}: {e:#}");
                    last_err = Some(e);
                }
            }
        }
        let mut st = self.state.lock().unwrap();
        st.dialing.remove(&key);
        let b = st.backoff.entry(key.clone()).or_insert(Backoff {
            next: Instant::now(),
            delay: Duration::from_secs(5),
        });
        b.next = Instant::now() + b.delay;
        let retry = b.delay.as_secs();
        b.delay = (b.delay * 2).min(MAX_BACKOFF);
        if let Some(e) = last_err {
            let msg = format!("cannot reach {}: {e:#} (retrying in {retry}s)", addrs.join(", "));
            // Once we are part of the mesh, unreachable addresses are normal (NAT, firewalls).
            if st.links.is_empty() {
                warn!("{msg}")
            } else {
                debug!("{msg}")
            }
        }
    }

    // ----------------------------------------------------------------------------- periodic

    async fn tick_loop(self: Arc<Self>) {
        let mut last_announce = Instant::now();
        let mut ticks: u64 = 0;
        loop {
            let dials = {
                let mut st = self.state.lock().unwrap();
                let ping = frame(T_PING, &(self.started.elapsed().as_micros() as u64).to_be_bytes());
                self.broadcast(&st, &ping, None);
                if last_announce.elapsed() >= REANNOUNCE
                    || self.endpoints(&st) != st.my_endpoints
                    || self.udp_candidates(&st) != st.my_udp
                {
                    self.announce(&mut st);
                    last_announce = Instant::now();
                }
                // Forget nodes that have been gone for a long time.
                let cutoff = now_ms().saturating_sub(FORGET_AFTER_MS);
                let links = &st.links;
                let before = st.records.len();
                let stale: Vec<NodeId> = st
                    .records
                    .iter()
                    .filter(|(id, r)| r.info.seq < cutoff && !links.contains_key(*id))
                    .map(|(id, _)| *id)
                    .collect();
                for id in stale {
                    st.records.remove(&id);
                }
                if st.records.len() != before {
                    info!("forgot {} long-gone node(s)", before - st.records.len());
                }
                st.forgotten.retain(|_, f| f.at > cutoff);
                self.expire_leases(&mut st);
                self.auto_forget(&mut st);
                self.rebuild(&mut st);
                self.dial_candidates(&mut st)
            };
            for (key, addrs, boot) in dials {
                tokio::spawn(self.clone().dial(key, addrs, boot));
            }
            if ticks.is_multiple_of(6) {
                self.ssh_check();
            }
            self.update_hosts();
            if ticks.is_multiple_of(6) {
                self.save_state();
            }
            ticks += 1;
            tokio::time::sleep(TICK).await;
        }
    }

    fn save_state(&self) {
        let st = self.state.lock().unwrap();
        let saved = SavedState {
            me: st.my_signed.clone(),
            peers: st.records.values().map(|r| r.signed.clone()).collect(),
            forgotten: st.forgotten.values().copied().collect(),
            rotation: st.rotation.as_ref().map(|(r, _)| r.clone()),
            roster: st.roster.as_ref().map(|(r, _)| r.clone()),
            claims: st.claims.values().map(|a| a.msg.clone()).collect(),
            leases: st.leases.clone(),
        };
        drop(st);
        if let Err(e) = saved.save(&self.dir) {
            warn!("saving state: {e:#}");
        }
    }

    /// Host keys of the nodes (as they publish them) for ssh clients, under the same names as
    /// in /etc/hosts.
    fn update_known_hosts(&self) {
        let mut st = self.state.lock().unwrap();
        let mut recs: Vec<_> = st.records.values().collect();
        recs.sort_by_key(|r| {
            (
                !self.is_online(&st, &r.info.id),
                std::cmp::Reverse(r.info.seq),
                r.info.id,
            )
        });
        let mut used = HashSet::from([st.my_name.clone()]);
        let mut entries = vec![(st.my_name.clone(), self.my_ip, st.my_ssh_host_key.clone())];
        for r in recs {
            let name = if used.insert(r.info.name.clone()) {
                r.info.name.clone()
            } else {
                format!("{}-{}", r.info.name, r.info.id.short())
            };
            entries.push((name, overlay_ip(&r.info.id), r.info.ssh_host_key.clone()));
        }
        let mut text = String::new();
        for (name, ip, key) in entries {
            let Some(key) = key.filter(|k| k.starts_with("ssh-") && !k.contains('\n')) else {
                continue;
            };
            // Plain names only where /etc/hosts maps them to the mesh (else they may be LAN hosts).
            let plain = if self.cfg.manage_hosts {
                format!(",{name}")
            } else {
                String::new()
            };
            text.push_str(&format!("{name}.mesh,{ip}{plain} {key}\n"));
        }
        if text == st.known_hosts_written {
            return;
        }
        let path = known_hosts_path(&self.dir);
        let write = || -> std::io::Result<()> {
            use std::os::unix::fs::PermissionsExt;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, &text)?;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
            std::fs::rename(&tmp, &path)
        };
        match write() {
            Ok(()) => st.known_hosts_written = text,
            Err(e) => {
                debug!("writing {}: {e}", path.display());
                st.known_hosts_written = text;
            }
        }
    }

    fn update_hosts(&self) {
        self.update_known_hosts();
        if !self.cfg.manage_hosts {
            return;
        }
        let mut st = self.state.lock().unwrap();
        let mut entries = vec![(st.my_name.clone(), self.my_ip, self.ident.id)];
        // If two nodes share a name, the plain name goes to the one that is online and newest
        // (e.g. a machine that was set up again gets its name back from its old identity).
        let mut others: Vec<_> = st.records.values().collect();
        others.sort_by_key(|r| {
            (
                !self.is_online(&st, &r.info.id),
                std::cmp::Reverse(r.info.seq),
                r.info.id,
            )
        });
        let others: Vec<_> = others
            .into_iter()
            .map(|r| (r.info.name.clone(), overlay_ip(&r.info.id), r.info.id))
            .collect();
        entries.extend(others);
        let block = crate::hosts::render(&entries);
        if block == st.hosts_written {
            return;
        }
        match crate::hosts::write(Some(&block)) {
            Ok(()) => st.hosts_written = block,
            Err(e) => warn!("updating /etc/hosts: {e} (set manage_hosts = false to disable)"),
        }
    }

    // ----------------------------------------------------------------------------- control

    pub fn status(&self) -> Status {
        let st = self.state.lock().unwrap();
        let mut peers: Vec<PeerStatus> = st
            .records
            .values()
            .map(|r| {
                let id = r.info.id;
                let udp = st.udp_paths.get(&id).filter(|p| p.usable());
                let path = if let Some(p) = udp {
                    format!("direct UDP {}", p.addr)
                } else if let Some(l) = st.links.get(&id) {
                    format!("direct {}", l.addr)
                } else if let Some(hop) = st.routes.get(&id) {
                    let via = st.records.get(hop).map(|r| r.info.name.clone()).unwrap_or(hop.short());
                    format!("relay via {via}")
                } else {
                    "-".into()
                };
                PeerStatus {
                    name: r.info.name.clone(),
                    id: id.hex(),
                    ip: overlay_ip(&id),
                    online: self.is_online(&st, &id),
                    path,
                    rtt_ms: udp
                        .and_then(|p| p.rtt)
                        .or_else(|| st.links.get(&id).and_then(|l| l.rtt))
                        .map(|d| d.as_millis() as u64),
                    endpoints: r.info.endpoints.clone(),
                    last_seen_secs: r.last_heard.map(|t| t.elapsed().as_secs()),
                    tags: r.info.tags.clone(),
                    inventory: r.info.inventory.clone(),
                    objects: r.info.objects.clone(),
                    lan: r.info.lan.clone(),
                    perf: r.info.perf.clone(),
                    measured: r.info.measured,
                    leases: r.info.leases.iter().filter(|l| l.expires > now_ms()).cloned().collect(),
                }
            })
            .collect();
        peers.sort_by(|a, b| b.online.cmp(&a.online).then(a.name.cmp(&b.name)));
        Status {
            name: st.my_name.clone(),
            network: self.cfg.network.clone(),
            id: self.ident.id.hex(),
            ip: self.my_ip,
            interface: self.cfg.interface.clone(),
            endpoints: st.my_endpoints.clone(),
            ssh_tunnel: self.cfg.ssh_tunnel.as_ref().map(|t| match t.remote_port {
                0 => format!("{} (outgoing only)", t.server),
                _ => format!("{} -> {}", t.server, t.public_endpoint()),
            }),
            outbound_via: if self.cfg.no_outbound {
                Some("disabled".into())
            } else {
                self.socks.clone()
            },
            warnings: range_conflicts(&self.cfg.interface),
            version: crate::update::CURRENT.into(),
            update_available: st.update_available.clone(),
            banned: st.banned.values().cloned().collect(),
            socks: matches!(self.io, PacketIo::Userspace(_)).then(|| self.cfg.socks_listen.clone()),
            ssh_server: st.my_ssh_host_key.as_ref().map(|k| {
                if *k == crate::sshserver::host_key_line(&self.ident) {
                    "built-in".to_string()
                } else {
                    "sshd".to_string()
                }
            }),
            tags: st.my_tags.clone(),
            inventory: st.inventory.clone(),
            lan: crate::net::local_lans()
                .into_iter()
                .map(|(_, ip, p)| format!("{ip}/{p}"))
                .collect(),
            perf: st.perf.values().cloned().collect(),
            measured: st.measured,
            objects: st.objects_ad.clone(),
            leases: st.leases.clone(),
            peers,
        }
    }

    // ----------------------------------------------------------------------------- updates

    fn update_client(&self) -> Result<reqwest::Client> {
        if self.cfg.no_outbound && self.socks.is_none() {
            bail!("this node does not connect out (no_outbound), so it cannot reach GitHub");
        }
        crate::update::client(self.socks.as_deref())
    }

    /// Checks GitHub for a newer release and (unless `check_only`) installs it and restarts.
    pub async fn update_now(self: &Arc<Self>, check_only: bool, force: bool) -> Result<String> {
        use crate::update;
        let client = self.update_client()?;
        let tag = update::latest_tag(&client).await?;
        if !update::is_newer(&tag, update::CURRENT) {
            self.state.lock().unwrap().update_available = None;
            return Ok(format!("meshvpn {} is up to date", update::CURRENT));
        }
        self.state.lock().unwrap().update_available = Some(tag.clone());
        if check_only {
            return Ok(format!("meshvpn {tag} is available (running {})", update::CURRENT));
        }
        if update::is_dev_build() && !force {
            bail!("this is a development build - update it with git pull && cargo build (or use --force)");
        }
        info!("updating to meshvpn {tag}");
        let exe = update::install(&client, &tag).await?;
        info!("installed meshvpn {tag}; restarting");
        let node = self.clone();
        tokio::spawn(async move {
            // Give the control socket a moment to deliver the answer.
            tokio::time::sleep(Duration::from_millis(500)).await;
            node.restart(exe);
        });
        Ok(format!("updated {} -> {tag}, restarting", update::CURRENT))
    }

    async fn update_loop(self: Arc<Self>) {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            let auto = self.cfg.auto_update && !crate::update::is_dev_build();
            match self.update_now(!auto, false).await {
                Ok(msg) if msg.contains("available") => {
                    info!(
                        "{msg} - install it with: {}",
                        crate::config::hint("sudo meshvpn update")
                    )
                }
                Ok(msg) => debug!("{msg}"),
                Err(e) => debug!("update check failed: {e:#}"),
            }
            // Spread checks out so a whole network does not hit GitHub at once.
            let jitter = rand::rngs::OsRng.next_u64() % 3600;
            tokio::time::sleep(Duration::from_secs(6 * 3600 + jitter)).await;
        }
    }

    /// Replaces this process with the (new) binary, keeping pid and arguments.
    fn restart(&self, exe: PathBuf) {
        use std::os::unix::process::CommandExt;
        self.save_state();
        crate::ssh::kill_all();
        std::fs::remove_file(crate::control::socket_path(&self.dir)).ok();
        let err = std::process::Command::new(&exe)
            .args(std::env::args_os().skip(1))
            .exec();
        // exec only returns on failure; let the service manager restart us.
        warn!("restarting {}: {err}", exe.display());
        std::process::exit(1);
    }

    /// `meshvpn tag add/rm`: changes this node's tags and tells everyone.
    pub fn set_tags(&self, add: Vec<String>, remove: Vec<String>) -> Result<Vec<String>> {
        if let Some(t) = add.iter().find(|t| !crate::proto::valid_tag(t)) {
            bail!("invalid tag {t:?} (use a-z, 0-9, - _ . =)");
        }
        let mut st = self.state.lock().unwrap();
        let mut tags = st.my_tags.clone();
        tags.retain(|t| !remove.contains(t));
        for t in add {
            if !tags.contains(&t) {
                tags.push(t);
            }
        }
        if tags.len() > 32 {
            bail!("at most 32 tags");
        }
        let mut cfg = Config::load(&self.dir)?;
        cfg.tags = tags.clone();
        cfg.save(&self.dir)?;
        st.my_tags = tags.clone();
        self.announce(&mut st);
        Ok(tags)
    }

    // ----------------------------------------------------------------------------- measuring

    /// Throughput to a directly linked peer: sends `bytes` of test data, the peer reports
    /// how fast it arrived.
    async fn bench(self: &Arc<Self>, peer: NodeId, bytes: u64) -> Option<f32> {
        let (tx, id, done) = {
            let mut st = self.state.lock().unwrap();
            let tx = st.links.get(&peer)?.tx.clone();
            let id = rand::rngs::OsRng.next_u64();
            let (otx, orx) = tokio::sync::oneshot::channel();
            st.bench_wait.insert(id, otx);
            (tx, id, orx)
        };
        let msg = serde_json::to_vec(&BenchMsg { id, mbps: 0.0 }).unwrap();
        let data = frame(T_BENCH_DATA, &vec![0u8; 60_000]);
        let run = async {
            tx.send(frame(T_BENCH_START, &msg)).await.ok()?;
            let mut sent = 0u64;
            while sent < bytes {
                tx.send(data.clone()).await.ok()?;
                sent += 60_000;
            }
            tx.send(frame(T_BENCH_END, &msg)).await.ok()?;
            done.await.ok()
        };
        let res = timeout(Duration::from_secs(90), run).await.ok().flatten();
        self.state.lock().unwrap().bench_wait.remove(&id);
        res
    }

    /// Round trip to a directly linked peer, measured now.
    async fn ping(&self, peer: NodeId) -> Option<Duration> {
        let before = {
            let mut st = self.state.lock().unwrap();
            let link = st.links.get_mut(&peer)?;
            let sent = link.rtt.take();
            let f = frame(T_PING, &(self.started.elapsed().as_micros() as u64).to_be_bytes());
            let _ = link.tx.try_send(f);
            sent
        };
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let st = self.state.lock().unwrap();
            if let Some(rtt) = st.links.get(&peer).and_then(|l| l.rtt) {
                return Some(rtt);
            }
        }
        before
    }

    /// `peer`'s address on a LAN we share, if it answers there (a refused connection counts:
    /// the machine is reachable).
    async fn lan_check(info: &NodeInfo) -> Option<Ipv4Addr> {
        let mine = crate::net::local_lans();
        let mut ports: Vec<u16> = info
            .endpoints
            .iter()
            .filter_map(|e| e.rsplit(':').next()?.parse().ok())
            .collect();
        ports.push(22);
        ports.dedup();
        for l in &info.lan {
            let Some((ip, _)) = crate::net::parse_cidr(l) else {
                continue;
            };
            if !mine
                .iter()
                .any(|(_, m, p)| *m != ip && crate::net::same_subnet(*m, *p, ip))
            {
                continue;
            }
            for port in &ports {
                match timeout(Duration::from_secs(1), TcpStream::connect((ip, *port))).await {
                    Ok(Ok(_)) => return Some(ip),
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Some(ip),
                    _ => {}
                }
            }
        }
        None
    }

    /// Fills our row of the network matrix: RTT and LAN path for every online peer, and the
    /// throughput of direct links when `bytes` > 0. Then tells everyone.
    pub async fn measure(self: Arc<Self>, only: Option<Vec<NodeId>>, bytes: u64) {
        let peers: Vec<NodeInfo> = {
            let st = self.state.lock().unwrap();
            st.records
                .values()
                .filter(|r| self.is_online(&st, &r.info.id))
                .filter(|r| only.as_ref().is_none_or(|o| o.contains(&r.info.id)))
                .map(|r| r.info.clone())
                .collect()
        };
        // Round trips first: during throughput tests pings queue behind the test data.
        let mut rtts = HashMap::new();
        for info in &peers {
            rtts.insert(info.id, self.ping(info.id).await);
        }
        for info in peers {
            let rtt = rtts.remove(&info.id).flatten();
            let mbps = if bytes > 0 {
                self.bench(info.id, bytes).await
            } else {
                None
            };
            let lan_ip = Self::lan_check(&info).await;
            let mut st = self.state.lock().unwrap();
            let rtt_us = rtt
                .or_else(|| st.links.get(&info.id).and_then(|l| l.rtt))
                .map(|d| d.as_micros() as u32);
            let old_mbps = st.perf.get(&info.id).and_then(|p| p.mesh_mbps);
            st.perf.insert(
                info.id,
                Perf {
                    peer: info.id,
                    rtt_us,
                    mesh_mbps: mbps.or(old_mbps),
                    lan_ip: lan_ip.map(|i| i.to_string()),
                    at: now_ms(),
                },
            );
        }
        let mut st = self.state.lock().unwrap();
        let alive: HashSet<NodeId> = st.records.keys().copied().collect();
        st.perf.retain(|id, _| alive.contains(id));
        if bytes > 0 {
            st.measured = now_ms();
        }
        self.announce(&mut st);
    }

    fn handle_measure(self: &Arc<Self>, from: NodeId, payload: &[u8]) {
        let Ok(req) = serde_json::from_slice::<MeasureReq>(payload) else {
            return;
        };
        self.start_measure(req, Some(from));
    }

    /// Floods a measurement request; nodes in it measure towards the others in it.
    pub fn start_measure(self: &Arc<Self>, req: MeasureReq, from: Option<NodeId>) {
        let mut st = self.state.lock().unwrap();
        if !st.measure_seen.insert(req.nonce) {
            return;
        }
        if st.measure_seen.len() > 1000 {
            st.measure_seen.clear();
        }
        self.broadcast(&st, &frame(T_MEASURE, &serde_json::to_vec(&req).unwrap()), from);
        drop(st);
        if req.nodes.contains(&self.ident.id) {
            let others: Vec<NodeId> = req.nodes.iter().copied().filter(|n| *n != self.ident.id).collect();
            tokio::spawn(self.clone().measure(Some(others), req.bytes.min(1 << 30)));
        }
    }

    // ----------------------------------------------------------------------------- sharing

    /// Network keys, current first (the chunk server accepts any of them during a rotation).
    pub fn network_keys(&self) -> Vec<[u8; 32]> {
        let st = self.state.lock().unwrap();
        let mut keys: Vec<(u32, [u8; 32])> = st.keys.iter().map(|(v, k)| (*v, *k)).collect();
        keys.sort_by_key(|(v, _)| std::cmp::Reverse(*v));
        keys.into_iter().map(|(_, k)| k).collect()
    }

    /// In userspace mode, connections into the mesh go through our own SOCKS proxy.
    pub fn socks_addr(&self) -> Option<String> {
        matches!(self.io, PacketIo::Userspace(_)).then(|| self.cfg.socks_listen.clone())
    }

    /// Re-announces which objects we serve.
    pub fn objects_changed(&self) {
        let mut st = self.state.lock().unwrap();
        st.objects_ad = self.shares.ads();
        self.announce(&mut st);
    }

    /// Online nodes that have object `id`, best first (verified LAN path, then low RTT).
    pub fn holders(&self, id: &str) -> Vec<crate::share::Holder> {
        let st = self.state.lock().unwrap();
        let mut list: Vec<(bool, u32, crate::share::Holder)> = st
            .records
            .values()
            .filter(|r| self.is_online(&st, &r.info.id) && r.info.objects.iter().any(|o| o.id == id))
            .map(|r| {
                let perf = st.perf.get(&r.info.id);
                let lan_ip = perf.and_then(|p| p.lan_ip.as_ref()).and_then(|ip| ip.parse().ok());
                let rtt = perf.and_then(|p| p.rtt_us).unwrap_or(u32::MAX);
                let h = crate::share::Holder {
                    name: r.info.name.clone(),
                    mesh_ip: overlay_ip(&r.info.id),
                    lan_ip,
                };
                (lan_ip.is_none(), rtt, h)
            })
            .collect();
        list.sort_by_key(|(no_lan, rtt, _)| (*no_lan, *rtt));
        list.into_iter().map(|(_, _, h)| h).collect()
    }

    /// Keeps the inventory (load, free memory, GPU use) fresh.
    async fn inventory_loop(self: Arc<Self>) {
        let userspace = matches!(self.io, PacketIo::Userspace(_));
        // Light measurements (RTT, LAN paths) every 5 minutes; throughput only on request.
        let node = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            loop {
                node.clone().measure(None, 0).await;
                tokio::time::sleep(Duration::from_secs(300)).await;
            }
        });
        loop {
            tokio::time::sleep(REANNOUNCE).await;
            if let Ok(inv) = tokio::task::spawn_blocking(move || crate::inventory::collect(userspace)).await {
                self.state.lock().unwrap().inventory = Some(inv);
            }
        }
    }

    /// `meshvpn rename NEW`: new name for this node; identity, IP and permissions stay.
    pub fn rename(&self, new: &str) -> Result<String> {
        let name = crate::config::sanitize_name(new);
        let mut st = self.state.lock().unwrap();
        if name == st.my_name {
            bail!("this node is already called {name}");
        }
        check_name_free(&name, st.records.values().map(|r| &r.info.name))?;
        let mut cfg = Config::load(&self.dir)?;
        cfg.name = name.clone();
        cfg.save(&self.dir)?;
        let old = std::mem::replace(&mut st.my_name, name.clone());
        self.announce(&mut st);
        drop(st);
        self.update_hosts();
        info!("renamed this node: {old} -> {name}");
        let mut msg = format!("renamed {old} -> {name}; the other nodes see it as {name}.mesh within seconds");
        if name != new.trim() {
            msg.push_str(&format!(
                " (names may only contain a-z, 0-9 and -, so {new:?} became {name:?})"
            ));
        }
        Ok(msg)
    }

    /// Adds a node address to dial (and remembers it in the config).
    pub fn add_peer(&self, addr: String) -> Result<()> {
        {
            let mut st = self.state.lock().unwrap();
            if !st.extra_bootstrap.contains(&addr) && !self.cfg.bootstrap.contains(&addr) {
                st.extra_bootstrap.push(addr.clone());
            }
            st.backoff.remove(&format!("boot:{addr}"));
        }
        let mut cfg = Config::load(&self.dir)?;
        if !cfg.bootstrap.contains(&addr) {
            cfg.bootstrap.push(addr);
            cfg.save(&self.dir)?;
        }
        Ok(())
    }

    /// Kicks the dialer immediately.
    pub fn dial_now(self: &Arc<Self>) {
        let dials = {
            let mut st = self.state.lock().unwrap();
            self.dial_candidates(&mut st)
        };
        for (key, addrs, boot) in dials {
            tokio::spawn(self.clone().dial(key, addrs, boot));
        }
    }
}

/// Refuses a name another node already has: two nodes with one name confuse `<name>.mesh`, and
/// the older one would be cleaned up as "replaced machine".
pub fn check_name_free<'a>(name: &str, mut others: impl Iterator<Item = &'a String>) -> Result<()> {
    if others.any(|other| other == name) {
        bail!(
            "another node is already called {name} - pick another name, or remove that node first \
             (`meshvpn forget {name}` if it is gone for good)"
        );
    }
    Ok(())
}

fn create_tun(cfg: &Config, my_ip: Ipv4Addr) -> std::result::Result<tun::AsyncDevice, String> {
    let mut tcfg = tun::Configuration::default();
    tcfg.tun_name(&cfg.interface)
        .address(my_ip)
        .netmask(OVERLAY_NETMASK)
        .mtu(cfg.mtu)
        .up();
    tun::create_as_async(&tcfg).map_err(|e| e.to_string())
}

fn permission_problem(msg: &str) -> bool {
    msg.contains("ermission") || msg.contains("EPERM") || msg.contains("not permitted")
}

/// The TUN device can't be had here (and probably never will): use the userspace stack.
fn tun_unavailable(msg: &str) -> bool {
    let missing = msg.contains("No such file") || msg.contains("No such device") || msg.contains("os error 2");
    // Not root on a normal machine is a mistake (sudo forgotten), not a reason to switch modes.
    let root_or_container =
        unsafe { libc::geteuid() } == 0 || crate::userspace::in_container() || crate::config::rootless();
    missing || (permission_problem(msg) && root_or_container)
}

fn tun_error(cfg: &Config, msg: &str) -> anyhow::Error {
    if msg.contains("busy") || msg.contains("os error 16") {
        anyhow!(
            "cannot create network interface {}: it is already in use, most likely by another meshvpn \
             that is still running (see `pgrep -a meshvpn`; if you installed the service, a copy started \
             by hand with `meshvpn up` has to be stopped first)",
            cfg.interface
        )
    } else if crate::userspace::in_container() {
        anyhow!(
            "cannot create network interface {}: {msg}\n  This container has no access to /dev/net/tun.\n  \
             Either start it with   docker run --cap-add=NET_ADMIN --device=/dev/net/tun ...\n  \
             (compose: cap_add: [NET_ADMIN] and devices: [\"/dev/net/tun:/dev/net/tun\"]),\n  \
             or let meshvpn run without it: set  userspace = \"auto\"  in the config.",
            cfg.interface
        )
    } else if permission_problem(msg) {
        anyhow!("cannot create the network interface: {msg}\n  -> meshvpn needs root: run `sudo meshvpn up`")
    } else {
        anyhow!("cannot create network interface {}: {msg}", cfg.interface)
    }
}

const SSH_CLIENT_DROPIN: &str = "/etc/ssh/ssh_config.d/meshvpn.conf";

/// Where the host keys of the mesh nodes are kept for ssh clients.
fn known_hosts_path(dir: &std::path::Path) -> PathBuf {
    if crate::config::rootless() {
        dir.join("known_hosts")
    } else {
        PathBuf::from("/var/lib/meshvpn/known_hosts")
    }
}

/// An ssh client drop-in: mesh host keys are known (no "are you sure" prompts), and in
/// userspace mode `ssh user@host.mesh` goes through meshvpn.
fn ssh_client_config(userspace: bool) {
    if !std::path::Path::new("/etc/ssh/ssh_config.d").is_dir() {
        return;
    }
    let mut text = String::from(
        "# Managed by meshvpn: host keys of the mesh nodes are known.\n\
         Host *\n    GlobalKnownHostsFile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2 /var/lib/meshvpn/known_hosts\n",
    );
    if userspace {
        let exe = crate::update::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/meshvpn"));
        text.push_str(&format!(
            "# Userspace mode: ssh to *.mesh hosts goes through meshvpn.\nHost *.mesh\n    ProxyCommand {} nc %h %p\n",
            crate::agent::sh_quote(&exe.to_string_lossy())
        ));
    }
    if std::fs::read_to_string(SSH_CLIENT_DROPIN).is_ok_and(|t| t == text) {
        return;
    }
    if let Err(e) = std::fs::write(SSH_CLIENT_DROPIN, text) {
        debug!("writing {SSH_CLIENT_DROPIN}: {e}");
    }
}

/// `meshvpn uninstall`: remove the ssh client drop-in again.
pub fn remove_ssh_client_config() {
    if std::fs::read_to_string(SSH_CLIENT_DROPIN).is_ok_and(|t| t.contains("Managed by meshvpn")) {
        let _ = std::fs::remove_file(SSH_CLIENT_DROPIN);
    }
}

/// Rootless: the same for this user, as a marked block in ~/.ssh/config (system files are off
/// limits). Kept up to date when the binary or directory moves.
pub fn user_ssh_config(dir: &std::path::Path, enable: bool) {
    use std::os::unix::fs::PermissionsExt;
    const BEGIN: &str = "# >>> meshvpn (rootless userspace mode): ssh to *.mesh goes through meshvpn";
    const END: &str = "# <<< meshvpn";
    let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) else {
        return;
    };
    let ssh_dir = PathBuf::from(home).join(".ssh");
    let file = ssh_dir.join("config");
    let exe = crate::update::current_exe().unwrap_or_else(|_| PathBuf::from("meshvpn"));
    let dir = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let block = format!(
        "{BEGIN}\nHost *.mesh\n    ProxyCommand {} --dir {} nc %h %p\n    UserKnownHostsFile ~/.ssh/known_hosts {}\n{END}\n",
        crate::agent::sh_quote(&exe.to_string_lossy()),
        crate::agent::sh_quote(&dir.to_string_lossy()),
        crate::agent::sh_quote(&known_hosts_path(&dir).to_string_lossy())
    );
    let old = std::fs::read_to_string(&file).unwrap_or_default();
    let block = if enable { block } else { String::new() };
    let new = match (old.find(BEGIN), old.find(END)) {
        (Some(b), Some(e)) if e > b => {
            let end = old[e..].find('\n').map_or(old.len(), |n| e + n + 1);
            format!("{}{block}{}", &old[..b], &old[end..])
        }
        _ if !enable => old.clone(),
        _ if old.is_empty() || old.ends_with('\n') => format!("{old}{block}"),
        _ => format!("{old}\n{block}"),
    };
    if new == old {
        return;
    }
    let _ = std::fs::create_dir_all(&ssh_dir);
    let _ = std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700));
    match std::fs::write(&file, new) {
        Ok(()) => {
            let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
            if enable {
                info!("ssh to <node>.mesh goes through meshvpn ({})", file.display());
            }
        }
        Err(e) => warn!("writing {}: {e}", file.display()),
    }
}

/// Splits records into gossip frames by size (records carry inventory, measurements...).
fn gossip_frames(records: &[SignedInfo]) -> Vec<Vec<u8>> {
    let mut frames = vec![];
    let mut batch: Vec<&SignedInfo> = vec![];
    let mut size = 0;
    for r in records {
        let len = r.data.len() + r.sig.len() + 32;
        if !batch.is_empty() && size + len > GOSSIP_BYTES {
            frames.push(frame(T_GOSSIP, &serde_json::to_vec(&batch).unwrap()));
            batch.clear();
            size = 0;
        }
        batch.push(r);
        size += len;
    }
    if !batch.is_empty() {
        frames.push(frame(T_GOSSIP, &serde_json::to_vec(&batch).unwrap()));
    }
    frames
}

/// `meshvpn ssh allow everyone ...`
fn is_everyone(who: &str) -> bool {
    matches!(who.trim(), "*" | "everyone" | "all" | "everybody")
}

/// Public keys (`~/.ssh/id_*.pub`) of this machine's login accounts.
fn local_ssh_keys() -> Vec<crate::proto::SshKey> {
    let mut out = vec![];
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        let (Some(user), Some(uid), Some(home)) = (f.first(), f.get(2), f.get(5)) else {
            continue;
        };
        let Ok(uid) = uid.parse::<u32>() else { continue };
        if (uid != 0 && uid < 1000) || uid >= 65534 || !crate::proto::valid_user(user) {
            continue;
        }
        for name in ["id_ed25519", "id_ecdsa", "id_rsa", "id_ed25519_sk", "id_ecdsa_sk"] {
            let private = format!("{home}/.ssh/{name}");
            let Some(text) = std::fs::read_to_string(format!("{private}.pub"))
                .ok()
                .or_else(|| derive_public_key(&private))
            else {
                continue;
            };
            let key: Vec<&str> = text.split_whitespace().take(2).collect();
            let key = key.join(" ");
            if crate::proto::valid_ssh_key(&key) && out.len() < 64 {
                out.push(crate::proto::SshKey {
                    user: user.to_string(),
                    key,
                });
            }
        }
    }
    out
}

/// Public key of a private key file that has no `.pub` next to it (common on servers).
/// Keys with a passphrase are skipped: nothing may prompt here. Cached per file version.
fn derive_public_key(private: &str) -> Option<String> {
    type Cache = HashMap<String, (SystemTime, Option<String>)>;
    static CACHE: Mutex<Option<Cache>> = Mutex::new(None);
    let modified = std::fs::metadata(private).ok()?.modified().ok()?;
    let mut cache = CACHE.lock().unwrap();
    let cache = cache.get_or_insert_default();
    if let Some((m, key)) = cache.get(private)
        && *m == modified
    {
        return key.clone();
    }
    let key = std::process::Command::new("ssh-keygen")
        .args(["-y", "-P", "", "-f", private])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    cache.insert(private.to_string(), (modified, key.clone()));
    key
}

/// The address of the interface used for the default route (no packets are sent).
fn primary_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:80").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified() && !is_overlay(ip)).then_some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_public_keys_but_never_prompts() {
        let dir = std::env::temp_dir().join(format!("meshvpn-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let keygen = |name: &str, pass: &str| {
            let path = dir.join(name);
            let ok = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", pass, "-f"])
                .arg(&path)
                .status()
                .unwrap()
                .success();
            assert!(ok);
            std::fs::remove_file(path.with_extension("pub")).unwrap();
            path.to_string_lossy().into_owned()
        };
        let plain = keygen("plain", "");
        let key = derive_public_key(&plain).expect("public key");
        assert!(crate::proto::valid_ssh_key(
            &key.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
        ));
        let locked = keygen("locked", "secret");
        assert_eq!(derive_public_key(&locked), None);
        std::fs::remove_dir_all(&dir).ok();
    }
}
