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

use crate::config::{Config, SavedState};
use crate::keys::{Identity, NodeId, OVERLAY_NETMASK, overlay_ip};
use crate::link::{self, Cipher, LinkReader, LinkWriter};
use crate::proto::*;

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
const GOSSIP_BATCH: usize = 32;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
}

pub struct Node {
    cfg: Config,
    dir: PathBuf,
    ident: Identity,
    psk: [u8; 32],
    my_ip: Ipv4Addr,
    tun: Arc<tun::AsyncDevice>,
    state: Mutex<State>,
    next_link_id: AtomicU64,
    started: Instant,
    socks: Option<String>,
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
    pub peers: Vec<PeerStatus>,
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
}

// ---------------------------------------------------------------------------------------------

pub async fn run(dir: PathBuf, cfg: Config) -> Result<()> {
    let ident = Identity::from_config(&cfg)?;
    let psk = cfg.network_key()?;
    let my_ip = overlay_ip(&ident.id);

    let mut tcfg = tun::Configuration::default();
    tcfg.tun_name(&cfg.interface)
        .address(my_ip)
        .netmask(OVERLAY_NETMASK)
        .mtu(cfg.mtu)
        .up();
    let tun = tun::create_as_async(&tcfg).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("ermission") || msg.contains("EPERM") || msg.contains("Operation not permitted") {
            anyhow!("cannot create the network interface: {msg}\n  -> meshvpn needs root: run `sudo meshvpn up`")
        } else {
            anyhow!("cannot create network interface {}: {msg}", cfg.interface)
        }
    })?;

    let socks = cfg.effective_socks();
    let node = Arc::new(Node {
        dir: dir.clone(),
        ident,
        psk,
        my_ip,
        tun: Arc::new(tun),
        state: Mutex::new(State::default()),
        next_link_id: AtomicU64::new(1),
        started: Instant::now(),
        socks,
        cfg,
    });

    {
        let saved = SavedState::load(&dir);
        let mut st = node.state.lock().unwrap();
        if let Some(me) = saved.me.and_then(|m| m.verify().ok()) {
            st.my_seq = me.seq;
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

    if let Some(listen) = node.cfg.listen.clone() {
        let listener = TcpListener::bind(&listen)
            .await
            .with_context(|| format!("cannot listen on {listen}"))?;
        info!("accepting peers on {listen}");
        tokio::spawn(node.clone().accept_loop(listener));
    }
    if let Some(t) = node.cfg.ssh_tunnel.clone() {
        let port = node.cfg.listen_port().context("ssh_tunnel needs `listen` to be set")?;
        tokio::spawn(crate::ssh::supervise(t, port));
    }
    if let Some(s) = &node.socks {
        info!("outgoing connections go through SOCKS proxy {s}");
    }
    tokio::spawn(node.clone().tun_loop());
    tokio::spawn(node.clone().tick_loop());
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
        st.my_seq = now_ms().max(st.my_seq + 1);
        let info = NodeInfo {
            id: self.ident.id,
            noise_pub: self.ident.noise_pub,
            name: self.cfg.name.clone(),
            endpoints: st.my_endpoints.clone(),
            neighbors,
            seq: st.my_seq,
            version: env!("CARGO_PKG_VERSION").into(),
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
        let info = match signed.verify() {
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
        let id = info.id;
        st.records.insert(
            id,
            Record {
                info,
                signed,
                last_heard: live.then(Instant::now),
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
            let f = frame(T_GOSSIP, &serde_json::to_vec(&changed).unwrap());
            self.broadcast(&st, &f, Some(from));
            drop(st);
            self.update_hosts();
        }
    }

    fn full_table(&self, st: &State) -> Vec<Vec<u8>> {
        let mut all: Vec<SignedInfo> = st.records.values().map(|r| r.signed.clone()).collect();
        all.extend(st.my_signed.clone());
        all.chunks(GOSSIP_BATCH)
            .map(|c| frame(T_GOSSIP, &serde_json::to_vec(c).unwrap()))
            .collect()
    }

    fn is_online(&self, st: &State, id: &NodeId) -> bool {
        st.links.contains_key(id)
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
        let key = self.ident.e2e_key(&rec.info.noise_pub, &self.psk);
        let c = XChaCha20Poly1305::new(&key.into());
        st.ciphers.insert(*peer, c.clone());
        Some(c)
    }

    /// Encrypts an IP packet end-to-end for `dst` and hands it to the first hop.
    fn send_packet(&self, dst_ip: Ipv4Addr, pkt: &[u8]) {
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

    async fn tun_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match self.tun.recv(&mut buf).await {
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
                None => Ok(TcpStream::connect(addr).await?),
            }
        };
        timeout(CONNECT_TIMEOUT, fut).await.map_err(|_| anyhow!("timed out"))?
    }

    /// Handshake + hello exchange + registration.
    async fn establish(self: &Arc<Self>, mut stream: TcpStream, initiator: bool, addr: String) -> Result<Established> {
        stream.set_nodelay(true).ok();
        let observed = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        let (transport, remote_static) = timeout(
            HANDSHAKE_TIMEOUT,
            link::handshake(&mut stream, initiator, &self.ident.noise_secret, &self.psk),
        )
        .await
        .map_err(|_| anyhow!("handshake timed out"))??;
        let cipher = Cipher::new(transport);
        let (r, w) = stream.into_split();
        let mut reader = LinkReader::new(r, cipher.clone());
        let mut writer = LinkWriter::new(w, cipher);

        let my_signed = self.state.lock().unwrap().my_signed.clone().unwrap();
        let my_nonce = rand::rngs::OsRng.next_u64();
        let hello = Hello {
            info: my_signed,
            observed,
            nonce: my_nonce,
        };
        writer.send(&frame(T_HELLO, &serde_json::to_vec(&hello)?)).await?;
        let msg = timeout(HANDSHAKE_TIMEOUT, reader.recv())
            .await
            .map_err(|_| anyhow!("hello timed out"))??;
        if msg.first() != Some(&T_HELLO) {
            bail!("expected hello");
        }
        let hello: Hello = serde_json::from_slice(&msg[1..])?;
        let info = hello.info.verify()?;
        if info.noise_pub != remote_static {
            bail!("record does not match link key");
        }
        let peer = info.id;
        if peer == self.ident.id {
            bail!("connected to myself");
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
                        let _ = self.tun.send(&pkt).await;
                    }
                }
                T_GOSSIP => self.handle_gossip(peer, payload),
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
                if last_announce.elapsed() >= REANNOUNCE || self.endpoints(&st) != st.my_endpoints {
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
                self.rebuild(&mut st);
                self.dial_candidates(&mut st)
            };
            for (key, addrs, boot) in dials {
                tokio::spawn(self.clone().dial(key, addrs, boot));
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
        };
        drop(st);
        if let Err(e) = saved.save(&self.dir) {
            warn!("saving state: {e:#}");
        }
    }

    fn update_hosts(&self) {
        if !self.cfg.manage_hosts {
            return;
        }
        let mut st = self.state.lock().unwrap();
        let mut entries = vec![(self.cfg.name.clone(), self.my_ip, self.ident.id)];
        let mut others: Vec<_> = st
            .records
            .values()
            .map(|r| (r.info.name.clone(), overlay_ip(&r.info.id), r.info.id))
            .collect();
        others.sort_by_key(|a| a.2);
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
                let path = if let Some(l) = st.links.get(&id) {
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
                    rtt_ms: st.links.get(&id).and_then(|l| l.rtt).map(|d| d.as_millis() as u64),
                    endpoints: r.info.endpoints.clone(),
                    last_seen_secs: r.last_heard.map(|t| t.elapsed().as_secs()),
                }
            })
            .collect();
        peers.sort_by(|a, b| b.online.cmp(&a.online).then(a.name.cmp(&b.name)));
        Status {
            name: self.cfg.name.clone(),
            network: self.cfg.network.clone(),
            id: self.ident.id.hex(),
            ip: self.my_ip,
            interface: self.cfg.interface.clone(),
            endpoints: st.my_endpoints.clone(),
            ssh_tunnel: self
                .cfg
                .ssh_tunnel
                .as_ref()
                .map(|t| format!("{} -> {}", t.server, t.public_endpoint())),
            outbound_via: if self.cfg.no_outbound {
                Some("disabled".into())
            } else {
                self.socks.clone()
            },
            peers,
        }
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

/// The address of the interface used for the default route (no packets are sent).
fn primary_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:80").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified() && !is_overlay(ip)).then_some(ip)
}
