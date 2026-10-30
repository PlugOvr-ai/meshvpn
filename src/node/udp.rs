//! Direct UDP paths between nodes, through NATs (hole punching).
//!
//! Every node has one UDP socket (its listen port, or a random one) and publishes address
//! candidates: its LAN addresses and its public address as other nodes see it. Nodes keep
//! sending authenticated probes to each other's candidates; outgoing probes open the NAT on
//! each side, so for most NATs a direct path appears within seconds. IP packets then go
//! straight over UDP - end-to-end encrypted as always - instead of TCP or a relay. Without
//! an answer for 30 s a path is dropped and traffic falls back to TCP/relays.
//!
//! Datagrams:
//!   probe  A1 | src id 32 | dst id 32 | timestamp 8 | nonce 8 | mac 16
//!   ack    A2 | src id 32 | dst id 32 | timestamp 8 | nonce 8 | seen-as ip 4/16 + port 2 | mac 16
//!
//! IPv6: a second socket on the same port. There is no NAT on the way, only stateful firewalls
//! (home routers, mobile networks) that let answers in - and probes sent at the same time from
//! both sides are answers for each other. So two nodes behind NATs that change ports per
//! destination (mobile networks, CGNAT), where IPv4 hole punching fails, usually get a direct
//! path over IPv6.
//!   data   A3 | src id prefix 8 | nonce 24 | XChaCha20-Poly1305(packet)   (49 bytes overhead)
//!   frag   A4 | src id prefix 8 | message 4 | index 1 | count 1 | part of a data datagram
//!
//! Path MTU: a full-size packet makes a datagram of about 1450 bytes, more than some paths
//! carry (VPNs, mobile networks, WSL2's NAT, which also drops IP fragments). Small probes get
//! through there, but big packets vanish - TCP connections hang. So each path is tested with
//! a probe padded to full size; until that is answered, data datagrams over 1200 bytes are
//! split into parts that fit any path (only towards nodes that can put them together).

use super::*;
use tokio::net::UdpSocket;

const PROBE: u8 = 0xA1;
const ACK: u8 = 0xA2;
const DATA: u8 = 0xA3;
const FRAG: u8 = 0xA4;
/// Datagram size that fits every path that carries 1280-byte IP packets.
const SAFE_DATAGRAM: usize = 1200;
/// Nodes from this version on understand padded probes and fragments.
const FRAG_VERSION: &str = "0.12.2";
/// How often a path's full-size capacity is checked again.
const BIG_RECHECK: Duration = Duration::from_secs(60);
/// A path without anything heard for this long is dropped.
pub(super) const PATH_TIMEOUT: Duration = Duration::from_secs(30);
const KEEPALIVE: Duration = Duration::from_secs(10);
/// Below the ~30 s after which NATs forget an idle UDP mapping, so both sides' holes overlap.
const MAX_PROBE_INTERVAL: Duration = Duration::from_secs(15);

pub(super) struct UdpPath {
    pub addr: SocketAddr,
    pub last_rx: Instant,
    pub rtt: Option<Duration>,
    /// Liveness checks while sending: probes sent since the peer was last heard.
    last_probe: Instant,
    unanswered: u32,
    /// Full-size datagrams get through (answered padded probe); None: not known yet.
    big: Option<bool>,
    /// The peer can reassemble split datagrams.
    frags: bool,
    /// The padded probe in flight (its nonce) and when the next check is due.
    big_probe: Option<(u64, Instant)>,
    big_next: Instant,
}

impl UdpPath {
    /// Large datagrams are split on this path.
    pub fn splitting(&self) -> bool {
        self.frags && self.big != Some(true)
    }

    /// Good for data: heard recently, and not ignoring our checks.
    pub fn usable(&self) -> bool {
        self.last_rx.elapsed() < Duration::from_secs(15) && self.unanswered < 4
    }
}

/// A split datagram being put back together.
pub(super) struct Reassembly {
    started: Instant,
    parts: Vec<Option<Vec<u8>>>,
}

/// Probing state per peer without a path.
pub(super) struct Probing {
    next: Instant,
    interval: Duration,
    /// Candidates the interval was computed for (restart quickly when they change).
    candidates: Vec<SocketAddr>,
}

fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    blake3::keyed_hash(key, data).as_bytes()[..16].try_into().unwrap()
}

fn now_ms() -> u64 {
    super::now_ms()
}

impl Node {
    /// Pairwise key for probes, derived from the end-to-end key (cached).
    fn probe_key(&self, st: &mut State, peer: &NodeId) -> Option<[u8; 32]> {
        if let Some(k) = st.udp_keys.get(peer) {
            return Some(*k);
        }
        let rec = st.records.get(peer)?;
        let e2e = self.ident.e2e_key(&rec.info.noise_pub, &self.net);
        let k = blake3::derive_key("meshvpn udp probe v1", &e2e);
        st.udp_keys.insert(*peer, k);
        Some(k)
    }

    /// Our address candidates: LAN addresses and what other nodes saw.
    pub(super) fn udp_candidates(&self, st: &State) -> Vec<String> {
        let Some(sock) = &self.udp else { return vec![] };
        let Ok(port) = sock.local_addr().map(|a| a.port()) else {
            return vec![];
        };
        let mut out: Vec<String> = crate::net::local_lans()
            .into_iter()
            .map(|(_, ip, _)| SocketAddr::new(IpAddr::V4(ip), port).to_string())
            .collect();
        for a in &st.udp_reflexive {
            out.push(a.to_string());
        }
        out.dedup();
        out.truncate(8);
        out
    }

    /// Our IPv6 candidates: the global addresses of this machine (no NAT to see through).
    pub(super) fn udp6_candidates(&self) -> Vec<String> {
        let Some(port) = self.udp6.as_ref().and_then(|s| s.local_addr().ok()).map(|a| a.port()) else {
            return vec![];
        };
        crate::sys::global_ipv6()
            .into_iter()
            .take(4)
            .map(|ip| SocketAddr::new(IpAddr::V6(ip), port).to_string())
            .collect()
    }

    /// Our NAT as other nodes see it (None without UDP), and our IPv6 candidates.
    pub(super) fn nat_report(&self, st: &State) -> (Option<NatKind>, Vec<String>) {
        let Some(port) = self.udp.as_ref().and_then(|s| s.local_addr().ok()).map(|a| a.port()) else {
            return (None, vec![]);
        };
        let observed: Vec<SocketAddr> = st
            .udp_seen
            .values()
            .filter(|(_, at)| at.elapsed() < Duration::from_secs(600))
            .map(|(a, _)| *a)
            .collect();
        let local: Vec<Ipv4Addr> = crate::sys::ipv4_interfaces().into_iter().map(|(_, ip, _)| ip).collect();
        (Some(nat_kind(&observed, &local, port)), st.my_udp6.clone())
    }

    /// The socket for sending to `addr`.
    pub(super) fn udp_socket(&self, addr: &SocketAddr) -> Option<&Arc<UdpSocket>> {
        if addr.is_ipv4() {
            self.udp.as_ref()
        } else {
            self.udp6.as_ref()
        }
    }

    fn udp_send(&self, d: &[u8], addr: SocketAddr) {
        if let Some(sock) = self.udp_socket(&addr) {
            let _ = sock.try_send_to(d, addr);
        }
    }

    /// The peer's candidates, plus the hosts of its TCP endpoints on its UDP port (servers
    /// behind 1:1 NAT know only their private address).
    fn peer_candidates(info: &NodeInfo) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = info.udp.iter().filter_map(|c| c.parse().ok()).collect();
        // The first candidates are the node's own addresses, so their port is its UDP port.
        // NATs that map per destination (Linux, many routers) usually keep the original port
        // for a new destination when it is free: try every public address on that port too.
        if let Some(port) = out.first().map(|a| a.port()) {
            let public: Vec<IpAddr> = out.iter().filter(|a| a.port() != port).map(|a| a.ip()).collect();
            out.extend(public.into_iter().map(|ip| SocketAddr::new(ip, port)));
            for e in &info.endpoints {
                if let Some((host, _)) = e.rsplit_once(':')
                    && let Ok(ip) = host.parse::<Ipv4Addr>()
                {
                    out.push(SocketAddr::new(IpAddr::V4(ip), port));
                }
            }
        }
        out.extend(info.udp6.iter().filter_map(|c| c.parse::<SocketAddr>().ok()));
        out.retain(|a| !is_overlay(a.ip()) && !a.ip().is_unspecified());
        out.sort();
        out.dedup();
        out
    }

    fn probe_datagram(
        &self,
        kind: u8,
        dst: &NodeId,
        ts: u64,
        nonce: u64,
        seen: Option<SocketAddr>,
        key: &[u8; 32],
    ) -> Vec<u8> {
        self.padded_datagram(kind, dst, ts, nonce, seen, key, 0)
    }

    /// A probe padded to `size` bytes (0: no padding), to test what a path carries.
    #[allow(clippy::too_many_arguments)]
    fn padded_datagram(
        &self,
        kind: u8,
        dst: &NodeId,
        ts: u64,
        nonce: u64,
        seen: Option<SocketAddr>,
        key: &[u8; 32],
        size: usize,
    ) -> Vec<u8> {
        let mut d = Vec::with_capacity(size.max(103));
        d.push(kind);
        d.extend_from_slice(&self.ident.id.0);
        d.extend_from_slice(&dst.0);
        d.extend_from_slice(&ts.to_be_bytes());
        d.extend_from_slice(&nonce.to_be_bytes());
        match seen {
            Some(SocketAddr::V4(s)) => d.extend_from_slice(&s.ip().octets()),
            Some(SocketAddr::V6(s)) => d.extend_from_slice(&s.ip().octets()),
            None => {}
        }
        if let Some(s) = seen {
            d.extend_from_slice(&s.port().to_be_bytes());
        }
        if size > d.len() + 16 {
            d.resize(size - 16, 0);
        }
        let m = mac(key, &d);
        d.extend_from_slice(&m);
        d
    }

    /// Sends probes: keepalives on live paths, punching attempts towards the others.
    pub(super) fn udp_probe_round(&self) {
        if self.udp.is_none() {
            return;
        }
        let mut st = self.state.lock().unwrap();
        let now = Instant::now();
        st.udp_paths.retain(|_, p| p.last_rx.elapsed() < PATH_TIMEOUT);
        let peers: Vec<(NodeId, Vec<SocketAddr>)> = st
            .records
            .values()
            .filter(|r| self.is_online(&st, &r.info.id))
            .map(|r| (r.info.id, Self::peer_candidates(&r.info)))
            .filter(|(_, c)| !c.is_empty())
            .collect();
        for (peer, candidates) in peers {
            let Some(key) = self.probe_key(&mut st, &peer) else {
                continue;
            };
            // Whether the peer can reassemble: its record may have arrived after the path.
            let frags = st
                .records
                .get(&peer)
                .is_some_and(|r| crate::update::at_least(&r.info.version, FRAG_VERSION));
            // Full-size check of a path (towards nodes that understand padded probes).
            if let Some(p) = st.udp_paths.get_mut(&peer)
                && (p.frags || frags)
            {
                p.frags = true;
                if let Some((_, sent)) = p.big_probe
                    && sent.elapsed() > Duration::from_secs(3)
                {
                    p.big_probe = None;
                    if p.big != Some(false) {
                        debug!("udp: full-size datagrams don't reach {peer}: splitting them");
                    }
                    p.big = Some(false);
                }
                if p.big_probe.is_none() && p.big_next <= now {
                    let nonce = rand::rngs::OsRng.next_u64();
                    p.big_probe = Some((nonce, now));
                    p.big_next = now + BIG_RECHECK;
                    let size = self.cfg.mtu as usize + 49;
                    let d = self.padded_datagram(PROBE, &peer, now_ms(), nonce, None, &key, size);
                    self.udp_send(&d, p.addr);
                }
            }
            let targets: Vec<SocketAddr> = match st.udp_paths.get(&peer) {
                Some(p) if p.last_rx.elapsed() < KEEPALIVE => continue,
                Some(p) => vec![p.addr],
                None => {
                    let pr = st.udp_probing.entry(peer).or_insert(Probing {
                        next: now,
                        interval: Duration::from_secs(2),
                        candidates: candidates.clone(),
                    });
                    if pr.candidates != candidates {
                        pr.candidates = candidates.clone();
                        pr.interval = Duration::from_secs(2);
                        pr.next = now;
                    }
                    if pr.next > now {
                        continue;
                    }
                    pr.next = now + pr.interval;
                    pr.interval = (pr.interval * 2).min(MAX_PROBE_INTERVAL);
                    candidates
                }
            };
            debug!("udp: probing {peer} at {targets:?}");
            let d = self.probe_datagram(PROBE, &peer, now_ms(), rand::rngs::OsRng.next_u64(), None, &key);
            for t in targets {
                self.udp_send(&d, t);
            }
        }
    }

    /// The datagram(s) carrying `pkt` to `dst` over its UDP path (split on small paths).
    pub(super) fn udp_datagrams(
        &self,
        dst: &NodeId,
        cipher: &XChaCha20Poly1305,
        pkt: &[u8],
    ) -> Option<(SocketAddr, Vec<Vec<u8>>)> {
        self.udp.as_ref()?;
        let addr = {
            let mut st = self.state.lock().unwrap();
            let key = self.probe_key(&mut st, dst);
            let p = st.udp_paths.get_mut(dst).filter(|p| p.usable())?;
            // Quiet for a while although we are sending: check the path along the way, so a
            // dead one is noticed in seconds rather than at the timeout.
            if p.last_rx.elapsed() > Duration::from_secs(3)
                && p.last_probe.elapsed() > Duration::from_secs(1)
                && let Some(key) = key
            {
                p.last_probe = Instant::now();
                p.unanswered += 1;
                let addr = p.addr;
                let probe = self.probe_datagram(PROBE, dst, now_ms(), rand::rngs::OsRng.next_u64(), None, &key);
                self.udp_send(&probe, addr);
            }
            (p.addr, p.splitting())
        };
        let (addr, split) = addr;
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher.encrypt(&XNonce::from(nonce), pkt).ok()?;
        let mut d = Vec::with_capacity(33 + ct.len());
        d.push(DATA);
        d.extend_from_slice(&self.ident.id.0[..8]);
        d.extend_from_slice(&nonce);
        d.extend_from_slice(&ct);
        if split && d.len() > SAFE_DATAGRAM {
            let id = rand::rngs::OsRng.next_u32();
            let chunk = SAFE_DATAGRAM - 15;
            let count = d.len().div_ceil(chunk);
            let parts = d
                .chunks(chunk)
                .enumerate()
                .map(|(i, part)| {
                    let mut f = Vec::with_capacity(15 + part.len());
                    f.push(FRAG);
                    f.extend_from_slice(&self.ident.id.0[..8]);
                    f.extend_from_slice(&id.to_be_bytes());
                    f.push(i as u8);
                    f.push(count as u8);
                    f.extend_from_slice(part);
                    f
                })
                .collect();
            Some((addr, parts))
        } else {
            Some((addr, vec![d]))
        }
    }

    /// A part of a split datagram; the whole datagram once all parts are there.
    fn udp_frag(&self, d: &[u8]) -> Option<Vec<u8>> {
        if d.len() < 16 {
            return None;
        }
        let prefix: [u8; 8] = d[1..9].try_into().ok()?;
        let id = u32::from_be_bytes(d[9..13].try_into().ok()?);
        let (index, count) = (d[13] as usize, d[14] as usize);
        if !(2..=8).contains(&count) || index >= count {
            return None;
        }
        let mut st = self.state.lock().unwrap();
        st.id_prefix.get(&prefix)?; // only known nodes (the data is authenticated as a whole)
        if st.udp_frags.len() > 256 {
            st.udp_frags.retain(|_, r| r.started.elapsed() < Duration::from_secs(2));
            if st.udp_frags.len() > 256 {
                return None;
            }
        }
        let r = st.udp_frags.entry((prefix, id)).or_insert_with(|| Reassembly {
            started: Instant::now(),
            parts: vec![None; count],
        });
        if r.parts.len() != count {
            return None;
        }
        r.parts[index] = Some(d[15..].to_vec());
        if r.parts.iter().any(|p| p.is_none()) {
            return None;
        }
        let r = st.udp_frags.remove(&(prefix, id))?;
        Some(r.parts.into_iter().flatten().flatten().collect())
    }

    pub(super) async fn udp_loop(self: Arc<Self>, sock: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let d = &buf[..n];
            match d.first() {
                Some(&PROBE) | Some(&ACK) => self.udp_control(&sock, d, from),
                Some(&DATA) => {
                    if let Some(pkt) = self.udp_data(d, from) {
                        self.deliver(pkt).await;
                    }
                }
                Some(&FRAG) => {
                    if let Some(whole) = self.udp_frag(d)
                        && whole.first() == Some(&DATA)
                        && let Some(pkt) = self.udp_data(&whole, from)
                    {
                        self.deliver(pkt).await;
                    }
                }
                _ => {}
            }
        }
    }

    fn udp_control(&self, sock: &UdpSocket, d: &[u8], from: SocketAddr) {
        let ack = d[0] == ACK;
        // Probes may be padded (full-size checks); acks never are (103 bytes, 115 with an
        // IPv6 address).
        if (ack && d.len() != 103 && d.len() != 115) || d.len() < 97 || d.len() > 2048 {
            return;
        }
        let len = d.len();
        let (Ok(src), Ok(dst)) = (NodeId::from_slice(&d[1..33]), NodeId::from_slice(&d[33..65])) else {
            return;
        };
        if dst != self.ident.id {
            return;
        }
        let mut st = self.state.lock().unwrap();
        let Some(key) = self.probe_key(&mut st, &src) else {
            return;
        };
        if mac(&key, &d[..len - 16]) != d[len - 16..] {
            return;
        }
        let ts = u64::from_be_bytes(d[65..73].try_into().unwrap());
        let nonce = u64::from_be_bytes(d[73..81].try_into().unwrap());
        if !ack {
            // The MAC proves the sender. The timestamp is only echoed back for the RTT, so
            // clocks that differ between machines don't matter.
            let reply = self.probe_datagram(ACK, &src, ts, nonce, Some(from), &key);
            let _ = sock.try_send_to(&reply, from);
            // Answer with a probe of our own right away: this opens our NAT towards them.
            if !st.udp_paths.contains_key(&src) {
                let p = self.probe_datagram(PROBE, &src, now_ms(), rand::rngs::OsRng.next_u64(), None, &key);
                let _ = sock.try_send_to(&p, from);
            }
            return;
        }
        // An answer to our probe: the path works in both directions.
        if let Some(p) = st.udp_paths.get_mut(&src)
            && p.big_probe.is_some_and(|(n, _)| n == nonce)
        {
            p.big_probe = None;
            if p.big != Some(true) {
                debug!("udp: full-size datagrams reach {src}");
            }
            p.big = Some(true);
            p.last_rx = Instant::now();
            return;
        }
        let rtt = Duration::from_millis(now_ms().saturating_sub(ts));
        let seen = if len == 115 {
            let ip: [u8; 16] = d[81..97].try_into().unwrap();
            SocketAddr::new(IpAddr::V6(ip.into()), u16::from_be_bytes([d[97], d[98]]))
        } else {
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(d[81], d[82], d[83], d[84])),
                u16::from_be_bytes([d[85], d[86]]),
            )
        };
        // Which way a peer answered first doesn't matter: keep the best working one (several
        // candidates answer while probing), so the path doesn't flip with every probe round.
        if let Some(p) = st.udp_paths.get_mut(&src)
            && p.addr != from
            && p.last_rx.elapsed() < KEEPALIVE
            && path_rank(&p.addr) <= path_rank(&from)
        {
            p.last_rx = Instant::now();
            return;
        }
        let fresh = !st.udp_paths.contains_key(&src);
        let frags = st
            .records
            .get(&src)
            .is_some_and(|r| crate::update::at_least(&r.info.version, FRAG_VERSION));
        let old = st.udp_paths.remove(&src);
        // Same address: keep what is known about its capacity.
        let (big, big_probe, big_next) = match old {
            Some(o) if o.addr == from => (o.big, o.big_probe, o.big_next),
            _ => (None, None, Instant::now()),
        };
        st.udp_paths.insert(
            src,
            UdpPath {
                addr: from,
                last_rx: Instant::now(),
                rtt: Some(rtt),
                last_probe: Instant::now(),
                unanswered: 0,
                big,
                frags,
                big_probe,
                big_next,
            },
        );
        st.udp_probing.remove(&src);
        if fresh {
            let name = st.records.get(&src).map(|r| r.info.name.clone()).unwrap_or_default();
            info!("direct UDP path to {name} ({src}) via {from}");
        }
        let SocketAddr::V4(_) = seen else { return }; // IPv6: no NAT, nothing to learn
        // How a node outside our networks sees us: for the NAT check.
        let lans = crate::net::local_lans();
        let peer_outside = match from.ip() {
            IpAddr::V4(f) => !lans.iter().any(|(_, ip, p)| crate::net::same_subnet(*ip, *p, f)),
            _ => false,
        };
        if peer_outside {
            st.udp_seen.insert(src, (seen, Instant::now()));
        }
        // Remember how the world sees us (our public address behind NAT).
        let local = lans.iter().any(|(_, ip, _)| IpAddr::V4(*ip) == seen.ip());
        if !local && !is_overlay(seen.ip()) && !st.udp_reflexive.contains(&seen) {
            st.udp_reflexive.insert(0, seen);
            st.udp_reflexive.truncate(2);
        }
    }

    fn udp_data(&self, d: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        if d.len() < 1 + 8 + 24 + 16 + 20 {
            return None;
        }
        let (src, cipher) = {
            let mut st = self.state.lock().unwrap();
            let src = *st.id_prefix.get(&<[u8; 8]>::try_from(&d[1..9]).ok()?)?;
            (src, self.cipher_for(&mut st, &src)?)
        };
        let nonce: [u8; 24] = d[9..33].try_into().ok()?;
        let pkt = cipher.decrypt(&XNonce::from(nonce), &d[33..]).ok()?;
        // Anti-spoofing: the inner source address must belong to the sender (and only to it).
        if !self.source_ok(&src, &pkt) {
            return None;
        }
        // Authentic: the path is alive (and follows the peer if its NAT mapping changed).
        let mut st = self.state.lock().unwrap();
        if let Some(p) = st.udp_paths.get_mut(&src) {
            p.last_rx = Instant::now();
            p.unanswered = 0;
            p.addr = from;
        }
        Some(pkt)
    }
}

/// What other nodes tell about our IPv4 NAT: `observed` = our address as seen by nodes
/// outside our networks, `local` = our own addresses, `port` = our UDP port.
pub(crate) fn nat_kind(observed: &[SocketAddr], local: &[Ipv4Addr], port: u16) -> NatKind {
    let Some(first) = observed.first() else {
        return NatKind::Unknown;
    };
    if observed
        .iter()
        .all(|a| matches!(a.ip(), IpAddr::V4(ip) if local.contains(&ip)))
    {
        return NatKind::Public;
    }
    if observed.len() < 2 {
        return NatKind::OneObservation;
    }
    if observed.iter().all(|a| a.port() == first.port()) {
        NatKind::KeepsPort {
            preserved: first.port() == port,
        }
    } else {
        NatKind::ChangesPort
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum NatKind {
    /// No node outside our networks has answered yet.
    Unknown,
    /// Our own address is public.
    Public,
    OneObservation,
    /// The same public port for every destination: hole punching works.
    KeepsPort {
        preserved: bool,
    },
    /// A new port per destination (mobile networks, CGNAT): IPv4 hole punching fails.
    ChangesPort,
}

impl NatKind {
    pub(crate) fn describe(&self) -> String {
        match self {
            NatKind::Unknown => "not known yet (no direct path to a node outside this network so far)".into(),
            NatKind::Public => "public address (no NAT) - other nodes can reach this one directly".into(),
            NatKind::OneObservation => "behind NAT (one observation so far)".into(),
            NatKind::KeepsPort { .. } => {
                "behind NAT that keeps one port for every destination - direct paths through NAT work".into()
            }
            NatKind::ChangesPort => "behind NAT that changes the port per destination (typical for mobile \
                                     networks) - direct IPv4 paths only to nodes that are reachable from outside"
                .into(),
        }
    }
}

/// Which path to keep when several work: the LAN, then IPv6, then IPv4 through NATs.
fn path_rank(a: &SocketAddr) -> u8 {
    match a.ip() {
        IpAddr::V4(ip) if ip.is_private() || ip.is_link_local() => 0,
        IpAddr::V6(_) => 1,
        IpAddr::V4(_) => 2,
    }
}

/// The IPv6 socket, on the IPv4 socket's port (IPv6 only, so the two don't collide).
/// Opened even without an IPv6 address yet: notebooks change networks.
pub(super) async fn bind6(v4: Option<&Arc<UdpSocket>>) -> Option<Arc<UdpSocket>> {
    let port = v4?.local_addr().ok()?.port();
    let s = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    s.set_only_v6(true).ok()?;
    s.set_nonblocking(true).ok()?;
    let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port);
    if s.bind(&addr.into()).is_err() && s.bind(&SocketAddr::new(addr.ip(), 0).into()).is_err() {
        return None;
    }
    super::exit::mark(&s);
    UdpSocket::from_std(s.into()).ok().map(Arc::new)
}

/// The UDP socket: the listen port if free, a random one otherwise.
pub(super) async fn bind(cfg: &Config) -> Option<Arc<UdpSocket>> {
    if !cfg.udp || cfg.no_outbound || cfg.effective_socks().is_some() {
        return None; // behind an SSH tunnel or proxy there is no UDP way out
    }
    let port = cfg.listen_port().unwrap_or(0);
    let sock = match UdpSocket::bind(("0.0.0.0", port)).await {
        Ok(s) => s,
        Err(_) => UdpSocket::bind(("0.0.0.0", 0)).await.ok()?,
    };
    super::exit::mark(&sock);
    Some(Arc::new(sock))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_kinds() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let local = ["192.168.1.5".parse().unwrap()];
        assert_eq!(nat_kind(&[], &local, 7870), NatKind::Unknown);
        assert_eq!(nat_kind(&[a("192.168.1.5:7870")], &local, 7870), NatKind::Public);
        assert_eq!(nat_kind(&[a("80.1.2.3:7870")], &local, 7870), NatKind::OneObservation);
        assert_eq!(
            nat_kind(&[a("80.1.2.3:7870"), a("80.1.2.3:7870")], &local, 7870),
            NatKind::KeepsPort { preserved: true }
        );
        assert_eq!(
            nat_kind(&[a("80.1.2.3:40001"), a("80.1.2.3:51234")], &local, 7870),
            NatKind::ChangesPort
        );
        assert!(path_rank(&a("192.168.1.9:7870")) < path_rank(&a("[2001:db8::1]:7870")));
        assert!(path_rank(&a("[2001:db8::1]:7870")) < path_rank(&a("80.1.2.3:7870")));
    }

    #[test]
    fn candidates_include_port_guesses() {
        let info = NodeInfo {
            id: crate::keys::Key32([1; 32]),
            noise_pub: crate::keys::Key32([2; 32]),
            name: "a".into(),
            endpoints: vec!["203.0.113.9:7870".into()],
            neighbors: vec![],
            seq: 1,
            net: String::new(),
            version: String::new(),
            ssh_keys: vec![],
            tags: vec![],
            inventory: None,
            lan: vec![],
            perf: vec![],
            udp: vec!["192.168.10.3:7870".into(), "198.51.100.2:18972".into()],
            udp6: vec![],
            measured: 0,
            objects: vec![],
            leases: vec![],
            ssh_host_key: None,
            login_user: None,
            exit: false,
        };
        let c: Vec<String> = Node::peer_candidates(&info).iter().map(|a| a.to_string()).collect();
        assert!(c.contains(&"192.168.10.3:7870".to_string()));
        assert!(c.contains(&"198.51.100.2:18972".to_string()), "reflexive address");
        assert!(c.contains(&"198.51.100.2:7870".to_string()), "port guess: {c:?}");
        assert!(c.contains(&"203.0.113.9:7870".to_string()), "endpoint host: {c:?}");
    }
}
