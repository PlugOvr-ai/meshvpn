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
//!          (the nonce counts packets: each is taken once, see `replay`)
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
/// Probes this far behind the sender's newest (by its clock) are taken for replays.
const PROBE_REPLAY_MS: u64 = 120_000;
/// Unfinished split datagrams, in all and per sending address.
const MAX_FRAGS: usize = 256;
const MAX_FRAGS_PER_SOURCE: usize = 32;
/// An answer to a probe counts only this soon.
const PROBE_ANSWER_WITHIN: Duration = Duration::from_secs(10);

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
    from: SocketAddr,
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
        for (_, a, _) in &st.stun_mapped {
            out.push(a.to_string());
        }
        // A port opened on the router (see portmap).
        if let Some(m) = st.port_mapping.as_ref().filter(|m| m.public())
            && let Some(p) = m.external_port(crate::portmap::UDP)
        {
            out.push(SocketAddr::new(IpAddr::V4(m.external), p).to_string());
        }
        let mut seen = HashSet::new();
        out.retain(|c| seen.insert(c.clone()));
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
            // Not what STUN servers saw: they may be reached another way than the nodes (a VPN,
            // a second router), which would look like a NAT that changes ports.
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
    pub(super) fn peer_candidates(info: &NodeInfo) -> Vec<SocketAddr> {
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
        out.retain(|a| !is_overlay(a.ip()) && super::address_dialable(a.ip()));
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

    /// A nonce for a probe to `peer`, remembered so its answer can be told from a replayed one.
    fn probe_nonce(st: &mut State, peer: &NodeId) -> u64 {
        let n = rand::rngs::OsRng.next_u64();
        let sent = st.udp_probes_sent.entry(*peer).or_default();
        sent.retain(|(_, at)| at.elapsed() < PROBE_ANSWER_WITHIN);
        sent.push_back((n, Instant::now()));
        while sent.len() > 32 {
            sent.pop_front();
        }
        n
    }

    /// One probe to `peer` at `addr` (its answer is recorded in `udp_answered_from`).
    pub(super) fn udp_probe_to(&self, peer: &NodeId, addr: SocketAddr) {
        let mut st = self.state.lock().unwrap();
        let Some(key) = self.probe_key(&mut st, peer) else {
            return;
        };
        let n = Self::probe_nonce(&mut st, peer);
        let d = self.probe_datagram(PROBE, peer, now_ms(), n, None, &key);
        drop(st);
        self.udp_send(&d, addr);
    }

    /// Sends probes: keepalives on live paths, punching attempts towards the others.
    pub(super) fn udp_probe_round(&self) {
        if self.udp.is_none() {
            return;
        }
        let mut st = self.state.lock().unwrap();
        let now = Instant::now();
        st.udp_paths.retain(|_, p| p.last_rx.elapsed() < PATH_TIMEOUT);
        // Online nodes at all their candidates; offline ones at their IPv6 addresses (hole
        // punching: they may be doing the same towards us, see `punch`).
        let peers: Vec<(NodeId, Vec<SocketAddr>)> = st
            .records
            .values()
            .map(|r| {
                let id = r.info.id;
                if self.is_online(&st, &id) {
                    (id, Self::peer_candidates(&r.info))
                } else {
                    (id, self.punch_targets(&st, &id))
                }
            })
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
            if let Some(c) = st.why_counts.get_mut(&peer) {
                c.sent += targets.len() as u32;
            }
            let n = Self::probe_nonce(&mut st, &peer);
            let d = self.probe_datagram(PROBE, &peer, now_ms(), n, None, &key);
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
            let check = key.is_some()
                && p.last_rx.elapsed() > Duration::from_secs(3)
                && p.last_probe.elapsed() > Duration::from_secs(1);
            if check {
                p.last_probe = Instant::now();
                p.unanswered += 1;
            }
            let (addr, split) = (p.addr, p.splitting());
            if check && let Some(key) = key {
                let n = Self::probe_nonce(&mut st, dst);
                let probe = self.probe_datagram(PROBE, dst, now_ms(), n, None, &key);
                self.udp_send(&probe, addr);
            }
            (addr, split)
        };
        let (addr, split) = addr;
        let nonce = self.nonces.nonce();
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
    fn udp_frag(&self, d: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        if d.len() < 16 {
            return None;
        }
        let prefix: [u8; 8] = d[1..9].try_into().ok()?;
        let id = u32::from_be_bytes(d[9..13].try_into().ok()?);
        let (index, count) = (d[13] as usize, d[14] as usize);
        // Parts are cut to fit SAFE_DATAGRAM: anything bigger isn't one of ours, and holding
        // it would let anyone who knows a node's id prefix fill memory.
        if !(2..=8).contains(&count) || index >= count || d.len() > SAFE_DATAGRAM {
            return None;
        }
        let mut st = self.state.lock().unwrap();
        st.id_prefix.get(&prefix)?; // only known nodes (the data is authenticated as a whole)
        // The id prefix is no secret, so anyone can send parts in a node's name. Parts from a
        // node's current UDP path come first: others can't crowd them out.
        let on_path = st.udp_paths.values().any(|p| p.addr == from);
        if !st.udp_frags.contains_key(&(prefix, id)) {
            let from_here = st.udp_frags.values().filter(|r| r.from == from).count();
            let in_name = || {
                st.udp_frags
                    .iter()
                    .filter(|((p, _), r)| *p == prefix && !st.udp_paths.values().any(|u| u.addr == r.from))
                    .count()
            };
            if from_here >= MAX_FRAGS_PER_SOURCE || (!on_path && in_name() >= MAX_FRAGS_PER_SOURCE) {
                return None;
            }
            if st.udp_frags.len() >= MAX_FRAGS {
                st.udp_frags.retain(|_, r| r.started.elapsed() < Duration::from_secs(2));
            }
            if st.udp_frags.len() >= MAX_FRAGS {
                if !on_path {
                    return None;
                }
                // Make room: the oldest one not from a path.
                let paths: Vec<SocketAddr> = st.udp_paths.values().map(|p| p.addr).collect();
                let victim = st
                    .udp_frags
                    .iter()
                    .filter(|(_, r)| !paths.contains(&r.from))
                    .min_by_key(|(_, r)| r.started)
                    .map(|(k, _)| *k)?;
                st.udp_frags.remove(&victim);
            }
        }
        let r = st.udp_frags.entry((prefix, id)).or_insert_with(|| Reassembly {
            started: Instant::now(),
            from,
            parts: vec![None; count],
        });
        // Parts of one datagram come from one place.
        if r.parts.len() != count || r.from != from {
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
                    if let Some(whole) = self.udp_frag(d, from)
                        && whole.first() == Some(&DATA)
                        && let Some(pkt) = self.udp_data(&whole, from)
                    {
                        self.deliver(pkt).await;
                    }
                }
                Some(&0x01) => self.stun_answer(d, from),
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
        if let Some(c) = st.why_counts.get_mut(&src) {
            if ack {
                c.answers += 1;
            } else {
                c.heard += 1;
            }
        }
        if !ack {
            // A recorded probe sent again (from anywhere) gets no answer: answers to a forged
            // source would make us send packets at someone else. The sender's timestamps only
            // go up (by its own clock); a probe more than two minutes behind its newest, or seen
            // before, is a replay.
            let seen = st.udp_probes_seen.entry(src).or_default();
            if ts.saturating_add(PROBE_REPLAY_MS) < seen.0 || seen.1.contains(&nonce) {
                return;
            }
            seen.0 = seen.0.max(ts);
            seen.1.push_back(nonce);
            while seen.1.len() > 256 {
                seen.1.pop_front();
            }
            // The MAC proves the sender. The timestamp is only echoed back for the RTT, so
            // clocks that differ between machines don't matter.
            let reply = self.probe_datagram(ACK, &src, ts, nonce, Some(from), &key);
            let _ = sock.try_send_to(&reply, from);
            // Answer with a probe of our own right away: this opens our NAT towards them.
            if !st.udp_paths.contains_key(&src) {
                let n = Self::probe_nonce(&mut st, &src);
                let p = self.probe_datagram(PROBE, &src, now_ms(), n, None, &key);
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
        // Only an answer to a probe we sent lately, and only once: a recorded answer sent
        // again (from anywhere) must not create or move a path.
        let Some(sent) = st.udp_probes_sent.get_mut(&src) else {
            return;
        };
        let Some(i) = sent
            .iter()
            .position(|(n, at)| *n == nonce && at.elapsed() < PROBE_ANSWER_WITHIN)
        else {
            return;
        };
        sent.remove(i);
        let heard = st.udp_answered_from.entry(src).or_default();
        heard.retain(|(a, at)| *a != from.ip() && at.elapsed() < Duration::from_secs(120));
        heard.push((from.ip(), Instant::now()));
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
        // Each packet once: a copy sent again from elsewhere must not move the path there.
        let verdict = self.replayed(&src, &nonce);
        if verdict == super::replay::Verdict::Replay {
            return None;
        }
        // Authentic and new: the path is alive, and follows the peer if its NAT mapping changed
        // (only for its newest packet; nodes without counters as before).
        let mut st = self.state.lock().unwrap();
        if let Some(p) = st.udp_paths.get_mut(&src) {
            p.last_rx = Instant::now();
            p.unanswered = 0;
            if verdict != super::replay::Verdict::Late {
                p.addr = from;
            }
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
    /// For `meshvpn net why`, from either side.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            NatKind::Unknown => "unknown",
            NatKind::Public => "public",
            NatKind::OneObservation | NatKind::KeepsPort { .. } => "keeps-port",
            NatKind::ChangesPort => "changes-port",
        }
    }

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

// ----------------------------------------------------------------------------- STUN

/// RFC 5389: binding request/success, the magic cookie, XOR-MAPPED-ADDRESS and MAPPED-ADDRESS.
const STUN_REQUEST: u16 = 0x0001;
const STUN_SUCCESS: u16 = 0x0101;
const STUN_COOKIE: u32 = 0x2112_A442;
/// How often it is checked whether STUN is needed (only while no node tells us our address).
const STUN_EVERY: Duration = Duration::from_secs(300);
/// What a STUN server said counts this long (the address may change).
const STUN_VALID: Duration = Duration::from_secs(1800);
/// Other nodes saw our UDP address this recently: no need to ask a STUN server.
const SEEN_RECENTLY: Duration = Duration::from_secs(600);

pub(super) fn stun_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut r = [0u8; 20];
    r[..2].copy_from_slice(&STUN_REQUEST.to_be_bytes());
    r[4..8].copy_from_slice(&STUN_COOKIE.to_be_bytes());
    r[8..20].copy_from_slice(txid);
    r
}

/// The address a binding success for `txid` reports (IPv4 only: the socket is IPv4).
pub(super) fn stun_parse(d: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if d.len() < 20
        || u16::from_be_bytes([d[0], d[1]]) != STUN_SUCCESS
        || u32::from_be_bytes(d[4..8].try_into().unwrap()) != STUN_COOKIE
        || &d[8..20] != txid
    {
        return None;
    }
    let len = (u16::from_be_bytes([d[2], d[3]]) as usize).min(d.len() - 20);
    let mut attrs = &d[20..20 + len];
    let mut plain = None;
    while attrs.len() >= 4 {
        let ty = u16::from_be_bytes([attrs[0], attrs[1]]);
        let n = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        let Some(v) = attrs.get(4..4 + n) else { break };
        // Family 1 = IPv4: 0, family, port, address.
        if v.len() >= 8 && v[1] == 1 {
            let port = u16::from_be_bytes([v[2], v[3]]);
            let ip = Ipv4Addr::new(v[4], v[5], v[6], v[7]);
            match ty {
                0x0020 => {
                    let c = STUN_COOKIE.to_be_bytes();
                    let port = port ^ (STUN_COOKIE >> 16) as u16;
                    let ip = Ipv4Addr::new(v[4] ^ c[0], v[5] ^ c[1], v[6] ^ c[2], v[7] ^ c[3]);
                    return Some(SocketAddr::new(IpAddr::V4(ip), port));
                }
                0x0001 => plain = Some(SocketAddr::new(IpAddr::V4(ip), port)),
                _ => {}
            }
        }
        attrs = attrs.get(4 + n.div_ceil(4) * 4..).unwrap_or(&[]);
    }
    plain
}

impl Node {
    /// Asks the STUN servers for our public UDP address while no other node tells us (none is
    /// connected, or none answers over UDP): after a new address from the provider, say, so
    /// this node's record and its rendezvous entry name the right address. Not more than
    /// needed: each request tells the server's operator that this address runs meshvpn.
    pub(super) async fn stun_loop(self: Arc<Self>) {
        let Some(sock) = self.udp.clone() else { return };
        if self.cfg.stun.is_empty() {
            return;
        }
        // The first links usually tell us within seconds: no request at every start.
        tokio::time::sleep(Duration::from_secs(30)).await;
        loop {
            let needed = {
                let mut st = self.state.lock().unwrap();
                st.stun_mapped.retain(|(_, _, at)| at.elapsed() < STUN_VALID);
                st.links.is_empty() || !st.udp_seen.values().any(|(_, at)| at.elapsed() < SEEN_RECENTLY)
            };
            if !needed {
                tokio::time::sleep(STUN_EVERY).await;
                continue;
            }
            let mut servers: Vec<SocketAddr> = vec![];
            for s in &self.cfg.stun {
                if let Ok(Ok(addrs)) = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(s)).await
                    && let Some(a) = addrs.filter(|a| a.is_ipv4()).find(|a| address_dialable(a.ip()))
                {
                    servers.push(a);
                }
            }
            {
                let mut st = self.state.lock().unwrap();
                st.stun_pending
                    .retain(|(_, _, at)| at.elapsed() < Duration::from_secs(30));
                for server in &servers {
                    let txid: [u8; 12] = crate::keys::random32()[..12].try_into().unwrap();
                    st.stun_pending.push((txid, *server, Instant::now()));
                    let _ = sock.try_send_to(&stun_request(&txid), *server);
                }
            }
            tokio::time::sleep(STUN_EVERY).await;
        }
    }

    fn stun_answer(&self, d: &[u8], from: SocketAddr) {
        let mut st = self.state.lock().unwrap();
        // Only an answer to a request of ours, from the server we asked.
        let Some(i) = st
            .stun_pending
            .iter()
            .position(|(txid, server, _)| *server == from && stun_parse(d, txid).is_some())
        else {
            return;
        };
        let (txid, server, _) = st.stun_pending.remove(i);
        let Some(mapped) = stun_parse(d, &txid) else { return };
        if is_overlay(mapped.ip()) || !address_dialable(mapped.ip()) {
            return;
        }
        st.stun_mapped.retain(|(s, _, _)| *s != server);
        st.stun_mapped.insert(0, (server, mapped, Instant::now()));
        st.stun_mapped.truncate(2);
    }
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
    fn stun_answers() {
        let txid = [3u8; 12];
        let req = stun_request(&txid);
        assert_eq!(&req[..2], &[0, 1]);
        // A binding success with XOR-MAPPED-ADDRESS 2.243.3.46:61000 (as Google's servers send).
        let mut ans = vec![0x01, 0x01, 0, 12];
        ans.extend_from_slice(&STUN_COOKIE.to_be_bytes());
        ans.extend_from_slice(&txid);
        let c = STUN_COOKIE.to_be_bytes();
        let port = 61000u16 ^ (STUN_COOKIE >> 16) as u16;
        ans.extend_from_slice(&[0x00, 0x20, 0, 8, 0, 1]);
        ans.extend_from_slice(&port.to_be_bytes());
        ans.extend_from_slice(&[2 ^ c[0], 243 ^ c[1], 3 ^ c[2], 46 ^ c[3]]);
        assert_eq!(stun_parse(&ans, &txid), Some("2.243.3.46:61000".parse().unwrap()));
        assert_eq!(stun_parse(&ans, &[4u8; 12]), None, "another transaction");
        // MAPPED-ADDRESS only (old servers).
        let mut old = ans[..20].to_vec();
        old.extend_from_slice(&[0x00, 0x01, 0, 8, 0, 1, 0x1f, 0x90, 80, 1, 2, 3]);
        assert_eq!(stun_parse(&old, &txid), Some("80.1.2.3:8080".parse().unwrap()));
        assert_eq!(stun_parse(&ans[..19], &txid), None);
    }

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
            ipv6: false,
            digest: false,
            links: 0,
            split: false,
            details: 0,
        };
        let c: Vec<String> = Node::peer_candidates(&info).iter().map(|a| a.to_string()).collect();
        assert!(c.contains(&"192.168.10.3:7870".to_string()));
        assert!(c.contains(&"198.51.100.2:18972".to_string()), "reflexive address");
        assert!(c.contains(&"198.51.100.2:7870".to_string()), "port guess: {c:?}");
        assert!(c.contains(&"203.0.113.9:7870".to_string()), "endpoint host: {c:?}");
    }
}
