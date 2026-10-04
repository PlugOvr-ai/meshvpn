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
//!   ack    A2 | src id 32 | dst id 32 | timestamp 8 | nonce 8 | seen-as ip 4 + port 2 | mac 16
//!   data   A3 | src id prefix 8 | nonce 24 | XChaCha20-Poly1305(packet)   (49 bytes overhead)

use super::*;
use std::net::SocketAddrV4;
use tokio::net::UdpSocket;

const PROBE: u8 = 0xA1;
const ACK: u8 = 0xA2;
const DATA: u8 = 0xA3;
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
}

impl UdpPath {
    /// Good for data: heard recently, and not ignoring our checks.
    pub fn usable(&self) -> bool {
        self.last_rx.elapsed() < Duration::from_secs(15) && self.unanswered < 4
    }
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
        seen: Option<SocketAddrV4>,
        key: &[u8; 32],
    ) -> Vec<u8> {
        let mut d = Vec::with_capacity(103);
        d.push(kind);
        d.extend_from_slice(&self.ident.id.0);
        d.extend_from_slice(&dst.0);
        d.extend_from_slice(&ts.to_be_bytes());
        d.extend_from_slice(&nonce.to_be_bytes());
        if let Some(s) = seen {
            d.extend_from_slice(&s.ip().octets());
            d.extend_from_slice(&s.port().to_be_bytes());
        }
        let m = mac(key, &d);
        d.extend_from_slice(&m);
        d
    }

    /// Sends probes: keepalives on live paths, punching attempts towards the others.
    pub(super) fn udp_probe_round(&self) {
        let Some(sock) = &self.udp else { return };
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
                let _ = sock.try_send_to(&d, t);
            }
        }
    }

    /// Sends `pkt` straight to `dst` if a UDP path is up. Returns false if not.
    pub(super) fn udp_send(&self, dst: &NodeId, cipher: &XChaCha20Poly1305, pkt: &[u8]) -> bool {
        let Some(sock) = &self.udp else { return false };
        let addr = {
            let mut st = self.state.lock().unwrap();
            let key = self.probe_key(&mut st, dst);
            let Some(p) = st.udp_paths.get_mut(dst).filter(|p| p.usable()) else {
                return false;
            };
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
                let _ = sock.try_send_to(&probe, addr);
            }
            p.addr
        };
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let Ok(ct) = cipher.encrypt(&XNonce::from(nonce), pkt) else {
            return false;
        };
        let mut d = Vec::with_capacity(33 + ct.len());
        d.push(DATA);
        d.extend_from_slice(&self.ident.id.0[..8]);
        d.extend_from_slice(&nonce);
        d.extend_from_slice(&ct);
        // A full socket buffer drops the packet, like a congested link would.
        let _ = sock.try_send_to(&d, addr);
        true
    }

    pub(super) async fn udp_loop(self: Arc<Self>) {
        let Some(sock) = self.udp.clone() else { return };
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
                _ => {}
            }
        }
    }

    fn udp_control(&self, sock: &UdpSocket, d: &[u8], from: SocketAddr) {
        let ack = d[0] == ACK;
        let len = if ack { 103 } else { 97 };
        if d.len() != len {
            return;
        }
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
            let seen = match from {
                SocketAddr::V4(v4) => Some(v4),
                _ => None,
            };
            let reply = self.probe_datagram(ACK, &src, ts, nonce, seen, &key);
            let _ = sock.try_send_to(&reply, from);
            // Answer with a probe of our own right away: this opens our NAT towards them.
            if !st.udp_paths.contains_key(&src) {
                let p = self.probe_datagram(PROBE, &src, now_ms(), rand::rngs::OsRng.next_u64(), None, &key);
                let _ = sock.try_send_to(&p, from);
            }
            return;
        }
        // An answer to our probe: the path works in both directions.
        let rtt = Duration::from_millis(now_ms().saturating_sub(ts));
        let seen = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(d[81], d[82], d[83], d[84])),
            u16::from_be_bytes([d[85], d[86]]),
        );
        let fresh = !st.udp_paths.contains_key(&src);
        st.udp_paths.insert(
            src,
            UdpPath {
                addr: from,
                last_rx: Instant::now(),
                rtt: Some(rtt),
                last_probe: Instant::now(),
                unanswered: 0,
            },
        );
        st.udp_probing.remove(&src);
        if fresh {
            let name = st.records.get(&src).map(|r| r.info.name.clone()).unwrap_or_default();
            info!("direct UDP path to {name} ({src}) via {from}");
        }
        // Remember how the world sees us (our public address behind NAT).
        let local = crate::net::local_lans()
            .iter()
            .any(|(_, ip, _)| IpAddr::V4(*ip) == seen.ip());
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
        // Anti-spoofing: the inner source address must belong to the sender.
        if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[12..16] != overlay_ip(&src).octets() {
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
    Some(Arc::new(sock))
}

#[cfg(test)]
mod tests {
    use super::*;

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
            measured: 0,
            objects: vec![],
        };
        let c: Vec<String> = Node::peer_candidates(&info).iter().map(|a| a.to_string()).collect();
        assert!(c.contains(&"192.168.10.3:7870".to_string()));
        assert!(c.contains(&"198.51.100.2:18972".to_string()), "reflexive address");
        assert!(c.contains(&"198.51.100.2:7870".to_string()), "port guess: {c:?}");
        assert!(c.contains(&"203.0.113.9:7870".to_string()), "endpoint host: {c:?}");
    }
}
