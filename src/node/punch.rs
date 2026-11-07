//! Hole punching over IPv6: two nodes that can't accept connections (a home router without a
//! port forward, a mobile network) connect to each other directly.
//!
//! IPv6 has no NAT on the way, only stateful firewalls that let answers in. So both nodes send
//! to each other's IPv6 address at the same time, from a fixed port: each one's outgoing packet
//! opens its own firewall for the other's.
//! * UDP: probes towards nodes that are offline too (not only towards online ones, as before),
//!   which gives the direct data path.
//! * TCP: a connect from our port to theirs, again and again; when both connects cross, TCP's
//!   simultaneous open makes one connection out of them - the link for records and control.
//!   Both ends get it from connect(), so the Noise roles go by node id (the lower one starts).
//!
//! The addresses come from the rendezvous (each node puts its temporary IPv6 addresses into its
//! DHT entry: they change daily, so they don't identify the machine) and, while they still
//! hold, from the node's saved record. Only for nodes heard of in the last day, so nobody gets
//! packets for long after a node is gone; after the first quarter of an hour without success
//! only in the first minute of every five (by the clock, so both sides try at the same time).
//! Off with `punch = false`.

use super::*;

/// One connect attempt (SYNs at 0, 1, 3 and 7 s).
const ATTEMPT: Duration = Duration::from_secs(10);
/// A punching run towards one node, then the next round decides again.
const RUN: Duration = Duration::from_secs(60);
/// Nodes heard of this recently are tried with the addresses in their records.
const RECORD_FRESH_MS: u64 = 86_400_000;
/// Punching runs at a time.
const MAX_RUNS: usize = 8;
/// Addresses from the rendezvous count this long.
pub(super) const PUNCH_HINT_TTL: Duration = Duration::from_secs(2 * 3600);
/// Tried all the time for this long, then only in the first minute of every five.
const EAGER: Duration = Duration::from_secs(15 * 60);
const SLOT_SECS: u64 = 300;
const WINDOW_SECS: u64 = 60;

/// Is now a time to try? `tried_for`: how long we have been trying (None: not yet).
fn in_window(tried_for: Option<Duration>, unix_secs: u64) -> bool {
    tried_for.is_none_or(|d| d < EAGER) || unix_secs % SLOT_SECS < WINDOW_SECS
}

fn unix_secs() -> u64 {
    now_ms() / 1000
}

fn global(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xe000 == 0x2000
}

impl Node {
    /// Our port for hole punching: the listen port (TCP and UDP use the same number).
    pub(super) fn punch_port(&self) -> u16 {
        self.cfg.listen_port().unwrap_or(crate::config::DEFAULT_PORT)
    }

    pub(super) fn punch_enabled(&self) -> bool {
        self.cfg.punch && !self.cfg.no_outbound && self.cfg.effective_socks().is_none()
    }

    /// Our IPv6 addresses for the rendezvous entry: the temporary ones only (the stable address
    /// would let anyone with the network key follow the machine around).
    pub(super) fn punch_candidates(&self) -> Vec<String> {
        if !self.punch_enabled() {
            return vec![];
        }
        let port = self.punch_port();
        crate::sys::temporary_ipv6()
            .into_iter()
            .take(4)
            .map(|ip| SocketAddr::new(IpAddr::V6(ip), port).to_string())
            .collect()
    }

    /// Where to punch towards an offline node: its addresses from the rendezvous, else from its
    /// record (if heard of lately).
    pub(super) fn punch_targets(&self, st: &State, id: &NodeId) -> Vec<SocketAddr> {
        if *id == self.ident.id || st.banned.contains_key(id) || !self.punch_enabled() {
            return vec![];
        }
        if !in_window(st.punch_since.get(id).map(|t| t.elapsed()), unix_secs()) {
            return vec![];
        }
        let mut out: Vec<SocketAddr> = st
            .punch_hints
            .get(id)
            .filter(|(_, at)| at.elapsed() < PUNCH_HINT_TTL)
            .map(|(a, _)| a.clone())
            .unwrap_or_default();
        if let Some(r) = st.records.get(id)
            && now_ms().saturating_sub(r.info.seq) < RECORD_FRESH_MS
        {
            for c in &r.info.udp6 {
                if let Ok(a) = c.parse::<SocketAddr>()
                    && !out.contains(&a)
                {
                    out.push(a);
                }
            }
        }
        out.retain(|a| matches!(a.ip(), IpAddr::V6(ip) if global(&ip)));
        out.truncate(6);
        out
    }

    /// Starts punching runs towards nodes we have no link to (every few seconds).
    pub(super) async fn punch_loop(self: Arc<Self>) {
        if !self.punch_enabled() {
            return;
        }
        let running: Arc<Mutex<HashSet<NodeId>>> = Arc::default();
        // The links from the known addresses come first.
        tokio::time::sleep(Duration::from_secs(10)).await;
        loop {
            if crate::sys::global_ipv6().is_empty() || self.leaving.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
            let due: Vec<(NodeId, Vec<SocketAddr>)> = {
                let mut st = self.state.lock().unwrap();
                // Since when we try each node: reset once there is a link.
                let linked: Vec<NodeId> = st.links.keys().copied().collect();
                st.punch_since.retain(|id, _| !linked.contains(id));
                let busy = running.lock().unwrap();
                let due: Vec<(NodeId, Vec<SocketAddr>)> = st
                    .records
                    .keys()
                    .filter(|id| !st.links.contains_key(*id) && !busy.contains(*id))
                    .map(|id| (*id, self.punch_targets(&st, id)))
                    .filter(|(_, t)| !t.is_empty())
                    .take(MAX_RUNS.saturating_sub(busy.len()))
                    .collect();
                for (id, _) in &due {
                    st.punch_since.entry(*id).or_insert_with(Instant::now);
                }
                due
            };
            for (id, targets) in due {
                running.lock().unwrap().insert(id);
                let node = self.clone();
                let running = running.clone();
                tokio::spawn(async move {
                    node.punch_run(id, targets).await;
                    running.lock().unwrap().remove(&id);
                });
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    fn linked(&self, id: &NodeId) -> bool {
        self.state.lock().unwrap().links.contains_key(id)
    }

    /// Connect attempts towards `id` from our port, until a link is up or the run is over.
    async fn punch_run(self: &Arc<Self>, id: NodeId, targets: Vec<SocketAddr>) {
        let started = Instant::now();
        let port = self.punch_port();
        while started.elapsed() < RUN && !self.linked(&id) && !self.leaving.load(Ordering::Relaxed) {
            for target in &targets {
                let Some(stream) = self.punch_connect(*target, port).await else {
                    continue;
                };
                if self.linked(&id) {
                    return;
                }
                // Both ends got this connection from connect(): the lower id starts the handshake.
                let initiator = self.ident.id < id;
                match self.establish(stream, initiator, target.to_string()).await {
                    Ok(est) => {
                        let name = self.state.lock().unwrap().records.get(&id).map(|r| r.info.name.clone());
                        info!(
                            "hole punching: TCP link to {} via {target}",
                            name.unwrap_or_else(|| id.short())
                        );
                        self.clone().serve(est).await;
                        return;
                    }
                    Err(e) => debug!("hole punching: {target}: {e:#}"),
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// One connect from our fixed port (so the other side knows where to send).
    async fn punch_connect(&self, target: SocketAddr, port: u16) -> Option<TcpStream> {
        // The address the system sends from towards the target (bound explicitly: [::]:port
        // would clash with a listener on 0.0.0.0:port).
        let local = {
            let probe = std::net::UdpSocket::bind("[::]:0").ok()?;
            probe.connect(target).ok()?;
            probe.local_addr().ok()?.ip()
        };
        let s = tokio::net::TcpSocket::new_v6().ok()?;
        s.set_reuseaddr(true).ok()?;
        #[cfg(unix)]
        s.set_reuseport(true).ok()?;
        exit::mark(&s);
        if let Err(e) = s.bind(SocketAddr::new(local, port)) {
            debug!("hole punching: cannot use port {port}: {e}");
            return None;
        }
        match tokio::time::timeout(ATTEMPT, s.connect(target)).await {
            Ok(Ok(stream)) => Some(stream),
            Ok(Err(e)) => {
                debug!("hole punching: {target}: {e}");
                // Refused (the other side isn't trying right now): don't hammer.
                tokio::time::sleep(Duration::from_secs(2)).await;
                None
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tries_eagerly_then_in_shared_windows() {
        let min = |m: u64| Some(Duration::from_secs(m * 60));
        let slot = 300 * 3334; // the start of a five-minute slot (unix seconds)
        assert!(in_window(None, slot + 123), "not tried yet: now");
        assert!(in_window(min(14), slot + 123), "the first quarter of an hour: always");
        // Then by the clock: the first minute of every five, the same on both sides.
        assert!(in_window(min(20), slot));
        assert!(in_window(min(20), slot + 59));
        assert!(!in_window(min(20), slot + 60));
        assert!(!in_window(min(20), slot + 299));
        assert!(in_window(min(20), slot + 300));
    }

    #[test]
    fn only_global_ipv6() {
        assert!(global(&"2a02:3100:41d1:8400::1".parse().unwrap()));
        assert!(global(&"2001:db8:78::5".parse().unwrap()));
        assert!(
            !global(&"fd0c:a96b:1e62::1".parse().unwrap()),
            "unique local (the mesh's own)"
        );
        assert!(!global(&"fe80::1".parse().unwrap()));
        assert!(!global(&"::1".parse().unwrap()));
    }
}
