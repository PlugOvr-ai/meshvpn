//! Rendezvous through BitTorrent's Mainline DHT: nodes find each other again after their
//! addresses changed (a new IP from the provider every night, a notebook outside the company
//! network), without a server of anyone's and without DynDNS.
//!
//! A node others can connect to puts its current endpoints into the DHT (BEP 44 mutable item),
//! and a node that lost a peer looks them up. The entry:
//! * is stored under a key and salt derived from the network key, the node's id and the day
//!   (UTC): only members find it, and the location changes daily, so DHT nodes can't follow a
//!   node across days;
//! * is encrypted with a key derived from the network key (XChaCha20-Poly1305): the DHT sees
//!   noise;
//! * is signed by the node itself and dated: members can't forge one another's entries, and an
//!   old one is ignored. After a ban the key rotates, so the banned node learns nothing new.
//!
//! The DHT runs as a client only (it never answers other people's queries) and starts the first
//! time it is needed. Off by default (`dht = true` in the config switches it on: firewalls in
//! company networks may take the traffic for BitTorrent); never through a proxy or SSH tunnel,
//! which have no way out for UDP.

use super::*;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use mainline::async_dht::AsyncDht;
use mainline::{Dht, MutableItem, RequestFilter, RequestSpecific, ServerSettings, SigningKey};

/// Entries are put again this often (DHT nodes drop them after about two hours).
const PUBLISH_EVERY: Duration = Duration::from_secs(30 * 60);
/// How often a node that is gone is looked up: soon while we have no link at all, or it is
/// gone only lately.
const LOOKUP_EVERY: Duration = Duration::from_secs(10 * 60);
const LOOKUP_ALONE: Duration = Duration::from_secs(2 * 60);
/// Nodes not heard of for a day are looked up rarely.
const LOOKUP_STALE: Duration = Duration::from_secs(60 * 60);
/// Lookups at a time.
const LOOKUPS_PER_ROUND: usize = 4;
/// An entry older than this is ignored.
/// (Entries are put again every half hour: an old one is from a node that moved or is gone, and
/// one found then would only send the others to an address that no longer holds.)
const MAX_AGE_MS: u64 = 75 * 60 * 1000;
/// An entry stored at fewer DHT nodes is put again soon.
const MIN_STORED: u32 = 8;
/// Addresses found are tried for this long.
pub(super) const HINT_TTL: Duration = Duration::from_secs(2 * 3600);
/// BEP 44 values are at most 1000 bytes.
const MAX_VALUE: usize = 1000;
const MAX_ENDPOINTS: usize = 6;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Entry {
    id: NodeId,
    net: String,
    at: u64,
    /// Where the node accepts connections.
    ep: Vec<String>,
    /// Its IPv6 addresses for hole punching (also of nodes nobody can connect to).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    v6: Vec<String>,
}

/// What an entry says.
#[derive(Debug, PartialEq, Default, Clone)]
pub(super) struct Found {
    pub ep: Vec<String>,
    pub v6: Vec<SocketAddr>,
    /// When the node made the entry (ms).
    pub at: u64,
}

fn day(now_ms: u64) -> u64 {
    now_ms / 86_400_000
}

fn derive(context: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(context);
    for p in parts {
        h.update(&(p.len() as u32).to_be_bytes());
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// The DHT key pair of a network for a day: every member can work it out, nobody else.
fn signing_key(net_key: &[u8; 32], day: u64) -> SigningKey {
    SigningKey::from_bytes(&derive("meshvpn rendezvous v1 key", &[net_key, &day.to_be_bytes()]))
}

/// Where one node's entry is (the salt, under the network's key of the day).
fn salt(net_key: &[u8; 32], day: u64, id: &NodeId) -> [u8; 20] {
    derive("meshvpn rendezvous v1 salt", &[net_key, &day.to_be_bytes(), &id.0])[..20]
        .try_into()
        .unwrap()
}

fn cipher(net_key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&derive("meshvpn rendezvous v1 seal", &[net_key]).into())
}

/// The DHT value for our endpoints: nonce | sealed(signed entry). None if it doesn't fit.
fn seal(
    net_key: &[u8; 32],
    ident: &Identity,
    net: &str,
    at: u64,
    endpoints: &[String],
    v6: &[String],
) -> Option<Vec<u8>> {
    let mut ep: Vec<String> = endpoints.iter().take(MAX_ENDPOINTS).cloned().collect();
    let v6: Vec<String> = v6.iter().take(4).cloned().collect();
    loop {
        let entry = Entry {
            id: ident.id,
            net: net.to_string(),
            at,
            ep: ep.clone(),
            v6: v6.clone(),
        };
        let doc = serde_json::to_vec(&SignedDoc::sign(&entry, ident)).ok()?;
        let nonce: [u8; 24] = crate::keys::random32()[..24].try_into().unwrap();
        let mut out = nonce.to_vec();
        out.extend(cipher(net_key).encrypt(&XNonce::from(nonce), doc.as_slice()).ok()?);
        if out.len() <= MAX_VALUE {
            return Some(out);
        }
        ep.pop()?;
    }
}

/// What a DHT value says, if it is `id`'s entry for network `net` and recent.
fn open(net_key: &[u8; 32], value: &[u8], id: &NodeId, net: &str, now_ms: u64) -> Option<Found> {
    if value.len() < 24 + 16 {
        return None;
    }
    let (nonce, sealed) = value.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().ok()?;
    let doc = cipher(net_key).decrypt(&XNonce::from(nonce), sealed).ok()?;
    let doc: SignedDoc = serde_json::from_slice(&doc).ok()?;
    let entry: Entry = doc.open(|e: &Entry| e.id).ok()?;
    if entry.id != *id || entry.net != net {
        return None;
    }
    if entry.at + MAX_AGE_MS < now_ms || entry.at > now_ms + 5 * 60 * 1000 {
        return None;
    }
    let mut ep: Vec<String> = entry.ep.into_iter().filter(|e| dialable(e)).collect();
    ep.truncate(MAX_ENDPOINTS);
    let mut v6: Vec<SocketAddr> = entry
        .v6
        .iter()
        .filter_map(|a| a.parse::<SocketAddr>().ok())
        .filter(|a| matches!(a.ip(), IpAddr::V6(ip) if ip.segments()[0] & 0xe000 == 0x2000))
        .collect();
    v6.truncate(4);
    (!ep.is_empty() || !v6.is_empty()).then_some(Found { ep, v6, at: entry.at })
}

/// Never answer other people's DHT queries: this node only asks and stores its own entries.
#[derive(Debug, Clone)]
struct ClientOnly;

impl RequestFilter for ClientOnly {
    fn allow_request(&self, _: &RequestSpecific, _: std::net::SocketAddrV4) -> bool {
        false
    }
}

fn start_dht() -> std::io::Result<AsyncDht> {
    let settings = ServerSettings {
        filter: Box::new(ClientOnly),
        max_info_hashes: 0,
        max_peers_per_info_hash: 0,
        max_immutable_values: 0,
        max_mutable_values: 0,
    };
    Ok(Dht::builder().server_settings(settings).build()?.as_async())
}

fn ago(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m", secs / 60),
        _ => format!("{}h", secs / 3600),
    }
}

/// What `status` shows.
#[derive(Default, Clone)]
pub(super) struct RendezvousState {
    /// Endpoints published, when, for which day.
    published: Option<(Vec<String>, Instant, u64)>,
    publishing: bool,
    /// Last lookup per node.
    looked_up: HashMap<NodeId, Instant>,
    /// Lookups running.
    running: usize,
    /// The DHT couldn't be started or reached (last error).
    error: Option<String>,
    /// The last put: when, at how many DHT nodes, and whether a lookup of our own then found it
    /// (or still an older one: the entry didn't reach the nodes others ask).
    put_at: Option<Instant>,
    stored_at: u32,
    visible: Option<bool>,
}

impl Node {
    fn rendezvous_enabled(&self) -> bool {
        self.cfg.dht && !self.cfg.no_outbound && self.cfg.effective_socks().is_none()
    }

    fn current_key(st: &State) -> Option<[u8; 32]> {
        st.keys.get(&st.key_version).copied()
    }

    async fn dht(&self) -> Option<AsyncDht> {
        if let Some(d) = self.dht.lock().unwrap().clone() {
            return Some(d);
        }
        match tokio::task::spawn_blocking(start_dht).await {
            Ok(Ok(d)) => {
                // Queries before it has joined reach few nodes (an entry stored at one, say).
                if tokio::time::timeout(Duration::from_secs(30), d.bootstrapped()).await != Ok(true) {
                    self.state.lock().unwrap().rendezvous.error = Some("cannot reach the DHT".into());
                    return None;
                }
                info!("rendezvous: using the BitTorrent DHT to find nodes whose address changed");
                *self.dht.lock().unwrap() = Some(d.clone());
                Some(d)
            }
            Ok(Err(e)) => {
                self.state.lock().unwrap().rendezvous.error = Some(format!("cannot start the DHT: {e}"));
                None
            }
            Err(_) => None,
        }
    }

    pub(super) async fn rendezvous_loop(self: Arc<Self>) {
        if !self.rendezvous_enabled() {
            return;
        }
        // Let the first links come up: no need for the DHT if the known addresses still work.
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            self.rendezvous_round().await;
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    }

    async fn rendezvous_round(self: &Arc<Self>) {
        let now = now_ms();
        let (publish, lookups) = {
            let mut st = self.state.lock().unwrap();
            let Some(key) = Self::current_key(&st) else { return };
            // Endpoints if others can connect to us; IPv6 addresses for hole punching in any case.
            let endpoints = if self.cfg.listen.is_some() {
                st.my_endpoints.clone()
            } else {
                vec![]
            };
            let v6 = self.punch_candidates();
            let mut all = endpoints.clone();
            all.extend(v6.iter().cloned());
            let publish = !all.is_empty()
                && !st.rendezvous.publishing
                && st
                    .rendezvous
                    .published
                    .as_ref()
                    .is_none_or(|(ep, at, d)| *ep != all || at.elapsed() >= PUBLISH_EVERY || *d != day(now));
            let publish = publish.then_some((key, endpoints, v6, all));
            if publish.is_some() {
                st.rendezvous.publishing = true;
            }
            let alone = st.links.is_empty();
            let mut due: Vec<(NodeId, u64)> = st
                .records
                .values()
                .filter(|r| r.info.id != self.ident.id && !self.is_online(&st, &r.info.id))
                .filter(|r| !st.banned.contains_key(&r.info.id))
                .filter_map(|r| {
                    let stale = now.saturating_sub(r.info.seq) > 86_400_000;
                    // Just gone (hole punching runs all the time then): often, so both sides
                    // soon try each other's current addresses - also while other links are up.
                    let fresh = self
                        .offline_for(&st, &r.info.id)
                        .is_some_and(|d| d < super::punch::EAGER);
                    let every = if stale {
                        LOOKUP_STALE
                    } else if alone || fresh {
                        LOOKUP_ALONE
                    } else {
                        LOOKUP_EVERY
                    };
                    let last = st.rendezvous.looked_up.get(&r.info.id);
                    last.is_none_or(|t| t.elapsed() >= every)
                        .then(|| (r.info.id, last.map_or(0, |t| t.elapsed().as_secs())))
                })
                .collect();
            // Longest not looked up first.
            due.sort_by_key(|(_, waited)| std::cmp::Reverse(*waited));
            let room = LOOKUPS_PER_ROUND.saturating_sub(st.rendezvous.running);
            due.truncate(room);
            for (id, _) in &due {
                st.rendezvous.looked_up.insert(*id, Instant::now());
            }
            st.rendezvous.running += due.len();
            (publish, due.into_iter().map(|(id, _)| (id, key)).collect::<Vec<_>>())
        };
        if publish.is_none() && lookups.is_empty() {
            return;
        }
        let Some(dht) = self.dht().await else {
            let mut st = self.state.lock().unwrap();
            st.rendezvous.publishing = false;
            st.rendezvous.running = st.rendezvous.running.saturating_sub(lookups.len());
            return;
        };
        if let Some((key, endpoints, v6, all)) = publish {
            let node = self.clone();
            let dht = dht.clone();
            tokio::spawn(async move {
                let ok = node.rendezvous_publish(&dht, &key, &endpoints, &v6, now).await;
                // Look it up ourselves: does a lookup find this version, or still an older one?
                let visible = match ok {
                    Ok(_) => Some(node.rendezvous_readback(&dht, &key, now).await),
                    Err(_) => None,
                };
                let mut st = node.state.lock().unwrap();
                st.rendezvous.publishing = false;
                match ok {
                    Ok(stored) => {
                        st.rendezvous.put_at = Some(Instant::now());
                        st.rendezvous.stored_at = stored;
                        st.rendezvous.visible = visible;
                        if visible == Some(false) {
                            info!(
                                "rendezvous: published, but a lookup still finds an older entry - again in 2 minutes"
                            );
                        }
                        // Stored at few nodes or not found: again soon, not in half an hour.
                        let at = if stored < MIN_STORED || visible == Some(false) {
                            Instant::now().checked_sub(PUBLISH_EVERY - Duration::from_secs(120))
                        } else {
                            None
                        };
                        st.rendezvous.published = Some((all, at.unwrap_or_else(Instant::now), day(now)));
                        st.rendezvous.error = None;
                    }
                    Err(e) => {
                        debug!("rendezvous: publishing failed: {e:#}");
                        st.rendezvous.error = Some(format!("{e:#}"));
                    }
                }
            });
        }
        for (id, key) in lookups {
            let node = self.clone();
            let dht = dht.clone();
            tokio::spawn(async move {
                let found = node.rendezvous_lookup(&dht, &key, &id).await;
                let mut st = node.state.lock().unwrap();
                st.rendezvous.running = st.rendezvous.running.saturating_sub(1);
                if let Some(found) = found {
                    let name = st.records.get(&id).map(|r| r.info.name.clone()).unwrap_or_default();
                    let known = st.dht_hints.get(&id).is_some_and(|(e, _)| *e == found.ep)
                        && st.punch_hints.get(&id).is_some_and(|(v, _, _)| *v == found.v6);
                    if !known {
                        let mut all = found.ep.clone();
                        all.extend(found.v6.iter().map(|a| a.to_string()));
                        info!("rendezvous: {name} ({id}) is at {}", all.join(", "));
                    }
                    if !found.ep.is_empty() {
                        st.dht_hints.insert(id, (found.ep, Instant::now()));
                    }
                    if !found.v6.is_empty() {
                        st.punch_hints.insert(id, (found.v6, Instant::now(), found.at));
                    }
                    // Try the new address now, not at the next backoff step.
                    st.backoff.remove(&id.hex());
                    drop(st);
                    node.dial_now();
                }
            });
        }
    }

    /// Puts our entry; how many DHT nodes stored it.
    async fn rendezvous_publish(
        &self,
        dht: &AsyncDht,
        key: &[u8; 32],
        endpoints: &[String],
        v6: &[String],
        now: u64,
    ) -> Result<u32> {
        let value = seal(key, &self.ident, &self.net, now, endpoints, v6).context("entry too large")?;
        let d = day(now);
        let salt = salt(key, d, &self.ident.id);
        let item = MutableItem::new(signing_key(key, d), &value, (now / 1000) as i64, Some(&salt));
        let out = dht.put_mutable(item, None).await.map_err(|e| anyhow!("{e}"))?;
        debug!(
            "rendezvous: published {} {} (stored at {} nodes)",
            endpoints.join(", "),
            v6.join(", "),
            out.stored_at
        );
        Ok(out.stored_at)
    }

    /// Whether a lookup finds the entry we just put (seq `now` in seconds).
    async fn rendezvous_readback(&self, dht: &AsyncDht, key: &[u8; 32], now: u64) -> bool {
        let d = day(now);
        let public = signing_key(key, d).verifying_key().to_bytes();
        let salt = salt(key, d, &self.ident.id);
        dht.get_mutable_most_recent(&public, Some(&salt))
            .await
            .is_some_and(|item| item.seq() >= (now / 1000) as i64)
    }

    /// What `id`'s entry of today says, or yesterday's (just after midnight).
    async fn rendezvous_lookup(&self, dht: &AsyncDht, key: &[u8; 32], id: &NodeId) -> Option<Found> {
        let now = now_ms();
        for d in [day(now), day(now).saturating_sub(1)] {
            let public = signing_key(key, d).verifying_key().to_bytes();
            let salt = salt(key, d, id);
            if let Some(item) = dht.get_mutable_most_recent(&public, Some(&salt)).await
                && let Some(eps) = open(key, item.value(), id, &self.net, now)
            {
                return Some(eps);
            }
        }
        None
    }

    /// For `status`.
    pub(super) fn rendezvous_status(&self, st: &State) -> Option<String> {
        if !self.rendezvous_enabled() {
            return None;
        }
        let r = &st.rendezvous;
        let mut parts = vec![];
        match (&r.published, r.put_at) {
            (Some((ep, _, _)), Some(at)) => {
                let check = match r.visible {
                    Some(true) => format!(", stored at {} DHT nodes, found by a lookup", r.stored_at),
                    Some(false) => format!(
                        ", stored at {} DHT nodes, but a lookup still finds an older entry (trying again)",
                        r.stored_at
                    ),
                    None => String::new(),
                };
                parts.push(format!(
                    "published {} ({} ago{check})",
                    ep.join(", "),
                    ago(at.elapsed().as_secs())
                ))
            }
            _ if st.my_endpoints.is_empty() && self.punch_candidates().is_empty() => {}
            _ => parts.push("not published yet".into()),
        }
        let found = st.dht_hints.values().filter(|(_, at)| at.elapsed() < HINT_TTL).count();
        if found > 0 {
            parts.push(format!("found {found} node(s) there"));
        }
        if let Some(e) = &r.error {
            parts.push(format!("last error: {e}"));
        }
        if parts.is_empty() {
            parts.push("ready (used once a node is gone)".into());
        }
        Some(format!("DHT, {}", parts.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> Identity {
        let cfg = crate::config::Config::new("a".into(), "n".into(), [1u8; 32]);
        Identity::from_config(&cfg).unwrap()
    }

    #[test]
    fn entries_open_only_for_members_and_the_right_node() {
        let me = ident();
        let other = ident();
        let key = [9u8; 32];
        let now = 1_800_000_000_000;
        let eps = vec!["2.243.3.46:7870".to_string(), "127.0.0.1:7870".to_string()];
        let v = seal(&key, &me, "net1", now, &eps, &[]).unwrap();
        assert!(v.len() <= MAX_VALUE);
        // Loopback is never dialed.
        assert_eq!(
            open(&key, &v, &me.id, "net1", now),
            Some(Found {
                ep: vec!["2.243.3.46:7870".to_string()],
                v6: vec![],
                at: now
            })
        );
        assert_eq!(open(&[8u8; 32], &v, &me.id, "net1", now), None, "another network's key");
        assert_eq!(
            open(&key, &v, &other.id, "net1", now),
            None,
            "under another node's name"
        );
        assert_eq!(open(&key, &v, &me.id, "net2", now), None);
        assert_eq!(open(&key, &v, &me.id, "net1", now + MAX_AGE_MS + 1), None, "too old");
        assert_eq!(
            open(&key, &v, &me.id, "net1", now - 10 * 60 * 1000),
            None,
            "from the future"
        );
        let mut bad = v.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(open(&key, &bad, &me.id, "net1", now), None);
    }

    #[test]
    fn ipv6_addresses_for_hole_punching() {
        let me = ident();
        let key = [9u8; 32];
        let now = 1_800_000_000_000;
        // A node nobody can connect to: no endpoints, only its IPv6 addresses.
        let v6 = vec![
            "[2a02:3035:b1c:74a9::5]:7870".to_string(),
            "[fd0c::1]:7870".to_string(),
            "[fe80::1]:7870".to_string(),
        ];
        let v = seal(&key, &me, "net1", now, &[], &v6).unwrap();
        let found = open(&key, &v, &me.id, "net1", now).unwrap();
        assert!(found.ep.is_empty());
        assert_eq!(
            found.v6,
            vec!["[2a02:3035:b1c:74a9::5]:7870".parse().unwrap()],
            "global addresses only"
        );
        // An entry without the field (older versions) still opens.
        let old = seal(&key, &me, "net1", now, &["2.243.3.46:7870".to_string()], &[]).unwrap();
        assert!(open(&key, &old, &me.id, "net1", now).unwrap().v6.is_empty());
    }

    #[test]
    fn a_member_cannot_sign_for_another() {
        let me = ident();
        let other = ident();
        let key = [9u8; 32];
        let now = 1_800_000_000_000;
        // `other` writes an entry that names `me`, signed with its own key.
        let entry = Entry {
            id: me.id,
            net: "net1".into(),
            at: now,
            ep: vec!["6.6.6.6:7870".into()],
            v6: vec![],
        };
        let doc = serde_json::to_vec(&SignedDoc::sign(&entry, &other)).unwrap();
        let nonce = [0u8; 24];
        let mut v = nonce.to_vec();
        v.extend(cipher(&key).encrypt(&XNonce::from(nonce), doc.as_slice()).unwrap());
        assert_eq!(open(&key, &v, &me.id, "net1", now), None);
    }

    #[test]
    fn locations_change_daily_and_per_node() {
        let key = [9u8; 32];
        let a = ident().id;
        let b = ident().id;
        assert_ne!(salt(&key, 1, &a), salt(&key, 2, &a));
        assert_ne!(salt(&key, 1, &a), salt(&key, 1, &b));
        assert_ne!(
            signing_key(&key, 1).verifying_key().to_bytes(),
            signing_key(&key, 2).verifying_key().to_bytes()
        );
        assert_ne!(
            signing_key(&key, 1).verifying_key().to_bytes(),
            signing_key(&[8u8; 32], 1).verifying_key().to_bytes()
        );
    }

    #[test]
    fn long_lists_are_cut_to_fit() {
        let me = ident();
        let eps: Vec<String> = (0..40)
            .map(|i| format!("very-long-host-name-number-{i}.example.org:7870"))
            .collect();
        let v = seal(&[9u8; 32], &me, "net1", 1, &eps, &[]).unwrap();
        assert!(v.len() <= MAX_VALUE);
    }

    /// Publish and look up through a DHT on localhost.
    #[tokio::test(flavor = "multi_thread")]
    async fn through_a_local_dht() {
        // On 127.0.0.1: the default 0.0.0.0 isn't reachable as a destination on macOS/Windows.
        let testnet = tokio::task::spawn_blocking(|| {
            mainline::Testnet::builder(5)
                .bind_address(std::net::Ipv4Addr::LOCALHOST)
                .build()
                .unwrap()
        })
        .await
        .unwrap();
        let client = |_: ()| {
            Dht::builder()
                .bootstrap(&testnet.bootstrap)
                .bind_address(std::net::Ipv4Addr::LOCALHOST)
                .build()
                .unwrap()
                .as_async()
        };
        let (a, b) = (client(()), client(()));
        // Joined the test network before asking (a race on slower machines otherwise).
        for d in [&a, &b] {
            assert!(d.bootstrapped().await, "joined the local DHT");
        }
        let me = ident();
        let key = [5u8; 32];
        let now = now_ms();
        let value = seal(&key, &me, "net1", now, &["2.243.3.46:7870".to_string()], &[]).unwrap();
        let d = day(now);
        let s = salt(&key, d, &me.id);
        a.put_mutable(
            MutableItem::new(signing_key(&key, d), &value, (now / 1000) as i64, Some(&s)),
            None,
        )
        .await
        .unwrap();
        let public = signing_key(&key, d).verifying_key().to_bytes();
        let item = b.get_mutable_most_recent(&public, Some(&s)).await.unwrap();
        assert_eq!(
            open(&key, item.value(), &me.id, "net1", now),
            Some(Found {
                ep: vec!["2.243.3.46:7870".to_string()],
                v6: vec![],
                at: now
            })
        );
    }
}
