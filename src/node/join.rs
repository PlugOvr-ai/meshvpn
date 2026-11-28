//! Joining through hole punching: a new node and the node that invited it meet although neither
//! can reach the other (a home router without a port forward, a mobile network).
//!
//! The invite carries a join hint: a random slot (secret, like the invite), the inviting node's
//! id and its IPv6 addresses. Until it has met anyone, the new node puts its own IPv6 addresses
//! into the DHT at a place derived from the network key and the slot - sealed and signed like a
//! rendezvous entry - and tries the inviting node's addresses (see `punch`). While the invite is
//! open, the inviting node looks there and tries back. The join itself then runs over the punched
//! link as always (ticket, admission).
//!
//! Only invites made where the DHT or Nostr is on carry a hint, and it says which (the new node
//! uses those for this one meeting whatever its own settings). The same place is a Nostr event
//! (see `nostr`). Places are looked at every 30 seconds for the first half hour of an invite, then
//! every two minutes, until it expires.

use super::*;
use crate::config::{JoinHint, JoinSlot};
use mainline::{MutableItem, SigningKey};

/// How often the new node puts its entry again (and the inviting node looks).
const PUT_EVERY: Duration = Duration::from_secs(60);
const LOOK_EAGER: Duration = Duration::from_secs(30);
const LOOK_LATER: Duration = Duration::from_secs(120);
/// The first half hour of an invite: looked at often.
const EAGER_MS: u64 = 30 * 60 * 1000;
/// A hint is good for this long at most (invites may be valid for longer).
const MAX_HINT_MS: u64 = 7 * 86_400_000;

/// The DHT place of a join slot: key pair and salt, from the network key and the slot.
fn place(net_key: &[u8; 32], slot: &str) -> (SigningKey, [u8; 20]) {
    let p = nostr_place(net_key, slot);
    (SigningKey::from_bytes(&p.seed), p.salt)
}

/// The same place for Nostr relays.
fn nostr_place(net_key: &[u8; 32], slot: &str) -> nostr::Place {
    let seed = rendezvous::derive("meshvpn join v1 key", &[net_key, slot.as_bytes()]);
    let salt = rendezvous::derive("meshvpn join v1 salt", &[net_key, slot.as_bytes()]);
    nostr::Place {
        seed,
        salt: salt[..20].try_into().unwrap(),
    }
}

impl Node {
    /// Our IPv6 addresses for meeting: the temporary ones, else any (an invite is handed over
    /// in person, unlike the rendezvous entries every former member can read).
    fn join_addresses(&self) -> Vec<String> {
        let mut v6 = self.punch_candidates();
        if v6.is_empty() && self.punch_enabled() {
            let port = self.punch_port();
            v6 = crate::sys::global_ipv6()
                .into_iter()
                .take(4)
                .map(|ip| SocketAddr::new(IpAddr::V6(ip), port).to_string())
                .collect();
        }
        v6
    }

    /// `meshvpn invite`: a slot for the new node to meet this one (kept until `until`).
    pub fn register_join(&self, until: u64) -> Result<JoinHint> {
        if !self.rendezvous_enabled() {
            bail!("the DHT and Nostr are off here (dht = false, nostr = false)");
        }
        let v6 = self.join_addresses();
        if v6.is_empty() {
            bail!("no IPv6 address here");
        }
        let now = now_ms();
        let until = until.min(now + MAX_HINT_MS);
        let slot: String = crate::keys::random32()[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut st = self.state.lock().unwrap();
        st.join_slots.retain(|s| s.until > now);
        st.join_slots.push(JoinSlot {
            slot: slot.clone(),
            from: now,
            until,
        });
        drop(st);
        self.save_state();
        Ok(JoinHint {
            slot,
            node: self.ident.id,
            v6,
            until,
            dht: self.dht_enabled(),
            nostr: self.nostr_enabled(),
        })
    }

    pub(super) async fn join_loop(self: Arc<Self>) {
        if !self.punch_enabled() {
            return;
        }
        let mut last_put: Option<Instant> = None;
        let mut looked: HashMap<String, Instant> = HashMap::new();
        let running: Arc<Mutex<HashSet<NodeId>>> = Arc::default();
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            self.join_as_new(&mut last_put, &running).await;
            self.join_as_inviter(&mut looked, &running).await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    fn spawn_punch(self: &Arc<Self>, id: NodeId, targets: Vec<SocketAddr>, running: &Arc<Mutex<HashSet<NodeId>>>) {
        if targets.is_empty() || !running.lock().unwrap().insert(id) {
            return;
        }
        let (node, running) = (self.clone(), running.clone());
        tokio::spawn(async move {
            node.punch_run(id, targets).await;
            running.lock().unwrap().remove(&id);
        });
    }

    /// The new node: until it has met anyone, put our addresses at the slot and try the
    /// inviting node's.
    async fn join_as_new(self: &Arc<Self>, last_put: &mut Option<Instant>, running: &Arc<Mutex<HashSet<NodeId>>>) {
        let Some(hint) = self.cfg.join.clone() else { return };
        let now = now_ms();
        let (alone, key) = {
            let st = self.state.lock().unwrap();
            (
                st.links.is_empty() && !st.records.keys().any(|id| *id != self.ident.id),
                Self::current_key(&st),
            )
        };
        if !alone || now > hint.until || !self.punch_enabled() {
            return;
        }
        let Some(key) = key else { return };
        let targets: Vec<SocketAddr> = hint.v6.iter().filter_map(|a| a.parse().ok()).collect();
        self.spawn_punch(hint.node, targets, running);
        if last_put.is_some_and(|t| t.elapsed() < PUT_EVERY) {
            return;
        }
        let v6 = self.join_addresses();
        if v6.is_empty() {
            return;
        }
        let Some(value) = rendezvous::seal(&key, &self.ident, &self.net, now, &[], &v6) else {
            return;
        };
        let mut at = vec![];
        if hint.nostr && !self.cfg.no_outbound {
            let relays = self.nostr_relays();
            let put = nostr::put(
                &relays,
                self.cfg.effective_socks(),
                &nostr_place(&key, &hint.slot),
                &value,
                now / 1000,
            )
            .await;
            if put.ok > 0 {
                at.push(format!("at {} of {} Nostr relays", put.ok, put.tried));
            } else if let Some(e) = put.error {
                debug!("joining: putting our addresses on Nostr relays: {e}");
            }
        }
        if hint.dht
            && let Some(dht) = self.dht().await
        {
            let (signer, salt) = place(&key, &hint.slot);
            let item = MutableItem::new(signer, &value, (now / 1000) as i64, Some(&salt));
            match dht.put_mutable(item, None).await {
                Ok(out) => at.push(format!("in the DHT at {} nodes", out.stored_at)),
                Err(e) => debug!("joining: putting our addresses in the DHT: {e}"),
            }
        }
        if !at.is_empty() {
            *last_put = Some(Instant::now());
            info!(
                "joining: waiting for the inviting node at {} (our addresses {})",
                hint.v6.join(", "),
                at.join(", ")
            );
        }
    }

    /// The inviting node: look at the open invites' places and try towards whoever is there.
    async fn join_as_inviter(
        self: &Arc<Self>,
        looked: &mut HashMap<String, Instant>,
        running: &Arc<Mutex<HashSet<NodeId>>>,
    ) {
        if !self.rendezvous_enabled() || !self.punch_enabled() {
            return;
        }
        let now = now_ms();
        let (due, key) = {
            let mut st = self.state.lock().unwrap();
            let before = st.join_slots.len();
            st.join_slots.retain(|s| s.until > now);
            if st.join_slots.len() != before {
                looked.retain(|slot, _| st.join_slots.iter().any(|s| s.slot == *slot));
            }
            let due: Vec<String> = st
                .join_slots
                .iter()
                .filter(|s| {
                    let every = if now.saturating_sub(s.from) < EAGER_MS {
                        LOOK_EAGER
                    } else {
                        LOOK_LATER
                    };
                    looked.get(&s.slot).is_none_or(|t| t.elapsed() >= every)
                })
                .map(|s| s.slot.clone())
                .collect();
            (due, Self::current_key(&st))
        };
        let Some(key) = key else { return };
        if due.is_empty() {
            return;
        }
        for slot in &due {
            looked.insert(slot.clone(), Instant::now());
        }
        // What is at the places: Nostr relays (all at once), the DHT (one by one).
        let mut values: Vec<Vec<u8>> = vec![];
        if self.nostr_enabled() {
            let places: Vec<nostr::Place> = due
                .iter()
                .take(nostr::MAX_PLACES)
                .map(|slot| nostr_place(&key, slot))
                .collect();
            let (found, _) = nostr::get(&self.nostr_relays(), self.cfg.effective_socks(), &places).await;
            values.extend(found.into_iter().flatten().map(|(v, _)| v));
        }
        if self.dht_enabled()
            && let Some(dht) = self.dht().await
        {
            for slot in &due {
                let (signer, salt) = place(&key, slot);
                let public = signer.verifying_key().to_bytes();
                if let Some(item) = dht.get_mutable_most_recent(&public, Some(&salt)).await {
                    values.push(item.value().to_vec());
                }
            }
        }
        for value in values {
            let Some((id, found)) = rendezvous::open_entry(&key, &value, &self.net, now_ms()) else {
                continue;
            };
            if id == self.ident.id || self.state.lock().unwrap().links.contains_key(&id) {
                continue;
            }
            if !running.lock().unwrap().contains(&id) {
                let list: Vec<String> = found.v6.iter().map(|a| a.to_string()).collect();
                info!(
                    "joining: a new node ({id}) waits at {} - trying to reach it",
                    list.join(", ")
                );
            }
            self.spawn_punch(id, found.v6, running);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places_depend_on_key_and_slot() {
        let (a, sa) = place(&[1u8; 32], "slot1");
        let (b, sb) = place(&[1u8; 32], "slot2");
        let (c, sc) = place(&[2u8; 32], "slot1");
        assert_ne!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
        assert_ne!(a.verifying_key().to_bytes(), c.verifying_key().to_bytes());
        assert!(sa != sb && sa != sc);
        // The same inputs give the same place on both sides.
        assert_eq!(place(&[1u8; 32], "slot1").1, sa);
    }
}
