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
//! Only invites made where the DHT is on carry a hint (`dht = true`); the new node uses the DHT
//! for this one meeting whatever its own setting. Places are looked at every 30 seconds for the
//! first half hour of an invite, then every two minutes, until it expires.

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
    let key = rendezvous::derive("meshvpn join v1 key", &[net_key, slot.as_bytes()]);
    let salt = rendezvous::derive("meshvpn join v1 salt", &[net_key, slot.as_bytes()]);
    (SigningKey::from_bytes(&key), salt[..20].try_into().unwrap())
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
            bail!("the DHT is off here (dht = false)");
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
        let Some(dht) = self.dht().await else { return };
        let Some(value) = rendezvous::seal(&key, &self.ident, &self.net, now, &[], &v6) else {
            return;
        };
        let (signer, salt) = place(&key, &hint.slot);
        let item = MutableItem::new(signer, &value, (now / 1000) as i64, Some(&salt));
        match dht.put_mutable(item, None).await {
            Ok(out) => {
                *last_put = Some(Instant::now());
                info!(
                    "joining: waiting for the inviting node at {} (our addresses in the DHT at {} nodes)",
                    hint.v6.join(", "),
                    out.stored_at
                );
            }
            Err(e) => debug!("joining: putting our addresses: {e}"),
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
        let Some(dht) = self.dht().await else { return };
        for slot in due {
            looked.insert(slot.clone(), Instant::now());
            let (signer, salt) = place(&key, &slot);
            let public = signer.verifying_key().to_bytes();
            let Some(item) = dht.get_mutable_most_recent(&public, Some(&salt)).await else {
                continue;
            };
            let Some((id, found)) = rendezvous::open_entry(&key, item.value(), &self.net, now_ms()) else {
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
