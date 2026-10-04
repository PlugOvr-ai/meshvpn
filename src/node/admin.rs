//! Managed networks: admins, and admission of new nodes by single-use invites.
//!
//! An open network (no roster) works as before: the network key is membership. Once a network
//! is managed, a node must also be admitted - listed in the roster, or holding a claim on an
//! invite ticket an admin signed. Only admins issue tickets, ban, and change the roster.
//!
//! Claims are only accepted while fresh (shortly after they were made, before the ticket
//! expires). The first member that accepts one countersigns it as a witness, so nodes that were
//! offline at the time accept it later too. A ticket admits at most `uses` nodes: the earliest
//! claims win on every node, so a ticket used twice still only lets one node in.

use super::*;

/// A claim must reach its first member within this time of being made.
const FRESH_MS: u64 = 3600 * 1000;

pub(super) struct Admitted {
    pub msg: ClaimMsg,
    pub claim: Claim,
    pub ticket: Ticket,
}

fn witness_bytes(claim: &SignedDoc) -> Vec<u8> {
    let mut v = b"meshvpn witness v1\n".to_vec();
    v.extend_from_slice(claim.data.as_bytes());
    v
}

impl Node {
    pub(super) fn managed(st: &State) -> bool {
        st.roster.is_some()
    }

    /// May `id` act as admin? In an open network everybody may (as before).
    pub(super) fn is_admin(st: &State, id: &NodeId) -> bool {
        match &st.roster {
            None => true,
            Some((_, r)) => r.admins.contains(id) && !st.banned.contains_key(id),
        }
    }

    /// May `id` be part of the network?
    pub(super) fn admitted(st: &State, id: &NodeId) -> bool {
        if st.banned.contains_key(id) {
            return false;
        }
        match &st.roster {
            None => true,
            Some((_, r)) => r.admins.contains(id) || r.members.contains(id) || st.claims.contains_key(id),
        }
    }

    /// Accepts a (newer) roster signed by an admin we already trust.
    pub(super) fn apply_roster(&self, st: &mut State, signed: SignedDoc) -> bool {
        let Ok(r) = signed.open::<Roster>(|r| r.issuer) else {
            return false;
        };
        if r.net != self.net || r.admins.is_empty() {
            return false;
        }
        let trusted = match &st.roster {
            Some((_, cur)) => {
                if r.version <= cur.version {
                    return false;
                }
                cur.admins.contains(&r.issuer) && !st.banned.contains_key(&r.issuer)
            }
            // First roster: the admins our invite named, or (networks that became managed
            // later) a roster that names its own signer as admin.
            None if !st.trusted_admins.is_empty() => st.trusted_admins.contains(&r.issuer),
            None => r.version == 1 && r.admins.contains(&r.issuer),
        };
        if !trusted {
            debug!(
                "ignoring roster v{} from {}: not signed by an admin",
                r.version, r.issuer
            );
            return false;
        }
        info!(
            "network is managed (roster v{}, {} admin(s), {} member(s) from before)",
            r.version,
            r.admins.len(),
            r.members.len()
        );
        st.roster = Some((signed, r));
        true
    }

    fn handle_roster(&self, from: NodeId, payload: &[u8]) {
        let Ok(signed) = serde_json::from_slice::<SignedDoc>(payload) else {
            return;
        };
        let mut st = self.state.lock().unwrap();
        if self.apply_roster(&mut st, signed.clone()) {
            self.broadcast(&st, &frame(T_ROSTER, &serde_json::to_vec(&signed).unwrap()), Some(from));
            self.drop_unadmitted(&mut st);
            drop(st);
            self.save_state();
        }
    }

    /// Checks a claim; on success it is recorded (with our witness if it is fresh) and
    /// returned for flooding. Errors say why a node can't join.
    pub(super) fn accept_claim(&self, st: &mut State, msg: ClaimMsg) -> Result<Option<ClaimMsg>> {
        let claim = msg.claim.open::<Claim>(|c| c.node)?;
        let ticket = claim.ticket.open::<Ticket>(|t| t.issuer)?;
        if claim.net != self.net || ticket.net != self.net {
            bail!("invite of another network");
        }
        if !Self::is_admin(st, &ticket.issuer) {
            bail!("the invite was not issued by an admin");
        }
        if st.banned.contains_key(&claim.node) {
            bail!("banned");
        }
        if let Some(a) = st.claims.get(&claim.node)
            && a.claim.ticket.data == claim.ticket.data
        {
            return Ok(None); // known
        }
        // Fresh (made recently, before the ticket expired) - or vouched for by a member that
        // saw it fresh.
        let now = now_ms();
        let fresh = claim.at <= ticket.expires && now.saturating_sub(claim.at) < FRESH_MS && claim.at <= now + FRESH_MS;
        let mut msg = msg;
        if !fresh {
            let witnessed = msg.witness.as_ref().is_some_and(|(w, sig)| {
                Self::admitted(st, w)
                    && *w != claim.node
                    && crate::keys::unb64(sig)
                        .ok()
                        .is_some_and(|s| crate::keys::verify(w, &witness_bytes(&msg.claim), &s).is_ok())
            });
            if !witnessed {
                if claim.at > ticket.expires {
                    bail!("the invite has expired - ask an admin for a new one");
                }
                bail!("the admission is too old and nobody vouched for it - ask an admin for a new invite");
            }
        } else if msg.witness.is_none() {
            let sig = crate::keys::b64(&self.ident.sign(&witness_bytes(&msg.claim)));
            msg.witness = Some((self.ident.id, sig));
        }
        // Single use: the earliest `uses` claims on a ticket win, everywhere alike.
        let mut rivals: Vec<(u64, NodeId)> = st
            .claims
            .values()
            .filter(|a| a.ticket.id == ticket.id)
            .map(|a| (a.claim.at, a.claim.node))
            .collect();
        rivals.push((claim.at, claim.node));
        rivals.sort();
        let winners: Vec<NodeId> = rivals
            .iter()
            .take(ticket.uses.max(1) as usize)
            .map(|(_, n)| *n)
            .collect();
        if !winners.contains(&claim.node) {
            bail!("this invite has already been used - ask an admin for a new one");
        }
        for (_, loser) in rivals.iter().skip(ticket.uses.max(1) as usize) {
            warn!("{loser} used an invite that another node used first - dropping it");
            st.claims.remove(loser);
        }
        info!("admitted {} with an invite from {}", claim.node, ticket.issuer);
        st.claims.insert(
            claim.node,
            Admitted {
                msg: msg.clone(),
                claim,
                ticket,
            },
        );
        Ok(Some(msg))
    }

    fn handle_claim(&self, from: NodeId, payload: &[u8]) {
        let Ok(msg) = serde_json::from_slice::<ClaimMsg>(payload) else {
            return;
        };
        let mut st = self.state.lock().unwrap();
        match self.accept_claim(&mut st, msg) {
            Ok(Some(m)) => {
                self.broadcast(&st, &frame(T_CLAIM, &serde_json::to_vec(&m).unwrap()), Some(from));
                self.drop_unadmitted(&mut st);
            }
            Ok(None) => {}
            Err(e) => debug!("ignoring admission: {e:#}"),
        }
    }

    /// Links and records of nodes that are not (or no longer) admitted.
    fn drop_unadmitted(&self, st: &mut State) {
        if !Self::managed(st) {
            return;
        }
        let out: Vec<NodeId> = st
            .links
            .keys()
            .chain(st.records.keys())
            .filter(|id| !Self::admitted(st, id))
            .copied()
            .collect();
        for id in out {
            if let Some(l) = st.links.remove(&id) {
                l.kill.notify_one();
            }
            if let Some(r) = st.records.remove(&id) {
                warn!(
                    "{} ({id}) is not admitted to this managed network - disconnected",
                    r.info.name
                );
            }
        }
        self.rebuild(st);
    }

    pub(super) fn admin_frames(&self, st: &State) -> Vec<Vec<u8>> {
        let mut f = vec![];
        if let Some((r, _)) = &st.roster {
            f.push(frame(T_ROSTER, &serde_json::to_vec(r).unwrap()));
        }
        for a in st.claims.values() {
            f.push(frame(T_CLAIM, &serde_json::to_vec(&a.msg).unwrap()));
        }
        f
    }

    /// Our own admission, made from the invite's ticket the first time we start.
    pub(super) fn own_claim(&self) -> Option<ClaimMsg> {
        if let Some(c) = &self.cfg.claim {
            return Some(c.clone());
        }
        let ticket = self.cfg.ticket.clone()?;
        let claim = Claim {
            net: self.net.clone(),
            ticket,
            node: self.ident.id,
            at: now_ms(),
        };
        let msg = ClaimMsg {
            claim: SignedDoc::sign(&claim, &self.ident),
            witness: None,
        };
        let res = (|| -> Result<()> {
            let mut cfg = Config::load(&self.dir)?;
            cfg.claim = Some(msg.clone());
            cfg.save(&self.dir)
        })();
        if let Err(e) = res {
            warn!("saving the admission: {e:#}");
        }
        Some(msg)
    }

    // ----------------------------------------------------------------------------- commands

    fn publish_roster(&self, st: &mut State, admins: Vec<NodeId>, members: Vec<NodeId>) -> Result<()> {
        let version = st.roster.as_ref().map_or(1, |(_, r)| r.version + 1);
        let roster = Roster {
            net: self.net.clone(),
            version,
            admins,
            members,
            issuer: self.ident.id,
            at: now_ms(),
        };
        let signed = SignedDoc::sign(&roster, &self.ident);
        if !self.apply_roster(st, signed.clone()) {
            bail!("could not apply the new roster");
        }
        self.broadcast(st, &frame(T_ROSTER, &serde_json::to_vec(&signed).unwrap()), None);
        Ok(())
    }

    /// Everybody admitted now (to keep them when the roster changes).
    fn current_members(&self, st: &State) -> Vec<NodeId> {
        let mut m: Vec<NodeId> = st.records.keys().copied().filter(|id| Self::admitted(st, id)).collect();
        if let Some((_, r)) = &st.roster {
            m.extend(r.members.iter().copied());
        }
        m.extend(st.claims.keys().copied());
        m.push(self.ident.id);
        m.retain(|id| !st.banned.contains_key(id));
        m.sort();
        m.dedup();
        m
    }

    /// `meshvpn admin enable`: this node becomes the first admin; everybody known stays in.
    pub fn admin_enable(&self) -> Result<String> {
        let mut st = self.state.lock().unwrap();
        if Self::managed(&st) {
            bail!("this network is already managed (see meshvpn admin status)");
        }
        let members = self.current_members(&st);
        let n = members.len();
        self.publish_roster(&mut st, vec![self.ident.id], members)?;
        drop(st);
        self.save_state();
        Ok(format!(
            "the network is now managed: {} is its admin, the {n} node(s) known now stay members. \
             New nodes need an invite from an admin (meshvpn invite), and only admins can ban.",
            self.cfg.name
        ))
    }

    fn resolve_node(&self, st: &State, who: &str) -> Result<(NodeId, String)> {
        let w = who.trim().to_lowercase();
        if w == st.my_name || (w.len() >= 4 && self.ident.id.hex().starts_with(&w)) {
            return Ok((self.ident.id, st.my_name.clone()));
        }
        let mut m: Vec<&Record> = st
            .records
            .values()
            .filter(|r| r.info.name == w || (w.len() >= 4 && r.info.id.hex().starts_with(&w)))
            .collect();
        m.sort_by_key(|r| (!self.is_online(st, &r.info.id), std::cmp::Reverse(r.info.seq)));
        m.first()
            .map(|r| (r.info.id, r.info.name.clone()))
            .ok_or_else(|| anyhow!("no node named {w:?} (see meshvpn status)"))
    }

    /// `meshvpn admin add/rm <node>`.
    pub fn admin_change(&self, who: &str, add: bool) -> Result<String> {
        let mut st = self.state.lock().unwrap();
        let Some((_, roster)) = st.roster.clone() else {
            bail!("this network is not managed yet - start with: sudo meshvpn admin enable");
        };
        if !Self::is_admin(&st, &self.ident.id) {
            bail!("only admins can change the admins");
        }
        let (id, name) = self.resolve_node(&st, who)?;
        let mut admins = roster.admins.clone();
        if add {
            if admins.contains(&id) {
                bail!("{name} is already an admin");
            }
            admins.push(id);
        } else {
            if !admins.contains(&id) {
                bail!("{name} is not an admin");
            }
            admins.retain(|a| *a != id);
            if admins.is_empty() {
                bail!("{name} is the last admin - add another one first");
            }
        }
        let members = self.current_members(&st);
        self.publish_roster(&mut st, admins, members)?;
        drop(st);
        self.save_state();
        Ok(format!(
            "{name} {} admin",
            if add { "is now an" } else { "is no longer an" }
        ))
    }

    pub fn admin_status(&self) -> serde_json::Value {
        let st = self.state.lock().unwrap();
        let name = |id: &NodeId| {
            if *id == self.ident.id {
                st.my_name.clone()
            } else {
                st.records
                    .get(id)
                    .map(|r| r.info.name.clone())
                    .unwrap_or_else(|| id.short())
            }
        };
        match &st.roster {
            None => serde_json::json!({
                "managed": false,
                "note": "open network: everybody with the network key is a member and may invite and ban",
            }),
            Some((_, r)) => serde_json::json!({
                "managed": true,
                "version": r.version,
                "admins": r.admins.iter().map(name).collect::<Vec<_>>(),
                "this_node_is_admin": Self::is_admin(&st, &self.ident.id),
                "members_from_before": r.members.len(),
                "admitted_by_invite": st.claims.values().map(|a| serde_json::json!({
                    "node": name(&a.claim.node), "invited_by": name(&a.ticket.issuer),
                })).collect::<Vec<_>>(),
            }),
        }
    }

    /// `meshvpn invite` in a managed network: a ticket signed by this (admin) node.
    pub fn issue_ticket(&self, uses: u32, valid_ms: u64) -> Result<(Option<SignedDoc>, Vec<NodeId>)> {
        let st = self.state.lock().unwrap();
        let Some((_, roster)) = &st.roster else {
            return Ok((None, vec![]));
        };
        if !Self::is_admin(&st, &self.ident.id) {
            let admins: Vec<String> = roster
                .admins
                .iter()
                .map(|a| st.records.get(a).map(|r| r.info.name.clone()).unwrap_or(a.short()))
                .collect();
            bail!("only admins can invite in this network - ask {}", admins.join(" or "));
        }
        let mut id = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let ticket = Ticket {
            net: self.net.clone(),
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            expires: now_ms() + valid_ms,
            uses: uses.max(1),
            issuer: self.ident.id,
        };
        Ok((Some(SignedDoc::sign(&ticket, &self.ident)), roster.admins.clone()))
    }

    pub(super) fn dispatch_admin(&self, kind: u8, peer: NodeId, payload: &[u8]) -> bool {
        match kind {
            T_ROSTER => self.handle_roster(peer, payload),
            T_CLAIM => self.handle_claim(peer, payload),
            _ => return false,
        }
        true
    }
}
