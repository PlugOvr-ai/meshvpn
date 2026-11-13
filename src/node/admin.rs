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
//!
//! Tickets travel inside every claim, so every member sees them. A ticket is therefore bound to
//! a one-time key whose secret is only in the invite: a claim counts only if that key signed it
//! too (for this node and time), so seeing a ticket is not enough to use it.

use super::*;

/// A claim must reach its first member within this time of being made.
const FRESH_MS: u64 = 3600 * 1000;
/// Open network: unconfirmed rosters kept, one per signer.
const MAX_PENDING_ROSTERS: usize = 16;

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
            Some((_, r)) => {
                r.admins.contains(id)
                    || r.members.contains(id)
                    || st
                        .claims
                        .get(id)
                        .is_some_and(|a| a.ticket.client.as_ref().is_none_or(|c| c.until > now_ms()))
            }
        }
    }

    /// Which of the nodes publishing the same name gets it (the smallest key): one online first;
    /// in a managed network then the one admitted first (a member can't take another's name by
    /// publishing a newer record - its own admission's time is fixed); then the newest record
    /// (a machine set up again gets its name back from its old identity).
    pub(super) fn name_rank(&self, st: &State, r: &super::Record) -> (bool, u64, std::cmp::Reverse<u64>, NodeId) {
        let id = r.info.id;
        let admitted_at = match &st.roster {
            None => 0,
            Some((_, roster)) if roster.admins.contains(&id) || roster.members.contains(&id) => 0,
            Some(_) => st.claims.get(&id).map_or(u64::MAX, |a| a.claim.at),
        };
        (!self.is_online(st, &id), admitted_at, std::cmp::Reverse(r.info.seq), id)
    }

    /// `id` is a client (a user's computer, admitted for a time), and whose.
    pub(super) fn client_of<'a>(st: &'a State, id: &NodeId) -> Option<&'a crate::proto::ClientGrant> {
        if let Some((_, r)) = &st.roster
            && (r.admins.contains(id) || r.members.contains(id))
        {
            return None;
        }
        st.claims.get(id).and_then(|a| a.ticket.client.as_ref())
    }

    /// Clients whose time is up: disconnect them; forget their admissions a day later.
    pub(super) fn expire_clients(&self, st: &mut State) {
        let now = now_ms();
        let expired = st
            .claims
            .values()
            .any(|a| a.ticket.client.as_ref().is_some_and(|c| c.until <= now));
        if expired {
            st.claims
                .retain(|_, a| a.ticket.client.as_ref().is_none_or(|c| c.until + 86_400_000 > now));
            self.drop_unadmitted(st);
        }
    }

    /// Accepts a (newer) roster signed by an admin we already trust. In an open network nobody
    /// is trusted yet: a first roster from another node waits until the owner of this machine
    /// confirms its signer (`meshvpn admin trust`), so no member can make itself the admin of
    /// everyone on its own.
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
            // First roster: the admins our invite named (or confirmed with admin trust), or our
            // own (admin enable here).
            None if st.trusted_admins.contains(&r.issuer) => true,
            None if r.issuer == self.ident.id => r.admins.contains(&r.issuer),
            None => {
                self.keep_pending_roster(st, &r, signed);
                return false;
            }
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
        st.pending_rosters.clear();
        true
    }

    /// A roster read back from our own saved state: we accepted it before (its signers may
    /// have changed since, so the chain isn't checked again), only the signature is.
    pub(super) fn restore_roster(&self, st: &mut State, signed: SignedDoc) {
        if let Ok(r) = signed.open::<Roster>(|r| r.issuer)
            && r.net == self.net
            && !r.admins.is_empty()
        {
            st.roster = Some((signed, r));
        }
    }

    /// An open network: a roster nobody here confirmed yet. Kept (newest per signer, signers
    /// we know only) for `admin status` and `admin trust`, and passed on once per version.
    fn keep_pending_roster(&self, st: &mut State, r: &Roster, signed: SignedDoc) {
        if !st.records.contains_key(&r.issuer) {
            return;
        }
        if let Some((_, have, _)) = st.pending_rosters.get(&r.issuer)
            && have.version >= r.version
        {
            return;
        }
        if !st.pending_rosters.contains_key(&r.issuer) && st.pending_rosters.len() >= MAX_PENDING_ROSTERS {
            return;
        }
        let forward = st
            .pending_rosters
            .get(&r.issuer)
            .is_none_or(|(_, _, at)| at.elapsed() >= Duration::from_secs(10));
        if !st.pending_rosters.contains_key(&r.issuer) {
            let name = st
                .records
                .get(&r.issuer)
                .map(|x| x.info.name.clone())
                .unwrap_or_default();
            warn!(
                "{name} wants to make this network managed (admins: {}); this node stays open until \
                 you confirm it: sudo meshvpn admin trust {name}",
                self.names(st, &r.admins).join(", ")
            );
        }
        let frame_bytes = frame(T_ROSTER, &serde_json::to_vec(&signed).unwrap());
        st.pending_rosters.insert(r.issuer, (signed, r.clone(), Instant::now()));
        if forward {
            self.broadcast(st, &frame_bytes, None);
        }
    }

    fn names(&self, st: &State, ids: &[NodeId]) -> Vec<String> {
        ids.iter()
            .map(|id| {
                if *id == self.ident.id {
                    st.my_name.clone()
                } else {
                    st.records.get(id).map_or_else(|| id.short(), |r| r.info.name.clone())
                }
            })
            .collect()
    }

    /// `meshvpn admin trust <node>`: open network, the owner of this machine accepts that node
    /// as admin. Its roster (if here already) applies now, a later one when it arrives.
    pub fn admin_trust(&self, who: &str) -> Result<String> {
        let mut st = self.state.lock().unwrap();
        if Self::managed(&st) {
            bail!("this network is managed already (see meshvpn admin status)");
        }
        let (id, name) = self.resolve_node(&st, who)?;
        if !st.trusted_admins.contains(&id) {
            st.trusted_admins.push(id);
            let mut cfg = Config::load(&self.dir)?;
            if !cfg.trusted_admins.contains(&id) {
                cfg.trusted_admins.push(id);
            }
            cfg.save(&self.dir)?;
        }
        let mut pending: Vec<SignedDoc> = {
            let mut v: Vec<(u32, SignedDoc)> = st
                .pending_rosters
                .values()
                .map(|(s, r, _)| (r.version, s.clone()))
                .collect();
            v.sort_by_key(|(v, _)| *v);
            v.into_iter().map(|(_, s)| s).collect()
        };
        let mut applied = false;
        for s in pending.drain(..) {
            if self.apply_roster(&mut st, s.clone()) {
                applied = true;
                self.broadcast(&st, &frame(T_ROSTER, &serde_json::to_vec(&s).unwrap()), None);
            }
        }
        if !applied {
            return Ok(format!(
                "{name} is trusted as admin here; this node becomes managed when its roster arrives \
                 (sudo meshvpn admin enable on {name})"
            ));
        }
        self.drop_unadmitted(&mut st);
        let admins = st
            .roster
            .as_ref()
            .map(|(_, r)| self.names(&st, &r.admins))
            .unwrap_or_default();
        drop(st);
        self.save_state();
        Ok(format!(
            "the network is managed here now, admins: {}",
            admins.join(", ")
        ))
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
        // A claim we took already costs no signature checks (anyone could resend one). Only
        // taken ones: a claim refused now (its admin's roster not here yet) may be fine later.
        let digest = *blake3::hash(&serde_json::to_vec(&msg.claim).unwrap_or_default()).as_bytes();
        if st.claims_seen.contains(&digest) {
            return Ok(None);
        }
        let res = self.check_claim(st, msg);
        if res.is_ok() {
            if st.claims_seen.len() >= 4096 {
                st.claims_seen.clear();
            }
            st.claims_seen.insert(digest);
        }
        res
    }

    fn check_claim(&self, st: &mut State, msg: ClaimMsg) -> Result<Option<ClaimMsg>> {
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
        // A bound ticket: only who has the invite can claim it (members see the ticket itself).
        if let Some(key) = &ticket.key {
            let msg = Claim::proof_bytes(&ticket.net, &ticket.id, &claim.node, claim.at);
            let ok = claim
                .proof
                .as_deref()
                .and_then(|p| crate::keys::unb64(p).ok())
                .is_some_and(|s| crate::keys::verify(key, &msg, &s).is_ok());
            if !ok {
                bail!("the admission doesn't prove it holds the invite (update meshvpn on the new node)");
            }
        }
        if let Some(a) = st.claims.get(&claim.node)
            && a.claim.ticket.data == claim.ticket.data
        {
            return Ok(None); // known
        }
        // A client renews with a new ticket; an older admission arriving late changes nothing.
        if let Some(a) = st.claims.get(&claim.node) {
            let until = |t: &Ticket| t.client.as_ref().map_or(u64::MAX, |c| c.until);
            if until(&a.ticket) >= until(&ticket) {
                return Ok(None);
            }
        }
        // Fresh (made recently, before the ticket expired) - or vouched for by a member that
        // saw it fresh.
        let now = now_ms();
        // Never after the ticket expired, never in the future - also when vouched for (the
        // node making the claim chooses its time).
        if claim.at > ticket.expires {
            bail!("the invite has expired - ask an admin for a new one");
        }
        if claim.at > now + FRESH_MS {
            bail!("the admission is dated in the future");
        }
        let fresh = now.saturating_sub(claim.at) < FRESH_MS;
        let mut msg = msg;
        if !fresh {
            // Members see the tickets in the claims they pass on, so a member's word counts only
            // while the ticket is still valid, and a client's never; an admin's always.
            let witnessed = msg.witness.as_ref().is_some_and(|(w, sig)| {
                let trusted = Self::admitted(st, w)
                    && (Self::is_admin(st, w) || (Self::client_of(st, w).is_none() && ticket.expires > now));
                trusted
                    && *w != claim.node
                    && crate::keys::unb64(sig)
                        .ok()
                        .is_some_and(|s| crate::keys::verify(w, &witness_bytes(&msg.claim), &s).is_ok())
            });
            if !witnessed {
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
        // A late claim (only vouched for) never pushes out a node already admitted with the
        // same invite: its time is the claimer's word.
        if !fresh && rivals.len() > ticket.uses.max(1) as usize {
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
        let claim = self.make_claim(ticket, self.cfg.ticket_key.as_deref());
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

    /// Our claim on `ticket`, with the proof from the invite's one-time key if it is bound.
    fn make_claim(&self, ticket: SignedDoc, ticket_key: Option<&str>) -> Claim {
        let at = now_ms();
        let proof = ticket
            .open::<Ticket>(|t| t.issuer)
            .ok()
            .filter(|t| t.key.is_some())
            .zip(ticket_key)
            .and_then(|(t, secret)| {
                let msg = Claim::proof_bytes(&t.net, &t.id, &self.ident.id, at);
                crate::keys::sign_one_time(secret, &msg).ok()
            })
            .map(|s| crate::keys::b64(&s));
        Claim {
            net: self.net.clone(),
            ticket,
            node: self.ident.id,
            at,
            proof,
        }
    }

    // ----------------------------------------------------------------------------- commands

    pub(super) fn publish_roster(&self, st: &mut State, admins: Vec<NodeId>, members: Vec<NodeId>) -> Result<()> {
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
    pub(super) fn current_members(&self, st: &State) -> Vec<NodeId> {
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
             New nodes need an invite from an admin (meshvpn invite), and only admins can ban.\n\
             Each other node applies this once its owner confirms it there: sudo meshvpn admin trust {}\n\
             (nodes older than 0.32.1 apply it right away)",
            self.cfg.name, self.cfg.name
        ))
    }

    pub(super) fn resolve_node(&self, st: &State, who: &str) -> Result<(NodeId, String)> {
        let w = who.trim().to_lowercase();
        if w == st.my_name || (w.len() >= 4 && self.ident.id.hex().starts_with(&w)) {
            return Ok((self.ident.id, st.my_name.clone()));
        }
        let mut m: Vec<&Record> = st
            .records
            .values()
            .filter(|r| r.info.name == w || (w.len() >= 4 && r.info.id.hex().starts_with(&w)))
            .collect();
        Self::one_node(&m, &w)?;
        m.sort_by_key(|r| self.name_rank(st, r));
        m.first()
            .map(|r| (r.info.id, r.info.name.clone()))
            .ok_or_else(|| anyhow!("no node named {w:?} (see meshvpn status)"))
    }

    /// Several nodes go by this name: a decision about one (admin, exit) needs its id - not
    /// whichever took the name last.
    pub(super) fn one_node(found: &[&Record], name: &str) -> Result<()> {
        if found.len() > 1 {
            let ids: Vec<String> = found.iter().map(|r| r.info.id.short()).collect();
            bail!(
                "{} nodes are called {name}: give the id instead (one of {})",
                found.len(),
                ids.join(", ")
            );
        }
        Ok(())
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
                "waiting": st.pending_rosters.values().map(|(_, r, _)| serde_json::json!({
                    "from": name(&r.issuer), "admins": r.admins.iter().map(name).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
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

    /// `meshvpn invite` in a managed network: a ticket signed by this (admin) node; with
    /// `client`, for a user's computer that is a member for a time only.
    pub fn issue_ticket(
        &self,
        uses: u32,
        valid_ms: u64,
        client: Option<crate::proto::ClientGrant>,
        bind: Option<NodeId>,
    ) -> Result<(Option<SignedDoc>, Vec<NodeId>)> {
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
            client,
            key: bind,
        };
        Ok((Some(SignedDoc::sign(&ticket, &self.ident)), roster.admins.clone()))
    }

    /// A new admission for this node from `ticket` (a client renewing its time): saved,
    /// accepted here and sent to everyone.
    pub fn readmit(&self, ticket: SignedDoc, ticket_key: Option<String>) -> Result<String> {
        let t = ticket.open::<Ticket>(|t| t.issuer)?;
        if t.net != self.net {
            bail!("this invite is for another network");
        }
        let claim = self.make_claim(ticket, ticket_key.as_deref());
        let msg = ClaimMsg {
            claim: SignedDoc::sign(&claim, &self.ident),
            witness: None,
        };
        let mut cfg = Config::load(&self.dir)?;
        cfg.ticket = Some(claim.ticket.clone());
        cfg.ticket_key = ticket_key;
        cfg.claim = Some(msg.clone());
        cfg.save(&self.dir)?;
        let mut st = self.state.lock().unwrap();
        if let Some(m) = self.accept_claim(&mut st, msg)? {
            self.broadcast(&st, &frame(T_CLAIM, &serde_json::to_vec(&m).unwrap()), None);
            // The others dropped our record while we weren't admitted, and a copy that came
            // before the admission was refused: send it again, after the admission on each link.
            self.announce(&mut st);
        }
        Ok(match &t.client {
            Some(c) => format!(
                "admitted as {}'s client until {}",
                c.user,
                crate::node::fmt_time(c.until)
            ),
            None => "admitted".into(),
        })
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
