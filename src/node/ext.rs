//! The node's side of extensions (see `crate::ext`): admin-signed documents, gossiped and kept
//! by every node, and authenticated messages from node to node.

use super::*;
use crate::ext::{Ctx, Doc, Extension, Inbound, Peer, SshAccess, View};

/// The largest document a node accepts (a policy for thousands of devices fits easily).
const MAX_DOC: usize = 512 * 1024;
/// Messages older than this are dropped (they are only signed, not otherwise replay-proof).
const MESSAGE_AGE_MS: u64 = 120_000;

#[derive(Serialize, Deserialize, Clone)]
struct DocBody {
    net: String,
    #[serde(flatten)]
    doc: Doc,
}

#[derive(Serialize, Deserialize)]
struct MsgBody {
    net: String,
    from: NodeId,
    to: NodeId,
    at_ms: u64,
    body: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    to: NodeId,
    ttl: u8,
    msg: SignedDoc,
}

impl Node {
    fn ext() -> Option<&'static Arc<dyn Extension>> {
        crate::ext::get()
    }

    pub(super) fn ext_ctx(self: &Arc<Self>) -> Ctx {
        Ctx { node: self.clone() }
    }

    fn peer_view(&self, st: &State, info: &NodeInfo) -> Peer {
        let mut ssh_users: Vec<String> = info.ssh_keys.iter().map(|k| k.user.clone()).collect();
        ssh_users.dedup();
        Peer {
            id: info.id,
            name: info.name.clone(),
            tags: info.tags.clone(),
            ip: overlay_ip(&info.id),
            online: self.is_online(st, &info.id),
            admin: Self::is_admin(st, &info.id),
            ssh_users,
        }
    }

    pub(crate) fn ext_view(&self) -> View {
        let st = self.state.lock().unwrap();
        let me = Peer {
            id: self.ident.id,
            name: st.my_name.clone(),
            tags: st.my_tags.clone(),
            ip: self.my_ip,
            online: true,
            admin: Self::is_admin(&st, &self.ident.id),
            ssh_users: vec![],
        };
        let peers = st
            .records
            .values()
            .filter(|r| !st.banned.contains_key(&r.info.id))
            .map(|r| self.peer_view(&st, &r.info))
            .collect();
        View {
            me,
            managed: Self::managed(&st),
            peers,
            now_ms: now_ms(),
        }
    }

    pub(crate) fn ext_doc(&self, kind: &str) -> Option<Doc> {
        self.state.lock().unwrap().docs.get(kind).map(|(d, _)| d.clone())
    }

    pub(crate) fn ext_dir(&self) -> &std::path::Path {
        &self.dir
    }

    pub(crate) fn ext_publish(&self, kind: &str, data: String) -> Result<Doc> {
        if data.len() > MAX_DOC {
            bail!("document too large ({} bytes, at most {MAX_DOC})", data.len());
        }
        let mut st = self.state.lock().unwrap();
        if !Self::is_admin(&st, &self.ident.id) {
            bail!("only admins publish this (see meshvpn admin status)");
        }
        let version = st.docs.get(kind).map_or(0, |(d, _)| d.version) + 1;
        let doc = Doc {
            kind: kind.into(),
            version,
            author: self.ident.id,
            at_ms: now_ms(),
            data,
        };
        let signed = SignedDoc::sign(
            &DocBody {
                net: self.net.clone(),
                doc: doc.clone(),
            },
            &self.ident,
        );
        st.docs.insert(kind.into(), (doc.clone(), signed.clone()));
        self.broadcast(&st, &frame(T_DOC, &serde_json::to_vec(&signed).unwrap()), None);
        drop(st);
        self.save_state();
        self.ext_notify.notify_one();
        Ok(doc)
    }

    /// Keeps a document if an admin signed it and it is newer than ours. True if it changed.
    pub(super) fn accept_doc(&self, st: &mut State, signed: SignedDoc) -> bool {
        if signed.data.len() > MAX_DOC + 4096 {
            return false;
        }
        let Ok(body) = signed.open::<DocBody>(|b| b.doc.author) else {
            return false;
        };
        if body.net != self.net || !Self::is_admin(st, &body.doc.author) || body.doc.kind.len() > 64 {
            return false;
        }
        if st
            .docs
            .get(&body.doc.kind)
            .is_some_and(|(d, _)| d.version >= body.doc.version)
        {
            return false;
        }
        st.docs.insert(body.doc.kind.clone(), (body.doc, signed));
        true
    }

    pub(super) fn handle_doc(&self, from: NodeId, payload: &[u8]) {
        let Ok(signed) = serde_json::from_slice::<SignedDoc>(payload) else {
            return;
        };
        let mut st = self.state.lock().unwrap();
        if self.accept_doc(&mut st, signed.clone()) {
            self.broadcast(&st, &frame(T_DOC, payload), Some(from));
            drop(st);
            self.save_state();
            self.ext_notify.notify_one();
        }
    }

    /// Every document, for a new link.
    pub(super) fn doc_frames(&self, st: &State) -> Vec<Vec<u8>> {
        st.docs
            .values()
            .map(|(_, s)| frame(T_DOC, &serde_json::to_vec(s).unwrap()))
            .collect()
    }

    pub(crate) fn ext_send(&self, to: &NodeId, body: &serde_json::Value) -> bool {
        let msg = SignedDoc::sign(
            &MsgBody {
                net: self.net.clone(),
                from: self.ident.id,
                to: *to,
                at_ms: now_ms(),
                body: body.clone(),
            },
            &self.ident,
        );
        let env = Envelope {
            to: *to,
            ttl: DEFAULT_TTL,
            msg,
        };
        let st = self.state.lock().unwrap();
        self.forward_ext(&st, &env)
    }

    fn forward_ext(&self, st: &State, env: &Envelope) -> bool {
        let hop = if st.links.contains_key(&env.to) {
            Some(env.to)
        } else {
            st.routes.get(&env.to).copied()
        };
        match hop.and_then(|h| st.links.get(&h)) {
            Some(l) => l.tx.try_send(frame(T_EXT, &serde_json::to_vec(env).unwrap())).is_ok(),
            None => false,
        }
    }

    pub(super) fn handle_ext(self: &Arc<Self>, payload: &[u8]) {
        let Ok(mut env) = serde_json::from_slice::<Envelope>(payload) else {
            return;
        };
        if env.to != self.ident.id {
            if env.ttl > 1 {
                env.ttl -= 1;
                let st = self.state.lock().unwrap();
                self.forward_ext(&st, &env);
            }
            return;
        }
        let Ok(m) = env.msg.open::<MsgBody>(|m| m.from) else {
            return;
        };
        let fresh = now_ms().abs_diff(m.at_ms) < MESSAGE_AGE_MS;
        let known = {
            let st = self.state.lock().unwrap();
            st.records.contains_key(&m.from) && !st.banned.contains_key(&m.from)
        };
        if m.net != self.net || m.to != self.ident.id || !fresh || !known {
            return;
        }
        if let Some(ext) = Self::ext() {
            let node = self.clone();
            // Off the link's task: an extension may take its time.
            tokio::task::spawn_blocking(move || ext.message(&node.ext_ctx(), m.from, m.body));
        }
    }

    /// The extension's view on SSH logins (computed before taking the state lock).
    pub(super) fn ext_ssh_access(&self) -> SshAccess {
        match Self::ext() {
            Some(e) => e.ssh_access(&self.ext_view()),
            None => SshAccess::default(),
        }
    }

    /// Lets the extension filter a packet from the mesh to this node.
    pub(super) fn ext_allows(&self, pkt: &[u8]) -> bool {
        let Some(ext) = Self::ext() else { return true };
        if pkt.len() < 20 {
            return false;
        }
        let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let from = {
            let st = self.state.lock().unwrap();
            match st.ip_map.get(&src) {
                Some(id) => *id,
                // Internet replies through our exit node: not a node's traffic to us.
                None => return true,
            }
        };
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        let protocol = pkt[9];
        let port = matches!(protocol, 6 | 17)
            .then(|| pkt.get(ihl + 2..ihl + 4).map(|p| u16::from_be_bytes([p[0], p[1]])))
            .flatten();
        ext.allow_inbound(&Inbound {
            from: &from,
            protocol,
            port,
        })
    }

    /// The daemon's side: start, react to new documents, tick.
    pub(super) fn ext_run(self: &Arc<Self>) {
        let Some(ext) = Self::ext() else { return };
        let node = self.clone();
        tokio::task::spawn_blocking(move || ext.start(&node.ext_ctx()));
        let node = self.clone();
        tokio::spawn(async move {
            loop {
                node.ext_notify.notified().await;
                let n = node.clone();
                let _ = tokio::task::spawn_blocking(move || ext.docs_changed(&n.ext_ctx())).await;
            }
        });
        let node = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let n = node.clone();
                let _ = tokio::task::spawn_blocking(move || ext.tick(&n.ext_ctx())).await;
            }
        });
    }
}
