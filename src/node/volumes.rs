//! The node's side of the volumes (`crate::volume`): their definitions are admin-signed
//! documents (kind `volume/<name>`), and who keeps chunks needs the nodes' addresses.

use super::*;
use crate::volume::{Def, KIND_PREFIX};

impl Node {
    pub fn id(&self) -> NodeId {
        self.ident.id
    }

    /// Every volume definition.
    pub fn volume_defs(&self) -> Vec<Def> {
        let st = self.state.lock().unwrap();
        let mut v: Vec<Def> = st
            .docs
            .iter()
            .filter_map(|(kind, (doc, _))| {
                let name = kind.strip_prefix(KIND_PREFIX)?;
                let def: Def = serde_json::from_str(&doc.data).ok()?;
                (def.name == name).then_some(def)
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn node_names(&self, ids: &[NodeId]) -> Vec<String> {
        let st = self.state.lock().unwrap();
        self.names(&st, ids)
    }

    /// How to reach `id`'s chunk server, if it is online.
    pub fn holder_of(&self, id: &NodeId) -> Option<crate::share::Holder> {
        let st = self.state.lock().unwrap();
        let r = st.records.get(id)?;
        if !self.is_online(&st, id) {
            return None;
        }
        let lan_ip = st
            .perf
            .get(id)
            .and_then(|p| p.lan_ip.as_ref())
            .and_then(|ip| ip.parse().ok());
        Some(crate::share::Holder {
            name: r.info.name.clone(),
            mesh_ip: r.info.ip(),
            lan_ip,
        })
    }

    /// `meshvpn volume create`: a volume on the disks of `nodes`, optionally filled from
    /// network storage.
    pub fn volume_create(
        &self,
        name: String,
        nodes: Vec<String>,
        from: Option<String>,
        copies: u8,
    ) -> Result<serde_json::Value> {
        crate::volume::valid_name(&name)?;
        let ids: Vec<NodeId> = {
            let st = self.state.lock().unwrap();
            if !Self::is_admin(&st, &self.ident.id) {
                bail!("only admins make volumes (see meshvpn admin status)");
            }
            let mut ids = vec![];
            for n in nodes
                .iter()
                .flat_map(|n| n.split(','))
                .map(str::trim)
                .filter(|n| !n.is_empty())
            {
                let (id, _) = self.resolve_node(&st, n)?;
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            ids
        };
        if ids.is_empty() {
            bail!("name the nodes whose disks hold the volume: --nodes a,b,c");
        }
        if self.volume_defs().iter().any(|d| d.name == name && !d.removed) {
            bail!("there is a volume {name} already (meshvpn volume list)");
        }
        // Checked here if this node has the storage too (every node of the group checks it).
        if let Some(src) = &from {
            let p = std::path::Path::new(src);
            if p.is_dir() && !crate::volume::network_fs(p)? {
                bail!(
                    "{src} is not on a network file system: a volume is filled from storage every node of the \
                     group has mounted at the same path"
                );
            }
        }
        let def = Def {
            name: name.clone(),
            nodes: ids.clone(),
            source: from,
            copies: copies.min(ids.len() as u8).max(1),
            created: now_ms(),
            removed: false,
        };
        def.check()?;
        self.ext_publish(&format!("{KIND_PREFIX}{name}"), serde_json::to_string(&def)?)?;
        Ok(serde_json::json!({
            "name": name, "nodes": self.node_names(&ids), "mount": def.mount(), "copies": def.copies,
            "source": def.source,
        }))
    }

    /// `meshvpn volume delete`: every node unmounts it and deletes its chunks.
    pub fn volume_delete(&self, name: &str) -> Result<()> {
        let Some(mut def) = self.volume_defs().into_iter().find(|d| d.name == name && !d.removed) else {
            bail!("no volume {name} (see meshvpn volume list)");
        };
        def.removed = true;
        self.ext_publish(&format!("{KIND_PREFIX}{name}"), serde_json::to_string(&def)?)?;
        Ok(())
    }
}
