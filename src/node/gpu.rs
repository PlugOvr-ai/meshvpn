//! GPU reservations: the node that owns the GPUs grants them, so two agents can never get the
//! same GPU. Reservations expire unless renewed and are published in the node's record.
//! They are advisory (like Slurm without cgroups): honoured by meshvpn launch and agents that
//! use CUDA_VISIBLE_DEVICES, not enforced against other programs.
//!
//! A machine in several networks has the same GPUs in each: the networks share their
//! reservations through a file in the base directory (locked while one reserves), and each
//! shows the others' to its nodes as taken, without who holds them.

use super::*;
use std::io::{Read, Seek, Write};

/// Reservations last at most this long without a renewal (30 days).
const MAX_LEASE_MS: u64 = 30 * 24 * 3600 * 1000;
/// The networks' reservations on this machine: network name ("" for the first) -> its leases.
const SHARED: &str = "gpu-reservations.json";
const FOREIGN_HOLDER: &str = "reserved in another network on this machine";

type Shared = std::collections::BTreeMap<String, Vec<Lease>>;

/// The shared file, open and locked (until it is dropped), and what it holds.
fn lock_shared(path: &std::path::Path) -> Option<(std::fs::File, Shared)> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path).ok()?;
    f.lock().ok()?;
    let mut text = String::new();
    let _ = f.read_to_string(&mut text);
    Some((f, serde_json::from_str(&text).unwrap_or_default()))
}

fn write_shared(f: &mut std::fs::File, map: &Shared) {
    let Ok(text) = serde_json::to_vec(map) else { return };
    let _ = f.set_len(0);
    let _ = f.rewind();
    let _ = f.write_all(&text);
}

impl Node {
    fn shared_file(&self) -> PathBuf {
        crate::networks::base(&self.dir).join(SHARED)
    }

    fn network_key(&self) -> String {
        crate::networks::name(&self.dir).unwrap_or_default()
    }

    /// The other networks' current reservations (of networks still on this machine), as this
    /// network shows them: without holder and owner.
    fn foreign_leases(&self, map: &Shared) -> Vec<Lease> {
        let me = self.network_key();
        let live: HashSet<String> = crate::networks::all(&crate::networks::base(&self.dir))
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        let now = now_ms();
        let mut out: Vec<Lease> = map
            .iter()
            .filter(|(n, _)| **n != me && live.contains(*n))
            .flat_map(|(_, l)| l)
            .filter(|l| l.expires > now && !l.gpus.is_empty())
            .map(|l| Lease {
                id: l.id.clone(),
                gpus: l.gpus.clone(),
                holder: FOREIGN_HOLDER.into(),
                expires: l.expires,
                owner: None,
            })
            .collect();
        out.truncate(32);
        out
    }

    /// Ours and the other networks' reservations, as the record shows them.
    pub(super) fn published_leases(st: &State) -> Vec<Lease> {
        let mut all = st.leases.clone();
        all.extend(st.foreign_leases.iter().cloned());
        all.truncate(64);
        all
    }

    /// Tells the other networks on this machine our reservations, and takes theirs (from the
    /// tick, and after every change).
    pub(super) fn share_leases(&self) {
        let Some((mut f, mut map)) = lock_shared(&self.shared_file()) else {
            return;
        };
        let foreign = self.foreign_leases(&map);
        let mine = {
            let mut st = self.state.lock().unwrap();
            Self::prune_leases(&mut st);
            if st.foreign_leases != foreign {
                st.foreign_leases = foreign;
                self.announce(&mut st);
            }
            st.leases.clone()
        };
        let me = self.network_key();
        if map.get(&me).cloned().unwrap_or_default() != mine {
            if mine.is_empty() {
                map.remove(&me);
            } else {
                map.insert(me, mine);
            }
            write_shared(&mut f, &map);
        }
    }

    fn prune_leases(st: &mut State) -> bool {
        let before = st.leases.len();
        let now = now_ms();
        st.leases.retain(|l| l.expires > now);
        st.leases.len() != before
    }

    /// Reserves `count` idle GPUs, or exactly `indices`.
    pub fn gpu_reserve(
        &self,
        count: Option<u32>,
        indices: Option<Vec<u32>>,
        ttl_ms: u64,
        holder: String,
        owner: Option<String>,
    ) -> Result<Lease> {
        if !crate::proto::clean_text(&holder) {
            bail!("invalid holder text");
        }
        // The other networks' reservations count too; the file stays locked until ours is in
        // it, so two networks can't take the same GPU at once.
        let mut shared = lock_shared(&self.shared_file());
        let foreign = shared.as_ref().map(|(_, m)| self.foreign_leases(m)).unwrap_or_default();
        let mut st = self.state.lock().unwrap();
        Self::prune_leases(&mut st);
        st.foreign_leases = foreign;
        let gpus = st.inventory.as_ref().map(|i| i.gpus.clone()).unwrap_or_default();
        if gpus.is_empty() {
            bail!("{} has no GPUs (none found by nvidia-smi)", st.my_name);
        }
        let elsewhere: Vec<u32> = st.foreign_leases.iter().flat_map(|l| l.gpus.iter().copied()).collect();
        let reserved: Vec<u32> = st
            .leases
            .iter()
            .flat_map(|l| l.gpus.iter().copied())
            .chain(elsewhere.iter().copied())
            .collect();
        let picked: Vec<u32> = match indices {
            Some(mut want) => {
                // At least one GPU, each once: a reservation of none (or the same GPU twice)
                // would let anyone fill the record with reservations until others refuse it.
                want.sort_unstable();
                want.dedup();
                if want.is_empty() {
                    bail!("name at least one GPU to reserve");
                }
                for g in &want {
                    if !gpus.iter().any(|x| x.index == *g) {
                        bail!("{} has no GPU {g}", st.my_name);
                    }
                    if elsewhere.contains(g) {
                        bail!(
                            "GPU {g} on {} is reserved in another network on this machine",
                            st.my_name
                        );
                    }
                    if reserved.contains(g) {
                        bail!("GPU {g} on {} is already reserved", st.my_name);
                    }
                }
                want
            }
            None => {
                let n = count.unwrap_or(1).max(1) as usize;
                let idle: Vec<u32> = gpus
                    .iter()
                    .filter(|g| !reserved.contains(&g.index))
                    .filter(|g| g.util_pct < 10 && g.mem_used_mb * 10 < g.mem_total_mb.max(1))
                    .map(|g| g.index)
                    .collect();
                if idle.len() < n {
                    let busy = gpus.len() - reserved.len() - idle.len();
                    bail!(
                        "{} needed, but only {} of the {} GPUs on {} are free ({} reserved, {busy} busy)",
                        n,
                        idle.len(),
                        gpus.len(),
                        st.my_name,
                        reserved.len()
                    );
                }
                idle[..n].to_vec()
            }
        };
        let mut id = [0u8; 6];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let lease = Lease {
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            gpus: picked,
            holder,
            expires: now_ms().saturating_add(ttl_ms.min(MAX_LEASE_MS)),
            owner,
        };
        st.leases.push(lease.clone());
        self.announce(&mut st);
        let mine = st.leases.clone();
        drop(st);
        if let Some((f, map)) = &mut shared {
            map.insert(self.network_key(), mine);
            write_shared(f, map);
        }
        drop(shared);
        self.save_state();
        Ok(lease)
    }

    /// May `caller` change lease `l`? Whoever made it, and root.
    fn lease_mine(l: &Lease, caller: &crate::ext::Caller) -> Result<()> {
        if caller.privileged || (l.owner.is_some() && l.owner == caller.user) {
            return Ok(());
        }
        bail!(
            "reservation {} is {}'s - only they (or root) can release or renew it",
            l.id,
            l.owner.as_deref().unwrap_or("root")
        )
    }

    pub fn gpu_release(&self, id: &str, caller: &crate::ext::Caller) -> Result<Lease> {
        let mut st = self.state.lock().unwrap();
        if st.foreign_leases.iter().any(|l| l.id == id) {
            bail!("reservation {id} was made in another network on this machine - release it there");
        }
        let pos = st
            .leases
            .iter()
            .position(|l| l.id == id)
            .ok_or_else(|| anyhow!("reservation {id} not found on {}", st.my_name))?;
        Self::lease_mine(&st.leases[pos], caller)?;
        let lease = st.leases.remove(pos);
        self.announce(&mut st);
        drop(st);
        self.save_state();
        self.share_leases();
        Ok(lease)
    }

    pub fn gpu_renew(&self, id: &str, ttl_ms: u64, caller: &crate::ext::Caller) -> Result<Lease> {
        let mut st = self.state.lock().unwrap();
        Self::prune_leases(&mut st);
        let my_name = st.my_name.clone();
        let lease = st
            .leases
            .iter_mut()
            .find(|l| l.id == id)
            .ok_or_else(|| anyhow!("reservation {id} not found on {my_name} (expired?)"))?;
        Self::lease_mine(lease, caller)?;
        lease.expires = now_ms().saturating_add(ttl_ms.min(MAX_LEASE_MS));
        let lease = lease.clone();
        self.announce(&mut st);
        drop(st);
        self.save_state();
        self.share_leases();
        Ok(lease)
    }

    /// Called from the tick: expired reservations free their GPUs.
    pub(super) fn expire_leases(&self, st: &mut State) {
        if Self::prune_leases(st) {
            info!("GPU reservation(s) expired");
            self.announce(st);
        }
    }
}
