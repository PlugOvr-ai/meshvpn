//! GPU reservations: the node that owns the GPUs grants them, so two agents can never get the
//! same GPU. Reservations expire unless renewed and are published in the node's record.
//! They are advisory (like Slurm without cgroups): honoured by meshvpn launch and agents that
//! use CUDA_VISIBLE_DEVICES, not enforced against other programs.

use super::*;

impl Node {
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
    ) -> Result<Lease> {
        if !crate::proto::clean_text(&holder) {
            bail!("invalid holder text");
        }
        let mut st = self.state.lock().unwrap();
        Self::prune_leases(&mut st);
        let gpus = st.inventory.as_ref().map(|i| i.gpus.clone()).unwrap_or_default();
        if gpus.is_empty() {
            bail!("{} has no GPUs (none found by nvidia-smi)", st.my_name);
        }
        let reserved: Vec<u32> = st.leases.iter().flat_map(|l| l.gpus.iter().copied()).collect();
        let picked: Vec<u32> = match indices {
            Some(want) => {
                for g in &want {
                    if !gpus.iter().any(|x| x.index == *g) {
                        bail!("{} has no GPU {g}", st.my_name);
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
            expires: now_ms() + ttl_ms,
        };
        st.leases.push(lease.clone());
        self.announce(&mut st);
        drop(st);
        self.save_state();
        Ok(lease)
    }

    pub fn gpu_release(&self, id: &str) -> Result<Lease> {
        let mut st = self.state.lock().unwrap();
        let pos = st
            .leases
            .iter()
            .position(|l| l.id == id)
            .ok_or_else(|| anyhow!("reservation {id} not found on {}", st.my_name))?;
        let lease = st.leases.remove(pos);
        self.announce(&mut st);
        drop(st);
        self.save_state();
        Ok(lease)
    }

    pub fn gpu_renew(&self, id: &str, ttl_ms: u64) -> Result<Lease> {
        let mut st = self.state.lock().unwrap();
        Self::prune_leases(&mut st);
        let my_name = st.my_name.clone();
        let lease = st
            .leases
            .iter_mut()
            .find(|l| l.id == id)
            .ok_or_else(|| anyhow!("reservation {id} not found on {my_name} (expired?)"))?;
        lease.expires = now_ms() + ttl_ms;
        let lease = lease.clone();
        self.announce(&mut st);
        drop(st);
        self.save_state();
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
