//! `meshvpn gpu`: reserving GPUs across nodes. The node with the GPUs grants a reservation
//! (locally through its daemon, remotely through `meshvpn gpu reserve-local` over SSH), so
//! reservations never collide, and every node sees them in the records.

use anyhow::{Result, anyhow, bail};
use serde::Serialize;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::agent::{self, NodeView, Remote, sh_quote};
use crate::control::{self, Request, Response};
use crate::proto::Lease;

#[derive(Serialize, serde::Deserialize, Clone)]
pub struct Grant {
    pub node: String,
    #[serde(flatten)]
    pub lease: Lease,
    /// Ready to export on that node.
    pub cuda_visible_devices: String,
}

impl Grant {
    fn new(node: &str, lease: Lease) -> Self {
        let cvd = lease.gpus.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(",");
        Grant {
            node: node.into(),
            lease,
            cuda_visible_devices: cvd,
        }
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// The account behind this request, for the reservation's holder text.
pub fn default_holder(note: Option<&str>) -> String {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let who = format!("{}@{}", Remote::default_user(), host.trim());
    match note {
        Some(n) => format!("{n} ({who})"),
        None => who,
    }
}

fn local(dir: &Path, req: &Request) -> Result<Lease> {
    let rt = tokio::runtime::Runtime::new()?;
    match rt.block_on(control::request(dir, req))? {
        Response::Message { text } => Ok(serde_json::from_str(&text)?),
        _ => bail!("unexpected answer from meshvpn"),
    }
}

/// Runs `meshvpn gpu <args> --json` on `node` and parses the lease it prints.
fn remote_call(node: &NodeView, remote: &Remote, args: &str) -> Result<Lease> {
    let r = agent::exec(
        std::slice::from_ref(node),
        remote,
        &[format!("meshvpn --json gpu {args}")],
    )
    .pop()
    .ok_or_else(|| anyhow!("no result"))?;
    let out = r.stdout.trim();
    if let Ok(lease) = serde_json::from_str::<Lease>(out) {
        return Ok(lease);
    }
    let msg = serde_json::from_str::<serde_json::Value>(out)
        .ok()
        .and_then(|v| v["error"].as_str().map(String::from))
        .unwrap_or_else(|| format!("{out} {}", r.stderr.trim()));
    bail!("{}: {}", node.name, msg.trim())
}

pub fn reserve_on(
    dir: &Path,
    node: &NodeView,
    remote: &Remote,
    count: u32,
    indices: Option<&[u32]>,
    ttl_ms: u64,
    holder: &str,
) -> Result<Grant> {
    let lease = if node.is_self {
        local(
            dir,
            &Request::GpuReserve {
                count: Some(count),
                indices: indices.map(|i| i.to_vec()),
                ttl_ms,
                holder: holder.into(),
            },
        )?
    } else {
        let pick = match indices {
            Some(i) => format!(
                "--gpus {}",
                i.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(",")
            ),
            None => format!("--count {count}"),
        };
        remote_call(
            node,
            remote,
            &format!("reserve-local {pick} --ttl-ms {ttl_ms} --holder {}", sh_quote(holder)),
        )?
    };
    Ok(Grant::new(&node.name, lease))
}

pub fn release_on(dir: &Path, node: &NodeView, remote: &Remote, id: &str) -> Result<Grant> {
    let lease = if node.is_self {
        local(dir, &Request::GpuRelease { id: id.into() })?
    } else {
        remote_call(node, remote, &format!("release-local {}", sh_quote(id)))?
    };
    Ok(Grant::new(&node.name, lease))
}

pub fn renew_on(dir: &Path, node: &NodeView, remote: &Remote, id: &str, ttl_ms: u64) -> Result<Grant> {
    let lease = if node.is_self {
        local(dir, &Request::GpuRenew { id: id.into(), ttl_ms })?
    } else {
        remote_call(node, remote, &format!("renew-local {} --ttl-ms {ttl_ms}", sh_quote(id)))?
    };
    Ok(Grant::new(&node.name, lease))
}

/// `count` GPUs on every node, all or nothing.
pub fn reserve_all(
    dir: &Path,
    nodes: &[NodeView],
    remote: &Remote,
    count: u32,
    ttl_ms: u64,
    holder: &str,
) -> Result<Vec<Grant>> {
    let results: Vec<Result<Grant>> = std::thread::scope(|s| {
        let hs: Vec<_> = nodes
            .iter()
            .map(|n| s.spawn(|| reserve_on(dir, n, remote, count, None, ttl_ms, holder)))
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let errors: Vec<String> = results
        .iter()
        .filter_map(|r| r.as_ref().err().map(|e| format!("{e:#}")))
        .collect();
    let grants: Vec<Grant> = results.into_iter().filter_map(Result::ok).collect();
    if !errors.is_empty() {
        for g in &grants {
            if let Some(n) = nodes.iter().find(|n| n.name == g.node) {
                let _ = release_on(dir, n, remote, &g.lease.id);
            }
        }
        bail!("could not reserve GPUs: {}", errors.join("; "));
    }
    Ok(grants)
}

/// The node holding reservation `id` (as gossiped).
pub fn find_lease<'a>(nodes: &'a [NodeView], id: &str) -> Result<&'a NodeView> {
    nodes
        .iter()
        .find(|n| n.leases.iter().any(|l| l.id == id))
        .ok_or_else(|| anyhow!("reservation {id} not found (see meshvpn gpu list)"))
}

#[derive(Serialize)]
pub struct GpuRow {
    pub node: String,
    pub index: u32,
    pub name: String,
    pub mem_total_mb: u64,
    pub mem_used_mb: u64,
    pub util_pct: u32,
    /// free, busy or reserved
    pub state: String,
    pub reservation: Option<Lease>,
}

pub fn rows(nodes: &[NodeView]) -> Vec<GpuRow> {
    let mut out = vec![];
    for n in nodes {
        let Some(inv) = &n.inventory else { continue };
        for g in &inv.gpus {
            let lease = n
                .leases
                .iter()
                .find(|l| l.gpus.contains(&g.index) && l.expires > now_ms());
            let busy = g.util_pct >= 10 || g.mem_used_mb * 10 >= g.mem_total_mb.max(1);
            out.push(GpuRow {
                node: n.name.clone(),
                index: g.index,
                name: g.name.replace("NVIDIA ", ""),
                mem_total_mb: g.mem_total_mb,
                mem_used_mb: g.mem_used_mb,
                util_pct: g.util_pct,
                state: if lease.is_some() {
                    "reserved".into()
                } else if busy {
                    "busy".into()
                } else {
                    "free".into()
                },
                reservation: lease.cloned(),
            });
        }
    }
    out
}

pub fn print_rows(rows: &[GpuRow]) {
    if rows.is_empty() {
        println!("No GPUs found on the selected nodes.");
        return;
    }
    let w = rows.iter().map(|r| r.node.len()).max().unwrap_or(4).max(4);
    println!(
        "{:<w$}  GPU  {:<22}  {:>15}  {:>4}  STATE",
        "NODE", "MODEL", "MEMORY", "UTIL"
    );
    for r in rows {
        let state = match &r.reservation {
            Some(l) => format!(
                "reserved {} by {} ({} min left)",
                l.id,
                l.holder,
                l.expires.saturating_sub(now_ms()) / 60_000
            ),
            None => r.state.clone(),
        };
        println!(
            "{:<w$}  {:>3}  {:<22}  {:>6}/{:>6} MB  {:>3}%  {state}",
            r.node, r.index, r.name, r.mem_used_mb, r.mem_total_mb, r.util_pct
        );
    }
}
