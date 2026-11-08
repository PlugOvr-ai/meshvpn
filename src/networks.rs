//! Several networks on one machine.
//!
//! The first network lives in the base directory (`/etc/meshvpn`, or `~/.config/meshvpn` for a
//! rootless install), as always. Each further one gets `<base>/networks/<name>/`, with its own
//! interface (`mesh1`, ...), port, service and names: its nodes are `<node>.<name>.mesh`.
//!
//! All networks use addresses from 100.64.0.0/10, which only the first one routes as a whole.
//! A further network routes just the addresses of its own nodes, so nothing changes for the
//! other nodes of either network.

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

use crate::config::{Config, DEFAULT_PORT};

const SUBDIR: &str = "networks";

/// The base directory of `dir`: itself for the first network.
pub fn base(dir: &Path) -> PathBuf {
    match name(dir) {
        Some(_) => dir
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_default(),
        None => dir.to_path_buf(),
    }
}

/// The name of a further network, None for the first one.
pub fn name(dir: &Path) -> Option<String> {
    if dir.parent()?.file_name()? != SUBDIR {
        return None;
    }
    dir.file_name()?.to_str().map(String::from)
}

/// Is `dir` a further network (not the machine's first)?
pub fn is_extra(dir: &Path) -> bool {
    name(dir).is_some()
}

pub fn dir_of(base: &Path, name: &str) -> PathBuf {
    base.join(SUBDIR).join(name)
}

/// What names of this network's nodes end in: `mesh`, or `<name>.mesh` for a further network.
pub fn suffix(dir: &Path) -> String {
    match name(dir) {
        Some(n) => format!("{n}.mesh"),
        None => "mesh".into(),
    }
}

/// Every network of this machine: (name, directory), the first one as "" and first.
pub fn all(base: &Path) -> Vec<(String, PathBuf)> {
    let mut out = vec![];
    if Config::path(base).exists() {
        out.push((String::new(), base.to_path_buf()));
    }
    let mut extra: Vec<(String, PathBuf)> = std::fs::read_dir(base.join(SUBDIR))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| Config::path(&e.path()).exists())
        .filter_map(|e| Some((e.file_name().to_str()?.to_string(), e.path())))
        .collect();
    extra.sort();
    out.extend(extra);
    out
}

/// A network's name as people see it: the further network's own, else the network's label.
pub fn display_name(dir: &Path) -> String {
    name(dir).unwrap_or_else(|| Config::load(dir).map(|c| c.network).unwrap_or_else(|_| "mesh".into()))
}

/// Valid as a network name here: a DNS label, and not one the names would clash with.
pub fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if !ok {
        bail!("{name:?} can't be the name of a network: use a-z, 0-9 and -, at most 32 characters");
    }
    if name == "mesh" {
        bail!(
            "\"mesh\" can't be the name of a further network (its nodes would be <node>.mesh.mesh): pick another with --net"
        );
    }
    Ok(())
}

/// A name for a new further network, from its label: free, and valid.
pub fn new_name(base: &Path, label: &str) -> String {
    let mut stem: String = crate::config::sanitize_name(label)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    stem = stem.trim_matches('-').chars().take(24).collect();
    if stem.is_empty() || stem == "mesh" {
        stem = "net".into();
    }
    let taken = |n: &str| dir_of(base, n).exists() || Config::load(base).is_ok_and(|c| c.network == n && n == "mesh");
    if !taken(&stem) && check_name(&stem).is_ok() {
        return stem;
    }
    (2..).map(|i| format!("{stem}{i}")).find(|n| !taken(n)).unwrap()
}

/// The further network of `base` that is network `id`, if this machine is in it already.
pub fn find_id(base: &Path, id: &str) -> Option<PathBuf> {
    all(base)
        .into_iter()
        .find(|(_, d)| Config::load(d).is_ok_and(|c| c.network_id() == id))
        .map(|(_, d)| d)
}

/// Interface, port and SOCKS address that no other network of this machine uses.
pub fn free_slot(base: &Path) -> (String, u16, String) {
    let cfgs: Vec<Config> = all(base).iter().filter_map(|(_, d)| Config::load(d).ok()).collect();
    let iface = (1..)
        .map(|i| format!("mesh{i}"))
        .find(|i| cfgs.iter().all(|c| &c.interface != i))
        .unwrap();
    // Not the ports meshvpn uses for other things.
    let port = (DEFAULT_PORT + 1..)
        .filter(|p| *p != crate::share::PORT)
        .find(|p| cfgs.iter().all(|c| c.listen_port() != Some(*p)))
        .unwrap();
    let socks = (1056..)
        .map(|p| format!("127.0.0.1:{p}"))
        .find(|s| cfgs.iter().all(|c| &c.socks_listen != s))
        .unwrap();
    (iface, port, socks)
}

/// Which network a command means when it names `node` and none was chosen: the other network
/// that knows the node, if exactly one does and the first one doesn't.
pub fn network_of_node(base: &Path, node: &str) -> Option<String> {
    let node = node.trim_end_matches('.').to_lowercase();
    // `<node>.<network>.mesh` and `<node>.<network>` say it themselves.
    for (n, _) in all(base).into_iter().filter(|(n, _)| !n.is_empty()) {
        if node.ends_with(&format!(".{n}.mesh")) || node.ends_with(&format!(".{n}")) {
            return Some(n);
        }
    }
    let plain = node.strip_suffix(".mesh").unwrap_or(&node).to_string();
    let knows = |d: &Path| known_names(d).contains(&plain);
    if knows(base) {
        return None;
    }
    let mut found = all(base).into_iter().filter(|(n, d)| !n.is_empty() && knows(d));
    match (found.next(), found.next()) {
        (Some((n, _)), None) => Some(n),
        _ => None,
    }
}

/// Names of the nodes a network knows: from its daemon, else from what it saved.
fn known_names(dir: &Path) -> Vec<String> {
    let Ok(cfg) = Config::load(dir) else { return vec![] };
    let asked = tokio::runtime::Runtime::new().ok().and_then(|rt| {
        rt.block_on(crate::control::request(dir, &crate::control::Request::Status))
            .ok()
    });
    if let Some(crate::control::Response::Status(st)) = asked {
        let mut names: Vec<String> = st.peers.into_iter().map(|p| p.name).collect();
        names.push(st.name);
        return names;
    }
    let net = cfg.network_id();
    let mut names: Vec<String> = crate::config::SavedState::load(dir)
        .peers
        .iter()
        .filter_map(|p| p.verify(&net).ok())
        .map(|i| i.name)
        .collect();
    names.push(cfg.name);
    names
}

static CURRENT: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// The network this process works with, decided at startup (and again when a command goes to
/// the network of the node it names).
pub fn set_current(dir: &Path) {
    *CURRENT.lock().unwrap() = Some(std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf()));
}

fn current() -> Option<PathBuf> {
    CURRENT.lock().unwrap().clone()
}

/// What node names end in, in the network this process works with.
pub fn current_suffix() -> String {
    current().map(|d| suffix(&d)).unwrap_or_else(|| "mesh".into())
}

/// `meshvpn nc` for ssh's ProxyCommand reaches the network this process works with.
pub fn current_dir_args() -> String {
    match current().filter(|d| is_extra(d)) {
        Some(d) => format!(" --dir {}", crate::agent::sh_quote(&d.to_string_lossy())),
        None => String::new(),
    }
}

/// Strips what names of nodes of `dir`'s network end in: `<node>.mesh`, or `<node>.<name>.mesh`
/// and `<node>.<name>` for a further network.
pub fn strip_suffix<'a>(dir: &Path, host: &'a str) -> &'a str {
    match name(dir) {
        Some(n) => host
            .strip_suffix(&format!(".{n}.mesh"))
            .or_else(|| host.strip_suffix(&format!(".{n}")))
            .unwrap_or(host),
        None => host.strip_suffix(".mesh").unwrap_or(host),
    }
}

/// Userspace mode: where a further network's share server listens on this machine, as the
/// first network's has port 7871 of 127.0.0.1 (Linux answers on all of 127.0.0.0/8; macOS gets
/// it as an alias of lo0).
pub fn share_loopback(dir: &Path) -> Option<std::net::Ipv4Addr> {
    let n = name(dir)?;
    let h = blake3::hash(n.as_bytes());
    let b = h.as_bytes();
    Some(std::net::Ipv4Addr::new(127, 77, b[0], b[1].max(1)))
}

/// The service of a network: `meshvpn`, or `meshvpn-<name>` for a further one.
pub fn service(dir: &Path) -> String {
    match name(dir) {
        Some(n) => format!("meshvpn-{n}"),
        None => "meshvpn".into(),
    }
}

/// `--net NAME`, for commands that use it in suggestions ("" for the first network).
pub fn flag(dir: &Path) -> String {
    match name(dir) {
        Some(n) => format!(" --net {n}"),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_places() {
        let base = std::env::temp_dir().join(format!("mv-networks-{}", std::process::id()));
        let lab = dir_of(&base, "lab");
        assert_eq!(name(&lab).as_deref(), Some("lab"));
        assert_eq!(name(&base), None);
        assert_eq!(base_of_test(&lab), base);
        assert_eq!(suffix(&lab), "lab.mesh");
        assert_eq!(suffix(&base), "mesh");
        assert_eq!(service(&lab), "meshvpn-lab");
        assert_eq!(service(&base), "meshvpn");
        assert!(check_name("lab-2").is_ok());
        assert!(check_name("mesh").is_err());
        assert!(check_name("Lab").is_err());
        assert!(check_name("-x").is_err());
        assert_eq!(new_name(&base, "My Lab!"), "my-lab");
        assert_eq!(new_name(&base, "mesh"), "net");
        std::fs::create_dir_all(dir_of(&base, "net")).unwrap();
        assert_eq!(new_name(&base, "mesh"), "net2");
        std::fs::remove_dir_all(&base).ok();
    }

    fn base_of_test(dir: &Path) -> PathBuf {
        base(dir)
    }
}
