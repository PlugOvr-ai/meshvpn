//! `<name>.mesh` entries in /etc/hosts - a tiny stand-in for MagicDNS.

use anyhow::Result;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::keys::NodeId;

#[cfg(unix)]
const HOSTS: &str = "/etc/hosts";
#[cfg(windows)]
const HOSTS: &str = r"C:\Windows\System32\drivers\etc\hosts";
const BEGIN: &str = "# BEGIN meshvpn (managed automatically, do not edit)";
const END: &str = "# END meshvpn";

/// `suffix`: `mesh`, or `<network>.mesh` for a further network of this machine.
fn names(name: &str, suffix: &str) -> String {
    match suffix.strip_suffix(".mesh") {
        Some(net) => format!("{name}.{suffix} {name}.{net}"),
        None => format!("{name}.{suffix} {name}"),
    }
}

/// A node's names: to its IPv4 address (None: that one is another node's here) and its IPv6
/// address (None: no IPv6 here). Programs try the IPv4 address first where there are both.
pub struct Entry {
    pub name: String,
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
    pub id: NodeId,
}

pub fn render(entries: &[Entry], suffix: &str) -> String {
    let mut used = HashSet::new();
    let mut out = String::new();
    for Entry { name, v4, v6, id } in entries {
        // Two nodes with the same name: the later one gets its id appended.
        let name = if used.insert(name.clone()) {
            name.clone()
        } else {
            format!("{name}-{}", id.short())
        };
        for ip in v4.map(|i| i.to_string()).into_iter().chain(v6.map(|i| i.to_string())) {
            out.push_str(&format!("{ip}\t{}\n", names(&name, suffix)));
        }
    }
    out
}

/// An extension's extra names; names of nodes (`taken`) win.
pub fn render_aliases(aliases: &[(String, Ipv4Addr)], taken: &HashSet<String>, suffix: &str) -> String {
    let mut used = taken.clone();
    let mut out = String::new();
    for (name, ip) in aliases {
        if used.insert(name.clone()) {
            out.push_str(&format!("{ip}\t{}\n", names(name, suffix)));
        }
    }
    out
}

/// `network`: None for the machine's first network, else the further network's name; each has
/// its own block.
pub fn write(network: Option<&str>, block: Option<&str>) -> Result<()> {
    let (begin, end) = match network {
        Some(n) => (
            format!("# BEGIN meshvpn network {n} (managed automatically, do not edit)"),
            format!("# END meshvpn network {n}"),
        ),
        None => (BEGIN.to_string(), END.to_string()),
    };
    // One meshvpn per network writes its own block: without the lock, two writing at once
    // (both linking up to new nodes) would each put back the file without the other's block.
    // If the lock can't be had, write anyway, as before.
    let _lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(format!("{HOSTS}.meshvpn-lock"))
        .ok()
        .filter(|f| f.lock().is_ok());
    let current = std::fs::read_to_string(HOSTS).unwrap_or_default();
    let mut kept = String::new();
    let mut inside = false;
    for line in current.lines() {
        if line == begin {
            inside = true;
        } else if line == end {
            inside = false;
        } else if !inside {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    if let Some(b) = block {
        kept.push_str(&format!("{begin}\n{b}{end}\n"));
    }
    if kept != current {
        // Written in place: /etc/hosts is often a bind mount (containers).
        std::fs::write(HOSTS, kept)?;
        // macOS caches name lookups, /etc/hosts included.
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("dscacheutil").arg("-flushcache").status();
            let _ = std::process::Command::new("killall")
                .args(["-HUP", "mDNSResponder"])
                .status();
        }
        #[cfg(windows)]
        let _ = std::process::Command::new("ipconfig")
            .arg("/flushdns")
            .stdout(std::process::Stdio::null())
            .status();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_never_shadow_node_names() {
        let ip = |n| Ipv4Addr::new(100, 64, 0, n);
        let taken = HashSet::from(["dev1".to_string()]);
        let out = render_aliases(
            &[
                ("train42".into(), ip(2)),
                ("dev1".into(), ip(3)),
                ("train42".into(), ip(4)),
            ],
            &taken,
            "mesh",
        );
        assert_eq!(out, "100.64.0.2\ttrain42.mesh train42\n");
    }

    #[test]
    fn further_networks_have_their_own_names() {
        let id = crate::keys::Key32([7; 32]);
        let e = |v4, v6| Entry {
            name: "gpu1".into(),
            v4,
            v6,
            id,
        };
        let v4 = Some(Ipv4Addr::new(100, 64, 0, 9));
        let v6: Option<Ipv6Addr> = Some("fd12:3456:789a::1".parse().unwrap());
        let out = render(&[e(v4, None)], "lab.mesh");
        assert_eq!(out, "100.64.0.9\tgpu1.lab.mesh gpu1.lab\n");
        let out = render(&[e(v4, None)], "mesh");
        assert_eq!(out, "100.64.0.9\tgpu1.mesh gpu1\n");
        let out = render(&[e(v4, v6)], "mesh");
        assert_eq!(out, "100.64.0.9\tgpu1.mesh gpu1\nfd12:3456:789a::1\tgpu1.mesh gpu1\n");
        // Its IPv4 address is another node's here: by name over IPv6 only.
        let out = render(&[e(None, v6)], "lab.mesh");
        assert_eq!(out, "fd12:3456:789a::1\tgpu1.lab.mesh gpu1.lab\n");
    }
}
