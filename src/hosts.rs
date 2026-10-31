//! `<name>.mesh` entries in /etc/hosts - a tiny stand-in for MagicDNS.

use anyhow::Result;
use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::keys::NodeId;

#[cfg(unix)]
const HOSTS: &str = "/etc/hosts";
#[cfg(windows)]
const HOSTS: &str = r"C:\Windows\System32\drivers\etc\hosts";
const BEGIN: &str = "# BEGIN meshvpn (managed automatically, do not edit)";
const END: &str = "# END meshvpn";

pub fn render(entries: &[(String, Ipv4Addr, NodeId)]) -> String {
    let mut used = HashSet::new();
    let mut out = String::new();
    for (name, ip, id) in entries {
        // Two nodes with the same name: the later one gets its id appended.
        let name = if used.insert(name.clone()) {
            name.clone()
        } else {
            format!("{name}-{}", id.short())
        };
        out.push_str(&format!("{ip}\t{name}.mesh {name}\n"));
    }
    out
}

/// An extension's extra names; names of nodes (`taken`) win.
pub fn render_aliases(aliases: &[(String, Ipv4Addr)], taken: &HashSet<String>) -> String {
    let mut used = taken.clone();
    let mut out = String::new();
    for (name, ip) in aliases {
        if used.insert(name.clone()) {
            out.push_str(&format!("{ip}\t{name}.mesh {name}\n"));
        }
    }
    out
}

pub fn write(block: Option<&str>) -> Result<()> {
    let current = std::fs::read_to_string(HOSTS).unwrap_or_default();
    let mut kept = String::new();
    let mut inside = false;
    for line in current.lines() {
        if line == BEGIN {
            inside = true;
        } else if line == END {
            inside = false;
        } else if !inside {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    if let Some(b) = block {
        kept.push_str(&format!("{BEGIN}\n{b}{END}\n"));
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
        );
        assert_eq!(out, "100.64.0.2\ttrain42.mesh train42\n");
    }
}
