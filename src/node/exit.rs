//! Exit nodes: a node can offer its internet connection to the mesh (`meshvpn exit offer`),
//! others send their internet traffic through it (`meshvpn exit use <node>`).
//!
//! The exit forwards and masquerades packets from mesh addresses, but only to public internet
//! addresses - never into its own LAN or the mesh. A kernel-mode client gets a default route
//! into the mesh in its own routing table, as wg-quick does: meshvpn's own sockets carry a
//! firewall mark and keep using the normal table, so do replies on connections that came in from
//! outside (SSH from the internet keeps working), and so do the machine's LANs. In userspace mode
//! the SOCKS proxy sends internet connections through the exit.

use super::*;
use std::process::Command;

/// Routing table and firewall mark of an exit client.
const TABLE: &str = "7870";
pub(crate) const FWMARK: u32 = 0x7870;
const COMMENT: &str = "meshvpn-exit";

/// Puts meshvpn's own traffic on the normal routing table, around an exit node's default route.
/// Needs CAP_NET_ADMIN; without it there is no exit routing either.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub(crate) fn mark_socket(fd: std::os::fd::RawFd) {
    #[cfg(target_os = "linux")]
    unsafe {
        let mark = FWMARK;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
    }
}

/// Addresses an exit forwards to: the public internet, not private networks, the mesh,
/// loopback, link-local, multicast or other special ranges.
pub(crate) fn is_public(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && b & 0xc0 == 64) // shared / CGNAT, the mesh
        || (a == 192 && b == 0)
        || (a == 198 && (b & 0xfe) == 18) // benchmarking
        || a >= 240)
}

fn run(args: &[&str]) -> Result<()> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| anyhow!("{}: {e}", args[0]))?;
    if !out.status.success() {
        bail!("{}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// `iptables` rule `spec` in `table`/`chain`, added once (`add`) or removed (`!add`).
fn iptables(table: &str, chain: &str, spec: &[&str], add: bool, insert: bool) -> Result<()> {
    let exists = |args: &[&str]| run(&[&["iptables", "-w", "-t", table, "-C", chain], args].concat()).is_ok();
    let spec = [spec, &["-m", "comment", "--comment", COMMENT]].concat();
    if add {
        if !exists(&spec) {
            run(&[
                &["iptables", "-w", "-t", table, if insert { "-I" } else { "-A" }, chain],
                &spec[..],
            ]
            .concat())?;
        }
    } else {
        while exists(&spec) {
            run(&[&["iptables", "-w", "-t", table, "-D", chain], &spec[..]].concat())?;
        }
    }
    Ok(())
}

fn need_iptables() -> Result<()> {
    if Command::new("iptables").arg("--version").output().is_err() {
        bail!("exit nodes need iptables (e.g. apt install iptables)");
    }
    Ok(())
}

/// The exit's side: forwarding and NAT for the mesh.
fn serve_exit(iface: &str, on: bool) -> Result<()> {
    need_iptables()?;
    let mesh = "100.64.0.0/10";
    iptables(
        "nat",
        "POSTROUTING",
        &["-s", mesh, "!", "-o", iface, "-j", "MASQUERADE"],
        on,
        false,
    )?;
    // Hosts with Docker drop forwarded packets by default.
    iptables(
        "filter",
        "FORWARD",
        &["-i", iface, "!", "-o", iface, "-j", "ACCEPT"],
        on,
        true,
    )?;
    iptables(
        "filter",
        "FORWARD",
        &[
            "-o",
            iface,
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        on,
        true,
    )?;
    for dir in ["-i", "-o"] {
        iptables(
            "mangle",
            "FORWARD",
            &[
                dir,
                iface,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ],
            on,
            false,
        )?;
    }
    let fwd = "/proc/sys/net/ipv4/ip_forward";
    if on && std::fs::read_to_string(fwd).unwrap_or_default().trim() != "1" {
        std::fs::write(fwd, "1").map_err(|e| {
            anyhow!(
                "enabling IP forwarding: {e}{}",
                if crate::userspace::in_container() {
                    " - start the container with --sysctl net.ipv4.ip_forward=1"
                } else {
                    ""
                }
            )
        })?;
    }
    Ok(())
}

/// The client's side: default route into the mesh, except for meshvpn itself, LANs and
/// connections that came in from outside.
fn use_exit(iface: &str, on: bool) -> Result<()> {
    need_iptables()?;
    let mark = format!("{FWMARK:#x}");
    // Replies on connections that came in from outside keep using the normal routes.
    iptables(
        "mangle",
        "PREROUTING",
        &[
            "!",
            "-i",
            iface,
            "-m",
            "addrtype",
            "--dst-type",
            "LOCAL",
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-j",
            "CONNMARK",
            "--set-mark",
            &mark,
        ],
        on,
        false,
    )?;
    iptables(
        "mangle",
        "OUTPUT",
        &["-m", "connmark", "--mark", &mark, "-j", "MARK", "--set-mark", &mark],
        on,
        false,
    )?;
    let _ = run(&["ip", "rule", "del", "priority", "7868"]);
    let _ = run(&["ip", "rule", "del", "priority", "7869"]);
    let _ = run(&["ip", "route", "flush", "table", TABLE]);
    if on {
        run(&["ip", "route", "replace", "default", "dev", iface, "table", TABLE])?;
        // More specific routes (LANs, Docker, the mesh) still win over the exit's default.
        run(&[
            "ip",
            "rule",
            "add",
            "priority",
            "7868",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ])?;
        run(&[
            "ip", "rule", "add", "priority", "7869", "not", "fwmark", &mark, "table", TABLE,
        ])?;
    }
    Ok(())
}

impl Node {
    fn kernel_mode(&self) -> bool {
        matches!(self.io, PacketIo::Tun(_))
    }

    /// Our internet traffic goes through an exit node.
    pub(crate) fn exit_active(&self) -> bool {
        self.state.lock().unwrap().exit_via.is_some()
    }

    /// The node that carries packets for `dst_ip` outside the mesh: our exit, if any.
    pub(super) fn exit_for(&self, st: &State, dst_ip: Ipv4Addr) -> Option<NodeId> {
        (!is_overlay(IpAddr::V4(dst_ip))).then_some(st.exit_via).flatten()
    }

    /// Is this packet from `src` (already decrypted) allowed in? Its source address must be the
    /// sender's own, except for internet replies relayed by our exit.
    pub(super) fn source_ok(&self, src: &NodeId, pkt: &[u8]) -> bool {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return false;
        }
        let from = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        if from == overlay_ip(src) {
            return self.owns_ip(src);
        }
        let st = self.state.lock().unwrap();
        st.exit_via == Some(*src) && is_public(from)
    }

    /// May a packet from the mesh go on to its destination here? Ours, or the internet if we
    /// are an exit.
    pub(super) fn may_deliver(&self, pkt: &[u8]) -> bool {
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        dst == self.my_ip || (is_public(dst) && self.state.lock().unwrap().exit_offer)
    }

    /// Applies the saved exit settings when meshvpn starts.
    pub(super) fn exit_start(&self) {
        let (offer, via) = {
            let st = self.state.lock().unwrap();
            (st.exit_offer, st.exit_via.is_some())
        };
        if offer && let Err(e) = self.exit_offer_system(true) {
            warn!("offering this node as exit: {e:#}");
        }
        if via
            && self.kernel_mode()
            && let Err(e) = use_exit(&self.cfg.interface, true)
        {
            warn!("routing internet traffic through the exit node: {e:#}");
        }
    }

    /// Takes the routes and firewall rules away again when meshvpn stops.
    pub(super) fn exit_stop(&self) {
        let (offer, via) = {
            let st = self.state.lock().unwrap();
            (st.exit_offer, st.exit_via.is_some())
        };
        if offer {
            let _ = serve_exit(&self.cfg.interface, false);
        }
        if via && self.kernel_mode() {
            let _ = use_exit(&self.cfg.interface, false);
        }
    }

    fn exit_offer_system(&self, on: bool) -> Result<()> {
        if on && !self.kernel_mode() {
            bail!("an exit node needs kernel mode (root and /dev/net/tun); this node runs in userspace mode");
        }
        serve_exit(&self.cfg.interface, on)
    }

    /// `meshvpn exit offer` / `meshvpn exit offer --stop`.
    pub fn set_exit_offer(&self, on: bool) -> Result<String> {
        if on && self.state.lock().unwrap().exit_via.is_some() {
            bail!("this node uses an exit node itself - `meshvpn exit off` first");
        }
        self.exit_offer_system(on)?;
        let mut cfg = Config::load(&self.dir)?;
        cfg.exit_offer = on;
        cfg.save(&self.dir)?;
        let mut st = self.state.lock().unwrap();
        st.exit_offer = on;
        self.announce(&mut st);
        Ok(if on {
            format!(
                "{} is now an exit node: other nodes can send their internet traffic through it \
                 (meshvpn exit use {}). Only to public addresses - not into this node's LAN.",
                st.my_name, st.my_name
            )
        } else {
            "This node no longer offers its internet connection.".into()
        })
    }

    /// `meshvpn exit use <node>` / `meshvpn exit off`.
    pub fn set_exit_via(&self, node: Option<String>) -> Result<String> {
        let target = match &node {
            None => None,
            Some(n) => {
                let st = self.state.lock().unwrap();
                if st.exit_offer {
                    bail!("this node is an exit node itself - `meshvpn exit offer --stop` first");
                }
                let mut found: Vec<&Record> = st
                    .records
                    .values()
                    .filter(|r| r.info.name == *n || (n.len() >= 4 && r.info.id.hex().starts_with(n.as_str())))
                    .collect();
                found.sort_by_key(|r| (!self.is_online(&st, &r.info.id), std::cmp::Reverse(r.info.seq)));
                let r = found
                    .first()
                    .ok_or_else(|| anyhow!("no node {n} (see meshvpn status)"))?;
                if !r.info.exit {
                    bail!(
                        "{} does not offer its internet connection - run `meshvpn exit offer` there",
                        r.info.name
                    );
                }
                Some((r.info.id, r.info.name.clone()))
            }
        };
        let was = self.state.lock().unwrap().exit_via.is_some();
        if self.kernel_mode() {
            if target.is_some() {
                use_exit(&self.cfg.interface, true)?;
            } else if was {
                use_exit(&self.cfg.interface, false)?;
            }
        }
        let mut cfg = Config::load(&self.dir)?;
        cfg.exit_node = target.as_ref().map(|(id, _)| id.hex());
        cfg.save(&self.dir)?;
        self.state.lock().unwrap().exit_via = target.as_ref().map(|(id, _)| *id);
        Ok(match target {
            Some((_, name)) if self.kernel_mode() => format!(
                "Internet traffic of this machine now goes through {name}. LANs and the mesh stay direct. \
                 Undo with: meshvpn exit off"
            ),
            Some((_, name)) => format!(
                "Connections through the SOCKS proxy ({}) now reach the internet through {name}. \
                 Undo with: meshvpn exit off",
                self.cfg.socks_listen
            ),
            None => "Internet traffic goes out directly again.".into(),
        })
    }

    /// Our exit, and its problems for the status.
    pub(super) fn exit_status(&self, st: &State) -> (Option<String>, Option<String>) {
        let Some(id) = st.exit_via else {
            return (None, None);
        };
        let Some(r) = st.records.get(&id) else {
            return (
                Some(id.short()),
                Some("the exit node is gone - no internet through the mesh (meshvpn exit off)".into()),
            );
        };
        let name = r.info.name.clone();
        let problem = if !self.is_online(st, &id) {
            Some(format!(
                "exit node {name} is offline - no internet until it is back (or meshvpn exit off)"
            ))
        } else if !r.info.exit {
            Some(format!(
                "{name} no longer offers its internet connection - no internet (meshvpn exit off)"
            ))
        } else {
            None
        };
        (Some(name), problem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exits_only_reach_the_internet() {
        for ip in ["1.1.1.1", "8.8.8.8", "140.82.112.3", "100.63.0.1", "100.128.0.1"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "192.0.2.1",
            "198.18.0.1",
            "240.0.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
