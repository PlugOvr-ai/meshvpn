//! Physical networks of this machine, for direct LAN paths between nodes.

use std::net::Ipv4Addr;

/// `a.b.c.d/p` -> (address, prefix).
pub fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, p) = s.split_once('/')?;
    let p: u8 = p.parse().ok()?;
    (p <= 32).then_some((ip.parse().ok()?, p))
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) }
}

/// Are `a` and `b` in the same subnet `a_prefix`?
pub fn same_subnet(a: Ipv4Addr, prefix: u8, b: Ipv4Addr) -> bool {
    u32::from(a) & mask(prefix) == u32::from(b) & mask(prefix)
}

/// Interfaces that are not a real shared network between machines: every Docker host has the
/// same 172.17.0.1/16, VPNs and bridges are not "the same LAN" either.
fn virtual_interface(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "lo",
        "docker",
        "br-",
        "veth",
        "virbr",
        "vnet",
        "tun",
        "tap",
        "mesh",
        "tailscale",
        "wg",
        "zt",
        "cni",
        "flannel",
        "cali",
        "vxlan",
        "kube",
        "podman",
        "lxc",
        "lxd",
        "incus",
        "ham",
        "nebula",
        "dummy",
    ];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

/// `ip/prefix` of this machine's physical networks, with the interface name.
pub fn local_lans() -> Vec<(String, Ipv4Addr, u8)> {
    let mut out = vec![];
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return out;
    }
    let mut cur = addrs;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null()
            || ifa.ifa_netmask.is_null()
            || unsafe { (*ifa.ifa_addr).sa_family } as i32 != libc::AF_INET
        {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if virtual_interface(&name) {
            continue;
        }
        let ip = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
        let nm = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
        let ip = Ipv4Addr::from(u32::from_be(ip.sin_addr.s_addr));
        let prefix = u32::from_be(nm.sin_addr.s_addr).count_ones() as u8;
        // Shared CGNAT space (100.64/10) is how VPNs number their nodes, not a LAN.
        if ip.is_loopback() || ip.is_link_local() || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64) {
            continue;
        }
        out.push((name, ip, prefix));
    }
    unsafe { libc::freeifaddrs(addrs) };
    out
}

/// Interface on which this machine reaches `peer` directly, if they share a LAN.
pub fn lan_interface_for(peer: Ipv4Addr) -> Option<String> {
    local_lans()
        .into_iter()
        .find(|(_, ip, p)| same_subnet(*ip, *p, peer))
        .map(|(n, _, _)| n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnets() {
        let a: Ipv4Addr = "192.168.1.10".parse().unwrap();
        assert!(same_subnet(a, 24, "192.168.1.200".parse().unwrap()));
        assert!(!same_subnet(a, 24, "192.168.2.1".parse().unwrap()));
        assert_eq!(parse_cidr("10.0.0.5/8"), Some(("10.0.0.5".parse().unwrap(), 8)));
        assert_eq!(parse_cidr("10.0.0.5/33"), None);
        assert!(virtual_interface("docker0") && virtual_interface("br-1a2b") && !virtual_interface("eth0"));
    }
}

/// The IPv4 header checksum of `header` (with its checksum field zero).
pub fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod checksum_tests {
    #[test]
    fn ipv4_header_checksum() {
        // Example header from RFC 1071 style worked examples (checksum field zeroed).
        let h = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8,
            0x00, 0xc7,
        ];
        assert_eq!(super::ip_checksum(&h), 0xb861);
    }
}
