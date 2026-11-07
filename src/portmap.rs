//! Opening the listen port on the home router, so a node behind NAT can be reached from the
//! internet (and becomes an anchor for the others) without a manual port forward.
//!
//! Three protocols, the first that answers wins:
//! * PCP (RFC 6887) and its predecessor NAT-PMP (RFC 6886): one UDP datagram to the gateway's
//!   port 5351. A PCP server that only speaks NAT-PMP answers a PCP request with "unsupported
//!   version", and the request is repeated in NAT-PMP.
//! * UPnP IGD: an SSDP search on the LAN, the router's device description over HTTP, and SOAP
//!   calls to its WANIPConnection (or WANPPPConnection) service. FRITZ!Boxes answer this once
//!   "Selbstständige Portfreigaben" (automatic port sharing) is allowed for the device.
//!
//! Mappings are leased (an hour) and renewed at half time. A mapping only helps if the router
//! has a public IPv4 address itself: behind DS-Lite or carrier-grade NAT it gets a private
//! one, and the mapping is not advertised.

use anyhow::{Context, Result, anyhow, bail};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

const PCP_PORT: u16 = 5351;
/// Requested lease. Renewed at half time.
pub const LIFETIME: u32 = 3600;

/// Ports opened on the router.
#[derive(Clone, Debug, PartialEq)]
pub struct Mapping {
    pub method: &'static str,
    pub gateway: Ipv4Addr,
    /// The router's own address on the internet side.
    pub external: Ipv4Addr,
    /// (protocol, internal port, external port)
    pub ports: Vec<(u8, u16, u16)>,
    /// How long the router keeps them (0: until it restarts).
    pub lifetime: u32,
}

impl Mapping {
    pub fn external_port(&self, proto: u8) -> Option<u16> {
        self.ports.iter().find(|p| p.0 == proto).map(|p| p.2)
    }

    /// Whether the router's address is reachable from the internet (not DS-Lite or CGNAT).
    pub fn public(&self) -> bool {
        is_public(self.external)
    }

    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = vec![];
        for (proto, internal, external) in &self.ports {
            let p = if *proto == TCP { "TCP" } else { "UDP" };
            parts.push(if internal == external {
                format!("{p} {external}")
            } else {
                format!("{p} {external}->{internal}")
            });
        }
        format!(
            "{} open on the router ({}, {})",
            parts.join(" + "),
            self.method,
            self.gateway
        )
    }
}

pub fn is_public(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10, carrier-grade NAT
        || o[0] == 192 && o[1] == 0 && o[2] == 0 // 192.0.0.0/24 (DS-Lite's B4 address)
        || o[0] >= 224)
}

/// The default gateway (IPv4), not through `skip_iface` (the mesh, an exit node's route).
pub fn gateway(skip_iface: &str) -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let text = std::fs::read_to_string("/proc/net/route").ok()?;
        gateway_from_proc(&text, skip_iface)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = skip_iface;
        let out = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.trim().strip_prefix("gateway:"))
            .and_then(|g| g.trim().parse().ok())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = skip_iface;
        None
    }
}

/// The gateway of the default route in /proc/net/route (hex, little-endian).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn gateway_from_proc(text: &str, skip_iface: &str) -> Option<Ipv4Addr> {
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[0] == skip_iface || f[1] != "00000000" {
            continue;
        }
        let flags = u16::from_str_radix(f[3], 16).unwrap_or(0);
        if flags & 0x2 == 0 {
            continue; // not via a gateway
        }
        let gw = u32::from_str_radix(f[2], 16).ok()?;
        let ip = Ipv4Addr::from(gw.to_le_bytes());
        if !ip.is_unspecified() {
            return Some(ip);
        }
    }
    None
}

/// Our address towards the gateway.
fn local_ip(gw: Ipv4Addr) -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect((gw, PCP_PORT)).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

/// Why nothing is mapped.
#[derive(Debug)]
pub enum NoMapping {
    /// This machine has a public address itself (no NAT in front of it).
    NotNeeded,
    /// No default gateway (or not on this platform).
    NoGateway,
    Failed(String),
}

/// Opens `ports` (protocol, internal port) on the router.
pub async fn map(ports: &[(u8, u16)], skip_iface: &str) -> Result<Mapping, NoMapping> {
    let gw = gateway(skip_iface).ok_or(NoMapping::NoGateway)?;
    let local = local_ip(gw).ok_or(NoMapping::NoGateway)?;
    if is_public(local) {
        return Err(NoMapping::NotNeeded);
    }
    let pcp_err = match pcp_map_all(SocketAddrV4::new(gw, PCP_PORT), local, ports, LIFETIME).await {
        Ok(mut m) => {
            m.gateway = gw;
            return Ok(m);
        }
        Err(e) => e,
    };
    match upnp_map_all(gw, local, ports, LIFETIME).await {
        Ok(m) => Ok(m),
        Err(e) => Err(NoMapping::Failed(format!("UPnP: {e:#}; PCP/NAT-PMP: {pcp_err:#}"))),
    }
}

// ----------------------------------------------------------------------------- PCP / NAT-PMP

async fn pcp_map_all(gw: SocketAddrV4, local: Ipv4Addr, ports: &[(u8, u16)], lifetime: u32) -> Result<Mapping> {
    let sock = UdpSocket::bind((local, 0)).await?;
    sock.connect(gw).await?;
    let mut out = Mapping {
        method: "PCP",
        gateway: *gw.ip(),
        external: Ipv4Addr::UNSPECIFIED,
        ports: vec![],
        lifetime,
    };
    let mut natpmp = false;
    for &(proto, port) in ports {
        if !natpmp {
            match pcp_map(&sock, local, proto, port, lifetime).await? {
                PcpReply::Mapped {
                    external,
                    port: ext,
                    lifetime,
                } => {
                    out.external = external;
                    out.ports.push((proto, port, ext));
                    out.lifetime = lifetime;
                    continue;
                }
                PcpReply::OnlyNatPmp => natpmp = true,
            }
        }
        let (ext, lifetime) = natpmp_map(&sock, proto, port, lifetime).await?;
        out.method = "NAT-PMP";
        out.ports.push((proto, port, ext));
        out.lifetime = lifetime;
    }
    if natpmp {
        out.external = natpmp_external(&sock).await?;
    }
    Ok(out)
}

/// Sends `req` and waits for an answer that `ok` accepts (a few tries, LAN round trips).
async fn exchange(sock: &UdpSocket, req: &[u8], ok: impl Fn(&[u8]) -> bool) -> Result<Vec<u8>> {
    let mut buf = [0u8; 1100];
    for wait in [250u64, 500, 1000] {
        sock.send(req).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(wait);
        loop {
            match tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
                Ok(Ok(n)) if ok(&buf[..n]) => return Ok(buf[..n].to_vec()),
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => return Err(e.into()), // e.g. ICMP port unreachable: no server
                Err(_) => break,
            }
        }
    }
    bail!("no answer from the gateway")
}

enum PcpReply {
    Mapped {
        external: Ipv4Addr,
        port: u16,
        lifetime: u32,
    },
    /// The server speaks NAT-PMP only.
    OnlyNatPmp,
}

fn mapped_v4(ip: Ipv4Addr) -> [u8; 16] {
    ip.to_ipv6_mapped().octets()
}

/// A PCP MAP request (RFC 6887 11.1): header (24) + MAP opcode (36).
fn pcp_request(local: Ipv4Addr, nonce: &[u8; 12], proto: u8, port: u16, lifetime: u32) -> [u8; 60] {
    let mut r = [0u8; 60];
    r[0] = 2; // version
    r[1] = 1; // MAP, request
    r[4..8].copy_from_slice(&lifetime.to_be_bytes());
    r[8..24].copy_from_slice(&mapped_v4(local));
    r[24..36].copy_from_slice(nonce);
    r[36] = proto;
    r[40..42].copy_from_slice(&port.to_be_bytes());
    r[42..44].copy_from_slice(&port.to_be_bytes()); // suggested external port: the same
    r[44..60].copy_from_slice(&mapped_v4(Ipv4Addr::UNSPECIFIED));
    r
}

fn pcp_parse(d: &[u8], nonce: &[u8; 12], proto: u8, port: u16) -> Result<PcpReply> {
    // A NAT-PMP server answers any version it doesn't know with result 1 (unsupported version).
    if d.len() >= 4 && d[0] == 0 && u16::from_be_bytes([d[2], d[3]]) == 1 {
        return Ok(PcpReply::OnlyNatPmp);
    }
    if d.len() < 60 || d[0] != 2 || d[1] != 0x81 {
        bail!("not a PCP MAP answer");
    }
    if d[3] != 0 {
        bail!("{}", pcp_result(d[3]));
    }
    if &d[24..36] != nonce || d[36] != proto || u16::from_be_bytes([d[40], d[41]]) != port {
        bail!("PCP answer to another request");
    }
    let lifetime = u32::from_be_bytes(d[4..8].try_into().unwrap());
    let ext_port = u16::from_be_bytes([d[42], d[43]]);
    let ip: [u8; 16] = d[44..60].try_into().unwrap();
    let external = std::net::Ipv6Addr::from(ip)
        .to_ipv4_mapped()
        .ok_or_else(|| anyhow!("PCP: external address is not IPv4"))?;
    Ok(PcpReply::Mapped {
        external,
        port: ext_port,
        lifetime,
    })
}

fn pcp_result(code: u8) -> &'static str {
    match code {
        1 => "PCP: unsupported version",
        2 => "PCP: not authorized (the router doesn't allow this device to open ports)",
        3 => "PCP: malformed request",
        8 => "PCP: no resources",
        11 => "PCP: cannot provide an external address",
        _ => "PCP: refused",
    }
}

async fn pcp_map(sock: &UdpSocket, local: Ipv4Addr, proto: u8, port: u16, lifetime: u32) -> Result<PcpReply> {
    let nonce: [u8; 12] = crate::keys::random32()[..12].try_into().unwrap();
    let req = pcp_request(local, &nonce, proto, port, lifetime);
    let d = exchange(sock, &req, |d| {
        (d.len() >= 4 && d[0] == 0) || (d.len() >= 60 && d[0] == 2 && d[1] == 0x81 && d[24..36] == nonce)
    })
    .await?;
    pcp_parse(&d, &nonce, proto, port)
}

/// NAT-PMP mapping request (RFC 6886 3.3): op 1 UDP, 2 TCP.
fn natpmp_request(proto: u8, port: u16, lifetime: u32) -> [u8; 12] {
    let mut r = [0u8; 12];
    r[1] = if proto == UDP { 1 } else { 2 };
    r[4..6].copy_from_slice(&port.to_be_bytes());
    r[6..8].copy_from_slice(&port.to_be_bytes());
    r[8..12].copy_from_slice(&lifetime.to_be_bytes());
    r
}

fn natpmp_parse(d: &[u8], proto: u8, port: u16) -> Result<(u16, u32)> {
    let op = if proto == UDP { 1 } else { 2 };
    if d.len() < 16 || d[0] != 0 || d[1] != 128 + op {
        bail!("not a NAT-PMP mapping answer");
    }
    match u16::from_be_bytes([d[2], d[3]]) {
        0 => {}
        2 => bail!("NAT-PMP: not authorized (port mapping is switched off on the router)"),
        3 => bail!("NAT-PMP: the router has no internet connection"),
        r => bail!("NAT-PMP: refused (result {r})"),
    }
    if u16::from_be_bytes([d[8], d[9]]) != port {
        bail!("NAT-PMP answer to another request");
    }
    Ok((
        u16::from_be_bytes([d[10], d[11]]),
        u32::from_be_bytes(d[12..16].try_into().unwrap()),
    ))
}

async fn natpmp_map(sock: &UdpSocket, proto: u8, port: u16, lifetime: u32) -> Result<(u16, u32)> {
    let op = if proto == UDP { 1 } else { 2 };
    let d = exchange(sock, &natpmp_request(proto, port, lifetime), |d| {
        d.len() >= 16 && d[0] == 0 && d[1] == 128 + op && u16::from_be_bytes([d[8], d[9]]) == port
    })
    .await?;
    natpmp_parse(&d, proto, port)
}

async fn natpmp_external(sock: &UdpSocket) -> Result<Ipv4Addr> {
    let d = exchange(sock, &[0, 0], |d| d.len() >= 12 && d[0] == 0 && d[1] == 128).await?;
    if u16::from_be_bytes([d[2], d[3]]) != 0 {
        bail!("NAT-PMP: no external address");
    }
    Ok(Ipv4Addr::new(d[8], d[9], d[10], d[11]))
}

// ----------------------------------------------------------------------------- UPnP IGD

const SSDP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
const SEARCH_TARGETS: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
];
const SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

/// LAN requests never go through a proxy from the environment.
fn http() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// The LOCATION of the gateway's device description (from the gateway itself only).
async fn ssdp_search(gw: Ipv4Addr, local: Ipv4Addr) -> Result<String> {
    let sock = UdpSocket::bind((local, 0)).await?;
    for st in SEARCH_TARGETS {
        let msg = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {st}\r\n\r\n"
        );
        let _ = sock.send_to(msg.as_bytes(), SSDP).await;
        let _ = sock.send_to(msg.as_bytes(), (gw, 1900)).await;
    }
    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
        if from.ip() != IpAddr::V4(gw) {
            continue;
        }
        if let Some(loc) = ssdp_location(&String::from_utf8_lossy(&buf[..n]), gw) {
            return Ok(loc);
        }
    }
    bail!("no UPnP answer from the router (switched off?)")
}

/// The LOCATION header of an SSDP answer, if it points at the gateway over plain HTTP.
fn ssdp_location(answer: &str, gw: Ipv4Addr) -> Option<String> {
    let loc = answer.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case("location").then(|| v.trim().to_string())
    })?;
    let rest = loc.strip_prefix("http://")?;
    let host = rest.split(['/', ':']).next()?;
    (host.parse::<Ipv4Addr>().ok()? == gw).then_some(loc)
}

/// Text of the first `<tag>` in `xml` (namespace prefixes ignored).
fn xml_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let mut rest = xml;
    loop {
        let start = rest.find('<')?;
        rest = &rest[start + 1..];
        let end = rest.find('>')?;
        let name = &rest[..end];
        let local = name.rsplit(':').next().unwrap_or(name);
        if local == tag {
            let body = &rest[end + 1..];
            let close = body.find("</")?;
            return Some(body[..close].trim());
        }
        rest = &rest[end + 1..];
    }
}

/// The best connection service in a device description: (service type, absolute control URL).
fn find_service(xml: &str, location: &str) -> Option<(String, String)> {
    let base = xml_text(xml, "URLBase")
        .map(|b| b.trim_end_matches('/').to_string())
        .unwrap_or_else(|| {
            let rest = location.strip_prefix("http://").unwrap_or(location);
            let host = rest.split('/').next().unwrap_or(rest);
            format!("http://{host}")
        });
    let mut found: Vec<(usize, String, String)> = vec![];
    for chunk in xml.split("<service>").skip(1) {
        let chunk = chunk.split("</service>").next().unwrap_or(chunk);
        let (Some(ty), Some(ctl)) = (xml_text(chunk, "serviceType"), xml_text(chunk, "controlURL")) else {
            continue;
        };
        if let Some(rank) = SERVICES.iter().position(|s| *s == ty) {
            let url = if ctl.starts_with("http://") {
                ctl.to_string()
            } else {
                format!("{base}/{}", ctl.trim_start_matches('/'))
            };
            found.push((rank, ty.to_string(), url));
        }
    }
    found.sort();
    found.into_iter().next().map(|(_, ty, url)| (ty, url))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// A SOAP call; Ok(body) or Err with the UPnP error code.
async fn soap(
    client: &reqwest::Client,
    url: &str,
    service: &str,
    action: &str,
    args: &[(&str, String)],
) -> Result<String, (u32, String)> {
    let mut body = String::new();
    for (k, v) in args {
        body.push_str(&format!("<{k}>{}</{k}>", xml_escape(v)));
    }
    let envelope = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{service}\">{body}\
         </u:{action}></s:Body></s:Envelope>"
    );
    let resp = client
        .post(url)
        .header("Content-Type", "text/xml; charset=\"utf-8\"")
        .header("SOAPAction", format!("\"{service}#{action}\""))
        .body(envelope)
        .send()
        .await
        .map_err(|e| (0, e.to_string()))?;
    let ok = resp.status().is_success();
    let text = resp.text().await.map_err(|e| (0, e.to_string()))?;
    if ok {
        return Ok(text);
    }
    let code = xml_text(&text, "errorCode").and_then(|c| c.parse().ok()).unwrap_or(0);
    let desc = xml_text(&text, "errorDescription").unwrap_or("refused").to_string();
    Err((code, desc))
}

fn upnp_error(code: u32, desc: &str) -> String {
    match code {
        606 => "not authorized - on a FRITZ!Box allow \"Selbstständige Portfreigaben\" for this device \
                (Internet > Freigaben > Portfreigaben)"
            .into(),
        718 => "the port is already forwarded to another device".into(),
        0 => desc.to_string(),
        c => format!("{desc} (UPnP error {c})"),
    }
}

async fn upnp_map_all(gw: Ipv4Addr, local: Ipv4Addr, ports: &[(u8, u16)], lifetime: u32) -> Result<Mapping> {
    let location = ssdp_search(gw, local).await?;
    let client = http()?;
    let xml = client.get(&location).send().await?.text().await?;
    let (service, url) = find_service(&xml, &location).context("the router offers no port mapping service")?;
    if !url.starts_with(&format!("http://{gw}")) {
        bail!("the router's control URL points elsewhere");
    }
    let external = soap(&client, &url, &service, "GetExternalIPAddress", &[])
        .await
        .map_err(|(c, d)| anyhow!(upnp_error(c, &d)))
        .and_then(|b| {
            xml_text(&b, "NewExternalIPAddress")
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                .context("the router reports no external address")
        })?;
    let mut out = Mapping {
        method: "UPnP",
        gateway: gw,
        external,
        ports: vec![],
        lifetime,
    };
    for &(proto, port) in ports {
        let mut lease = lifetime;
        // The same port outside first; another one if a different device has it.
        let mut tries: Vec<u16> = vec![port];
        tries.extend((1..4).map(|i| port.wrapping_add(i * 1000)).filter(|p| *p > 1024));
        let mut last = String::new();
        let mut done = false;
        for ext in tries {
            let args = |lease: u32| {
                vec![
                    ("NewRemoteHost", String::new()),
                    ("NewExternalPort", ext.to_string()),
                    ("NewProtocol", if proto == TCP { "TCP" } else { "UDP" }.to_string()),
                    ("NewInternalPort", port.to_string()),
                    ("NewInternalClient", local.to_string()),
                    ("NewEnabled", "1".to_string()),
                    ("NewPortMappingDescription", "meshvpn".to_string()),
                    ("NewLeaseDuration", lease.to_string()),
                ]
            };
            let mut res = soap(&client, &url, &service, "AddPortMapping", &args(lease)).await;
            if let Err((725, _)) = res {
                // OnlyPermanentLeasesSupported
                lease = 0;
                res = soap(&client, &url, &service, "AddPortMapping", &args(0)).await;
            }
            match res {
                Ok(_) => {
                    out.ports.push((proto, port, ext));
                    out.lifetime = lease;
                    done = true;
                    break;
                }
                Err((718, d)) => last = upnp_error(718, &d),
                Err((c, d)) => bail!(upnp_error(c, &d)),
            }
        }
        if !done {
            bail!(last);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_addresses() {
        for ip in [
            "192.168.178.20",
            "10.1.2.3",
            "100.64.1.1",
            "100.127.255.1",
            "192.0.0.2",
            "169.254.1.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["2.243.3.46", "178.77.77.96", "100.128.0.1", "100.63.0.1"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn default_gateway_from_proc() {
        let t = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                 mesh0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n\
                 eth0\t00000000\t01B2A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                 eth0\t00B2A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(gateway_from_proc(t, "mesh0"), Some(Ipv4Addr::new(192, 168, 178, 1)));
        assert_eq!(gateway_from_proc(t, "eth0"), None);
    }

    #[test]
    fn pcp_round_trip() {
        let local = Ipv4Addr::new(192, 168, 178, 20);
        let nonce = [7u8; 12];
        let req = pcp_request(local, &nonce, TCP, 7870, 3600);
        assert_eq!(&req[..2], &[2, 1]);
        // The server's answer: the request with the response bit, result 0 and the mapping.
        let mut ans = req;
        ans[1] = 0x81;
        ans[3] = 0;
        ans[42..44].copy_from_slice(&7871u16.to_be_bytes());
        ans[44..60].copy_from_slice(&mapped_v4(Ipv4Addr::new(2, 243, 3, 46)));
        match pcp_parse(&ans, &nonce, TCP, 7870).unwrap() {
            PcpReply::Mapped {
                external,
                port,
                lifetime,
            } => {
                assert_eq!((external, port, lifetime), (Ipv4Addr::new(2, 243, 3, 46), 7871, 3600));
            }
            PcpReply::OnlyNatPmp => panic!(),
        }
        assert!(
            pcp_parse(&ans, &[8u8; 12], TCP, 7870).is_err(),
            "another request's nonce"
        );
        let mut refused = ans;
        refused[3] = 2;
        assert!(pcp_parse(&refused, &nonce, TCP, 7870).is_err());
        assert!(matches!(
            pcp_parse(&[0, 129, 0, 1], &nonce, TCP, 7870),
            Ok(PcpReply::OnlyNatPmp)
        ));
    }

    #[test]
    fn natpmp_round_trip() {
        let req = natpmp_request(UDP, 7870, 3600);
        assert_eq!(&req[..2], &[0, 1]);
        let mut ans = [0u8; 16];
        ans[1] = 129;
        ans[8..10].copy_from_slice(&7870u16.to_be_bytes());
        ans[10..12].copy_from_slice(&7870u16.to_be_bytes());
        ans[12..16].copy_from_slice(&1800u32.to_be_bytes());
        assert_eq!(natpmp_parse(&ans, UDP, 7870).unwrap(), (7870, 1800));
        assert!(natpmp_parse(&ans, TCP, 7870).is_err());
    }

    /// A NAT-PMP-only gateway on localhost: the PCP request falls back to NAT-PMP.
    #[tokio::test]
    async fn natpmp_fallback_against_a_fake_gateway() {
        let gw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = match gw.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 1100];
            loop {
                let (n, from) = gw.recv_from(&mut buf).await.unwrap();
                let d = &buf[..n];
                let ans: Vec<u8> = match (d[0], d[1]) {
                    (2, _) => vec![0, 128 + d[1], 0, 1, 0, 0, 0, 0], // unsupported version
                    (0, 0) => vec![0, 128, 0, 0, 0, 0, 0, 9, 2, 243, 3, 46],
                    (0, op) => {
                        let mut a = vec![0, 128 + op, 0, 0, 0, 0, 0, 9];
                        a.extend_from_slice(&d[4..6]);
                        a.extend_from_slice(&d[4..6]);
                        a.extend_from_slice(&d[8..12]);
                        a
                    }
                    _ => continue,
                };
                gw.send_to(&ans, from).await.unwrap();
            }
        });
        let m = pcp_map_all(addr, Ipv4Addr::LOCALHOST, &[(TCP, 7870), (UDP, 7870)], 3600)
            .await
            .unwrap();
        assert_eq!(m.method, "NAT-PMP");
        assert_eq!(m.external, Ipv4Addr::new(2, 243, 3, 46));
        assert_eq!(m.ports, vec![(TCP, 7870, 7870), (UDP, 7870, 7870)]);
        assert!(m.public());
    }

    #[test]
    fn upnp_description() {
        let gw = Ipv4Addr::new(192, 168, 178, 1);
        let answer = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.178.1:49000/igddesc.xml\r\n\
                      ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
        let loc = ssdp_location(answer, gw).unwrap();
        assert_eq!(loc, "http://192.168.178.1:49000/igddesc.xml");
        assert!(ssdp_location(&answer.replace("192.168.178.1:", "10.0.0.9:"), gw).is_none());
        let xml = r#"<?xml version="1.0"?><root><device><serviceList>
            <service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
              <controlURL>/igdupnp/control/Layer3Forwarding</controlURL></service>
            </serviceList><deviceList><device><deviceList><device><serviceList>
            <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
              <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
              <controlURL>/igdupnp/control/WANIPConn1</controlURL></service>
            </serviceList></device></deviceList></device></deviceList></device></root>"#;
        assert_eq!(
            find_service(xml, &loc).unwrap(),
            (
                "urn:schemas-upnp-org:service:WANIPConnection:1".to_string(),
                "http://192.168.178.1:49000/igdupnp/control/WANIPConn1".to_string()
            )
        );
        let fault = "<s:Envelope><s:Body><s:Fault><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
                     <errorCode>606</errorCode><errorDescription>Action not authorized</errorDescription>\
                     </UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        assert_eq!(xml_text(fault, "errorCode"), Some("606"));
        let ip =
            "<u:GetExternalIPAddressResponse xmlns:u=\"x\"><NewExternalIPAddress>2.243.3.46</NewExternalIPAddress>";
        assert_eq!(xml_text(ip, "NewExternalIPAddress"), Some("2.243.3.46"));
    }
}
