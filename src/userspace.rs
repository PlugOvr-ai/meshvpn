//! Userspace networking: meshvpn without a TUN device, e.g. in containers that may not have
//! `/dev/net/tun` or `NET_ADMIN`.
//!
//! A small TCP/IP stack (smoltcp) terminates the mesh traffic inside this process:
//! - incoming TCP connections to this node's mesh IP are passed to the service listening on
//!   the same port on 127.0.0.1 (sshd, web servers, ...); pings are answered;
//! - outgoing connections go through a SOCKS5 proxy (`socks5h://127.0.0.1:1055`), which
//!   also resolves `<name>.mesh` and passes everything that is not in the mesh straight on.

use anyhow::Result;
use rand::{Rng, RngCore};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, info, warn};

use crate::node::Node;

const BUFFER: usize = 256 * 1024;
const CHUNK: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// What the rest of meshvpn hands to the stack.
pub enum Cmd {
    /// An IP packet from the mesh, addressed to this node.
    Packet(Vec<u8>),
    /// Open a connection into the mesh for a SOCKS client (the stack answers the client).
    Connect {
        dst: Ipv4Addr,
        port: u16,
        client: TcpStream,
    },
    /// A local service accepted (or refused) a connection that came in from the mesh.
    LocalReady {
        handle: SocketHandle,
        id: u64,
        stream: Option<Box<dyn LocalStream>>,
    },
}

/// The local end of a connection: a socket to a local service, or the built-in SSH server.
pub trait LocalStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> LocalStream for T {}

pub type StackTx = mpsc::UnboundedSender<Cmd>;

// ---------------------------------------------------------------------------------------------
// The virtual network device between smoltcp and the mesh

struct VirtualDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push(buf);
        r
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: SmolInstant) -> Option<(Rx, Tx<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

// ---------------------------------------------------------------------------------------------
// Connections

enum Kind {
    /// Opened by a SOCKS client; it is answered once the handshake succeeds or fails.
    Outbound { client: Option<TcpStream>, local_port: u16 },
    /// Opened from the mesh, to be passed to 127.0.0.1:`port`.
    Inbound { port: u16, dialing: bool },
}

struct Conn {
    /// Unique, unlike socket handles (smoltcp reuses those).
    id: u64,
    kind: Kind,
    /// Data from the local side, and what is left of the chunk being sent.
    from_local: Option<mpsc::Receiver<Vec<u8>>>,
    pending: Option<(Vec<u8>, usize)>,
    local_eof: bool,
    closing: bool,
    /// Data for the local side.
    to_local: Option<mpsc::Sender<Vec<u8>>>,
}

impl Conn {
    fn new(kind: Kind) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Conn {
            id: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            kind,
            from_local: None,
            pending: None,
            local_eof: false,
            closing: false,
            to_local: None,
        }
    }
}

/// Copies between a local socket and the stack; `wake` tells the stack there is work.
fn bridge(stream: Box<dyn LocalStream>, wake: Arc<Notify>) -> (mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>) {
    let (mut r, mut w) = tokio::io::split(stream);
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(8);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(8);
    let wake_r = wake.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if in_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                    wake_r.notify_one();
                }
            }
        }
        drop(in_tx); // end of stream
        wake_r.notify_one();
    });
    tokio::spawn(async move {
        while let Some(chunk) = out_rx.recv().await {
            if w.write_all(&chunk).await.is_err() {
                break;
            }
            wake.notify_one();
        }
        let _ = w.shutdown().await;
    });
    (in_rx, out_tx)
}

fn new_socket() -> tcp::Socket<'static> {
    let mut s = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; BUFFER]),
        tcp::SocketBuffer::new(vec![0u8; BUFFER]),
    );
    s.set_nagle_enabled(false);
    s.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
    s.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
    s
}

/// Is a service listening on `port` here (on all addresses or loopback)? Otherwise the stack
/// answers the SYN with a reset, so the other side sees "connection refused" right away.
pub fn listening_locally(port: u16) -> bool {
    let want = format!(":{port:04X}");
    ["/proc/net/tcp", "/proc/net/tcp6"].iter().any(|f| {
        std::fs::read_to_string(f).unwrap_or_default().lines().skip(1).any(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            let (Some(local), Some(st)) = (cols.get(1), cols.get(3)) else {
                return false;
            };
            let Some((addr, p)) = local.split_once(':') else {
                return false;
            };
            let any_or_loopback = addr.chars().all(|c| c == '0')
                || addr.ends_with("7F") // 127.x.x.x (little endian)
                || addr == "00000000000000000000000001000000"; // ::1
            *st == "0A" && format!(":{p}") == want && any_or_loopback
        })
    })
}

/// A new incoming connection (SYN without ACK): (source address, source port, our port).
fn syn(packet: &[u8]) -> Option<(Ipv4Addr, u16, u16)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    let tcp = packet.get(ihl..ihl + 20)?;
    let flags = tcp[13];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    (flags & 0x02 != 0 && flags & 0x10 == 0).then(|| {
        (
            src,
            u16::from_be_bytes([tcp[0], tcp[1]]),
            u16::from_be_bytes([tcp[2], tcp[3]]),
        )
    })
}

// ---------------------------------------------------------------------------------------------
// The stack

struct Stack {
    node: Arc<Node>,
    my_ip: Ipv4Addr,
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    conns: HashMap<SocketHandle, Conn>,
    /// One listening socket per new incoming connection (several may arrive at once).
    listeners: HashMap<u16, Vec<SocketHandle>>,
    /// SYNs we opened a listener for, so retransmissions don't open more.
    seen_syns: HashMap<(Ipv4Addr, u16, u16), Instant>,
    used_ports: HashSet<u16>,
    started: Instant,
    wake: Arc<Notify>,
    tx: StackTx,
}

impl Stack {
    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.started.elapsed().as_micros() as i64)
    }

    fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Packet(p) => {
                if let Some(key @ (_, _, port)) = syn(&p)
                    && !self.seen_syns.contains_key(&key)
                    && (listening_locally(port) || (port == 22 && self.node.ssh_builtin_userspace()))
                {
                    // Accept on any port: open a listener just in time for this connection.
                    let mut s = new_socket();
                    if s.listen(port).is_ok() {
                        let h = self.sockets.add(s);
                        self.listeners.entry(port).or_default().push(h);
                        self.conns.insert(h, Conn::new(Kind::Inbound { port, dialing: false }));
                        self.seen_syns.insert(key, Instant::now());
                        if self.seen_syns.len() > 4096 {
                            self.seen_syns.retain(|_, t| t.elapsed() < Duration::from_secs(60));
                        }
                    }
                }
                if self.device.rx.len() < 4096 {
                    self.device.rx.push_back(p);
                }
            }
            Cmd::Connect { dst, port, client } => {
                let local_port = loop {
                    let p = rand::thread_rng().gen_range(49152..=65535u16);
                    if self.used_ports.insert(p) {
                        break p;
                    }
                };
                let mut s = new_socket();
                let cx = self.iface.context();
                let ok = s
                    .connect(
                        cx,
                        (IpAddress::Ipv4(dst), port),
                        (IpAddress::Ipv4(self.my_ip), local_port),
                    )
                    .is_ok();
                if !ok {
                    self.used_ports.remove(&local_port);
                    tokio::spawn(socks_reply(client, false));
                    return;
                }
                let h = self.sockets.add(s);
                self.conns.insert(
                    h,
                    Conn::new(Kind::Outbound {
                        client: Some(client),
                        local_port,
                    }),
                );
            }
            Cmd::LocalReady { handle, id, stream } => {
                let Some(conn) = self.conns.get_mut(&handle).filter(|c| c.id == id) else {
                    return; // that connection is gone already
                };
                match stream {
                    Some(stream) => {
                        let (from, to) = bridge(stream, self.wake.clone());
                        conn.from_local = Some(from);
                        conn.to_local = Some(to);
                    }
                    None => self.sockets.get_mut::<tcp::Socket>(handle).abort(),
                }
            }
        }
    }

    /// Moves data between sockets and local connections; opens and closes what is due.
    fn service(&mut self) {
        let handles: Vec<SocketHandle> = self.conns.keys().copied().collect();
        for h in handles {
            let sock = self.sockets.get_mut::<tcp::Socket>(h);
            let state = sock.state();
            let conn = self.conns.get_mut(&h).unwrap();

            match &mut conn.kind {
                Kind::Outbound { client, .. } if client.is_some() => match state {
                    tcp::State::Established => {
                        let mut client = client.take().unwrap();
                        let (tx, id, wake) = (self.tx.clone(), conn.id, self.wake.clone());
                        // Answer the SOCKS client first, then bridge.
                        tokio::spawn(async move {
                            let stream = client
                                .write_all(&SOCKS_OK)
                                .await
                                .ok()
                                .map(|_| Box::new(client) as Box<dyn LocalStream>);
                            let _ = tx.send(Cmd::LocalReady { handle: h, id, stream });
                            wake.notify_one();
                        });
                    }
                    tcp::State::Closed => {
                        tokio::spawn(socks_reply(client.take().unwrap(), false));
                    }
                    _ => {}
                },
                Kind::Inbound { port, dialing } if !*dialing && state != tcp::State::Listen => {
                    *dialing = true;
                    let port = *port;
                    if let Some(list) = self.listeners.get_mut(&port) {
                        list.retain(|x| *x != h);
                        if list.is_empty() {
                            self.listeners.remove(&port);
                        }
                    }
                    let (tx, id, wake) = (self.tx.clone(), conn.id, self.wake.clone());
                    if port == 22 && self.node.ssh_builtin_userspace() {
                        // The built-in SSH server, through an in-memory pipe.
                        let peer = match sock.remote_endpoint() {
                            Some(ep) => match ep.addr {
                                IpAddress::Ipv4(ip) => std::net::SocketAddr::from((ip, ep.port)),
                            },
                            None => std::net::SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                        };
                        let (ours, theirs) = tokio::io::duplex(256 * 1024);
                        let local = std::net::SocketAddr::from((self.my_ip, 22));
                        tokio::spawn(crate::sshserver::serve(self.node.clone(), theirs, peer, local));
                        let _ = tx.send(Cmd::LocalReady {
                            handle: h,
                            id,
                            stream: Some(Box::new(ours)),
                        });
                        wake.notify_one();
                        continue;
                    }
                    tokio::spawn(async move {
                        let local = TcpStream::connect(("127.0.0.1", port))
                            .await
                            .ok()
                            .map(|s| Box::new(s) as Box<dyn LocalStream>);
                        if local.is_none() {
                            debug!("nothing listens on local port {port}; refusing the connection");
                        }
                        let _ = tx.send(Cmd::LocalReady {
                            handle: h,
                            id,
                            stream: local,
                        });
                        wake.notify_one();
                    });
                }
                _ => {}
            }

            // stack -> local
            if let Some(to) = &conn.to_local {
                while sock.can_recv() && to.capacity() > 0 {
                    let mut buf = vec![0u8; CHUNK];
                    match sock.recv_slice(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            buf.truncate(n);
                            let _ = to.try_send(buf);
                        }
                    }
                }
                // The other side closed its half (FIN received) and everything was passed on.
                let peer_closed = matches!(
                    state,
                    tcp::State::CloseWait
                        | tcp::State::LastAck
                        | tcp::State::Closing
                        | tcp::State::TimeWait
                        | tcp::State::Closed
                );
                if peer_closed && !sock.can_recv() {
                    conn.to_local = None;
                }
            }

            // local -> stack
            if let Some(from) = &mut conn.from_local {
                loop {
                    if conn.pending.is_none() {
                        match from.try_recv() {
                            Ok(chunk) => conn.pending = Some((chunk, 0)),
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                conn.local_eof = true;
                                break;
                            }
                        }
                    }
                    let Some((chunk, off)) = &mut conn.pending else { break };
                    if !sock.can_send() {
                        break;
                    }
                    match sock.send_slice(&chunk[*off..]) {
                        Ok(n) => *off += n,
                        Err(_) => break,
                    }
                    if *off < chunk.len() {
                        break;
                    }
                    conn.pending = None;
                }
                if conn.local_eof && conn.pending.is_none() && !conn.closing {
                    conn.closing = true;
                    sock.close();
                }
            }

            // Done: closed, and everything received was passed on.
            if state == tcp::State::Closed && !sock.can_recv() {
                if let Kind::Outbound { local_port, .. } = conn.kind {
                    self.used_ports.remove(&local_port);
                }
                self.conns.remove(&h);
                self.sockets.remove(h);
            }
        }
    }

    fn flush(&mut self) {
        for p in self.device.tx.drain(..) {
            if p.len() >= 20 && p[0] >> 4 == 4 {
                let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
                self.node.send_packet(dst, &p);
            }
        }
    }
}

const SOCKS_OK: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

async fn socks_reply(mut client: TcpStream, ok: bool) {
    let reply = if ok { SOCKS_OK } else { [5, 5, 0, 1, 0, 0, 0, 0, 0, 0] };
    let _ = client.write_all(&reply).await;
}

/// Starts the stack; returns where to send it packets and commands.
pub fn start(node_ip: Ipv4Addr, prefix: u8, mtu: usize) -> (StackTx, impl FnOnce(Arc<Node>)) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Cmd>();
    let tx2 = tx.clone();
    let run = move |node: Arc<Node>| {
        tokio::spawn(async move {
            let mut device = VirtualDevice {
                rx: VecDeque::new(),
                tx: vec![],
                mtu,
            };
            let mut config = IfaceConfig::new(HardwareAddress::Ip);
            config.random_seed = rand::rngs::OsRng.next_u64();
            let started = Instant::now();
            let mut iface = Interface::new(config, &mut device, SmolInstant::from_micros(0));
            iface.update_ip_addrs(|a| {
                let _ = a.push(IpCidr::new(IpAddress::Ipv4(node_ip), prefix));
            });
            let mut stack = Stack {
                node,
                my_ip: node_ip,
                iface,
                device,
                sockets: SocketSet::new(vec![]),
                conns: HashMap::new(),
                listeners: HashMap::new(),
                seen_syns: HashMap::new(),
                used_ports: HashSet::new(),
                started,
                wake: Arc::new(Notify::new()),
                tx: tx2,
            };
            loop {
                let now = stack.now();
                stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
                stack.service();
                stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
                stack.flush();
                let delay = stack
                    .iface
                    .poll_delay(stack.now(), &stack.sockets)
                    .map(|d| Duration::from_micros(d.total_micros()))
                    .unwrap_or(Duration::from_secs(1))
                    .min(Duration::from_secs(1));
                let wake = stack.wake.clone();
                tokio::select! {
                    cmd = rx.recv() => {
                        let Some(cmd) = cmd else { break };
                        stack.handle(cmd);
                        while let Ok(cmd) = rx.try_recv() {
                            stack.handle(cmd);
                        }
                    }
                    _ = wake.notified() => {}
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        });
    };
    (tx, run)
}

// ---------------------------------------------------------------------------------------------
// SOCKS5 proxy for programs in this container

pub async fn socks_server(node: Arc<Node>, stack: StackTx, listen: String) {
    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            warn!("userspace mode: cannot open the SOCKS proxy on {listen}: {e}");
            return;
        }
    };
    info!("userspace mode: reach the mesh through socks5h://{listen}");
    while let Ok((client, _)) = listener.accept().await {
        let (node, stack) = (node.clone(), stack.clone());
        tokio::spawn(async move {
            if let Err(e) = socks_client(client, &node, &stack).await {
                debug!("socks: {e:#}");
            }
        });
    }
}

async fn socks_client(mut c: TcpStream, node: &Node, stack: &StackTx) -> Result<()> {
    c.set_nodelay(true).ok();
    let mut head = [0u8; 2];
    c.read_exact(&mut head).await?;
    let mut methods = vec![0u8; head[1] as usize];
    c.read_exact(&mut methods).await?;
    if head[0] != 5 || !methods.contains(&0) {
        c.write_all(&[5, 0xff]).await?;
        anyhow::bail!("unsupported SOCKS client");
    }
    c.write_all(&[5, 0]).await?;
    let mut req = [0u8; 4];
    c.read_exact(&mut req).await?;
    if req[1] != 1 {
        c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        anyhow::bail!("only CONNECT is supported");
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        3 => {
            let len = c.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            c.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        4 => {
            let mut a = [0u8; 16];
            c.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => anyhow::bail!("bad address type"),
    };
    let port = c.read_u16().await?;

    // Mesh names and addresses go through the stack, everything else straight out.
    let mesh_ip = node.resolve(&host);
    match mesh_ip {
        Some(ip) if ip == node.my_ip() => {
            let local = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(("127.0.0.1", port))).await;
            direct(c, local.ok().and_then(|r| r.ok())).await
        }
        Some(ip) => {
            let _ = stack.send(Cmd::Connect {
                dst: ip,
                port,
                client: c,
            });
            Ok(())
        }
        None => {
            let target = format!("{}:{port}", host.trim_end_matches('.'));
            let out = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await;
            direct(c, out.ok().and_then(|r| r.ok())).await
        }
    }
}

async fn direct(mut c: TcpStream, out: Option<TcpStream>) -> Result<()> {
    let Some(mut out) = out else {
        socks_reply(c, false).await;
        return Ok(());
    };
    c.write_all(&SOCKS_OK).await?;
    tokio::io::copy_bidirectional(&mut c, &mut out).await?;
    Ok(())
}

/// Is meshvpn running inside a container?
pub fn in_container() -> bool {
    if std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
        || std::env::var_os("container").is_some()
    {
        return true;
    }
    std::fs::read_to_string("/proc/1/cgroup")
        .map(|c| {
            ["docker", "kubepods", "containerd", "lxc", "libpod"]
                .iter()
                .any(|k| c.contains(k))
        })
        .unwrap_or(false)
}

/// `meshvpn nc HOST PORT`: stdin/stdout through the mesh (ssh ProxyCommand).
pub async fn netcat(proxy: &str, host: &str, port: u16) -> Result<()> {
    let target = format!("{host}:{port}");
    let s = crate::link::socks5_connect(proxy, &target).await?;
    let (mut r, mut w) = s.into_split();
    let up = async {
        let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut w).await;
        let _ = w.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut r, &mut tokio::io::stdout()).await;
    };
    tokio::join!(up, down);
    Ok(())
}
