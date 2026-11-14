//! Peer-to-peer distribution of datasets and checkpoints.
//!
//! `meshvpn share PATH` hashes a file or directory in 4 MB chunks (BLAKE3) and publishes a
//! manifest; its id is the hash of the manifest, so the id proves the content. `meshvpn fetch
//! ID DIR` pulls the chunks in parallel from every node that has the object - over a shared LAN
//! where possible, the mesh otherwise - verifies each one, and then serves them as well, so
//! every finished node speeds up the next ones.
//!
//! The chunk server listens on TCP 7871. Every connection must prove it knows the network key
//! (challenge/response); chunks are verified by their hash on arrival. Over the mesh the data
//! is encrypted; over a LAN path it is authenticated but not encrypted (like NCCL traffic).

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

/// Opening a symlink fails instead of following it.
#[cfg(unix)]
const NOFOLLOW: i32 = libc::O_NOFOLLOW;
/// Windows: opens a symlink or junction itself, not its target (FILE_FLAG_OPEN_REPARSE_POINT).
#[cfg(windows)]
const NOFOLLOW: u32 = 0x0020_0000;

/// Reads and writes at an offset, as `std::os::unix::fs::FileExt` does.
#[cfg(windows)]
trait FileExt {
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<()>;
    fn write_all_at(&self, buf: &[u8], off: u64) -> std::io::Result<()>;
}

#[cfg(windows)]
impl FileExt for std::fs::File {
    fn read_exact_at(&self, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
        use std::os::windows::fs::FileExt as _;
        while !buf.is_empty() {
            match self.seek_read(buf, off)? {
                0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                n => {
                    buf = &mut buf[n..];
                    off += n as u64;
                }
            }
        }
        Ok(())
    }

    fn write_all_at(&self, mut buf: &[u8], mut off: u64) -> std::io::Result<()> {
        use std::os::windows::fs::FileExt as _;
        while !buf.is_empty() {
            let n = self.seek_write(buf, off)?;
            buf = &buf[n..];
            off += n as u64;
        }
        Ok(())
    }
}

/// Permission bits for the manifest (Windows has none: read-only or not).
fn file_mode(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        meta.permissions().mode() & 0o777
    }
    #[cfg(windows)]
    {
        if meta.permissions().readonly() { 0o444 } else { 0o644 }
    }
}
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::node::Node;
use crate::proto::ObjectAd;

pub const PORT: u16 = 7871;
const CHUNK: u64 = 4 * 1024 * 1024;
const WORKERS: usize = 8;
const MISSING: u64 = u64::MAX;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileEntry {
    /// Relative path, `/`-separated.
    pub path: String,
    pub size: u64,
    pub mode: u32,
    /// BLAKE3 of each chunk (hex).
    pub chunks: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub name: String,
    pub chunk_size: u64,
    pub total: u64,
    pub files: Vec<FileEntry>,
}

impl Manifest {
    pub fn id(json: &[u8]) -> String {
        blake3::hash(json).to_hex()[..32].to_string()
    }

    /// Paths from other nodes must stay inside the destination.
    fn validate(&self) -> Result<()> {
        if !(64 * 1024..=64 * 1024 * 1024).contains(&self.chunk_size) || self.files.len() > 1_000_000 {
            bail!("unreasonable manifest");
        }
        // The name goes into this node's record once the object is here: one that records
        // may not carry would make the other nodes refuse the whole record.
        if !crate::proto::clean_text(&self.name) {
            bail!("invalid name in manifest");
        }
        for f in &self.files {
            let p = Path::new(&f.path);
            if f.path.is_empty()
                || p.is_absolute()
                || p.components().any(|c| !matches!(c, Component::Normal(_)))
                || f.chunks.len() as u64 != f.size.div_ceil(self.chunk_size).max(1)
            {
                bail!("invalid path or size in manifest: {:?}", f.path);
            }
        }
        Ok(())
    }
}

/// A shared object: its manifest and where its files are.
#[derive(Serialize, Deserialize, Clone)]
pub struct Stored {
    pub id: String,
    pub manifest: Manifest,
    pub root: PathBuf,
}

impl Stored {
    fn file(&self, idx: usize) -> PathBuf {
        self.root.join(&self.manifest.files[idx].path)
    }

    /// Files still there with the right sizes (a changed file would serve bad chunks).
    fn intact(&self) -> bool {
        self.manifest
            .files
            .iter()
            .enumerate()
            .all(|(i, f)| std::fs::metadata(self.file(i)).is_ok_and(|m| m.len() == f.size))
    }

    fn ad(&self) -> ObjectAd {
        ObjectAd {
            id: self.id.clone(),
            name: self.manifest.name.clone(),
            size: self.manifest.total,
        }
    }
}

/// Shared objects of this node, kept in `<dir>/objects/<id>.json`.
pub struct Store {
    dir: PathBuf,
    objects: Mutex<HashMap<String, Stored>>,
}

impl Store {
    pub fn load(dir: &Path) -> Self {
        let dir = dir.join("objects");
        let mut objects = HashMap::new();
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let Ok(s) = std::fs::read(e.path())
                .map_err(anyhow::Error::from)
                .and_then(|b| serde_json::from_slice::<Stored>(&b).map_err(anyhow::Error::from))
            else {
                continue;
            };
            if s.intact() {
                objects.insert(s.id.clone(), s);
            } else {
                warn!(
                    "shared object {} ({}) changed or is gone - no longer shared",
                    s.id, s.manifest.name
                );
            }
        }
        Store {
            dir,
            objects: Mutex::new(objects),
        }
    }

    pub fn ads(&self) -> Vec<ObjectAd> {
        // An object stored by an older version may have a name records can't carry: it stays
        // out of the record (the others would refuse the record with it).
        let mut v: Vec<ObjectAd> = self
            .objects
            .lock()
            .unwrap()
            .values()
            .map(Stored::ad)
            .filter(|a| crate::proto::clean_text(&a.name))
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v.truncate(128); // keeps the node's record small enough for one link message
        v
    }

    fn get(&self, id: &str) -> Option<Stored> {
        self.objects.lock().unwrap().get(id).cloned()
    }

    fn add(&self, s: Stored) -> Result<()> {
        crate::config::create_dir(&self.dir)?;
        crate::config::write_private(&self.dir.join(format!("{}.json", s.id)), &serde_json::to_vec(&s)?)?;
        self.objects.lock().unwrap().insert(s.id.clone(), s);
        Ok(())
    }

    pub fn remove(&self, id: &str) -> bool {
        let _ = std::fs::remove_file(self.dir.join(format!("{id}.json")));
        self.objects.lock().unwrap().remove(id).is_some()
    }
}

// ---------------------------------------------------------------------------------------------
// Sharing

fn hash_file(path: &Path, size: u64) -> Result<Vec<String>> {
    let f = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut chunks = vec![];
    let mut buf = vec![0u8; CHUNK as usize];
    let mut off = 0u64;
    loop {
        let want = (size - off).min(CHUNK) as usize;
        f.read_exact_at(&mut buf[..want], off)?;
        chunks.push(blake3::hash(&buf[..want]).to_hex().to_string());
        off += want as u64;
        if off >= size {
            break;
        }
    }
    Ok(chunks)
}

/// Builds the manifest of a file or directory (blocking).
pub fn build(path: &Path, name: Option<String>) -> Result<Stored> {
    let path = path.canonicalize().with_context(|| format!("{}", path.display()))?;
    let root = path.parent().unwrap_or(Path::new("/")).to_path_buf();
    let mut files = vec![];
    let mut stack = vec![path.clone()];
    while let Some(p) = stack.pop() {
        let meta = std::fs::symlink_metadata(&p)?;
        if meta.is_dir() {
            for e in std::fs::read_dir(&p)? {
                stack.push(e?.path());
            }
        } else if meta.is_file() {
            let rel = p.strip_prefix(&root)?.to_string_lossy().replace('\\', "/");
            files.push(FileEntry {
                path: rel,
                size: meta.len(),
                mode: file_mode(&meta),
                chunks: hash_file(&p, meta.len())?,
            });
        }
    }
    if files.is_empty() {
        bail!("{}: nothing to share", path.display());
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = Manifest {
        name: name.unwrap_or_else(|| path.file_name().unwrap_or_default().to_string_lossy().into_owned()),
        chunk_size: CHUNK,
        total: files.iter().map(|f| f.size).sum(),
        files,
    };
    if !crate::proto::clean_text(&manifest.name) {
        bail!("the name is too long (128 bytes at most) or has control characters: give one with --name");
    }
    let id = Manifest::id(&serde_json::to_vec(&manifest)?);
    Ok(Stored { id, manifest, root })
}

pub fn share(store: &Store, path: &Path, name: Option<String>) -> Result<Stored> {
    let s = build(path, name)?;
    store.add(s.clone())?;
    info!("sharing {} ({}, {} bytes)", s.id, s.manifest.name, s.manifest.total);
    Ok(s)
}

// ---------------------------------------------------------------------------------------------
// Serving

fn auth_tag(key: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(&blake3::derive_key("meshvpn share auth v1", key), nonce).as_bytes()
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Req {
    /// The first line of every connection: which node the client is, signed over the server's
    /// nonce. The network key alone opens nothing - a banned node still has one, and so does
    /// whoever holds an invite that was used long ago.
    Hello {
        id: crate::keys::NodeId,
        sig: String,
    },
    Manifest {
        id: String,
    },
    Chunk {
        id: String,
        file: usize,
        index: usize,
    },
    /// Throughput test: data follows until the sender closes; the answer is how much arrived.
    Sink,
    /// A volume's file list version (`crate::volume`), on the node that keeps it.
    /// `user`: for which user of the asking node (None: the node itself, for its mount).
    VolHead {
        vol: String,
        #[serde(default)]
        user: Option<String>,
    },
    VolManifest {
        vol: String,
        #[serde(default)]
        user: Option<String>,
    },
    /// Bytes of a volume's chunk this node keeps (never more than one chunk).
    VolRead {
        vol: String,
        #[serde(default)]
        user: Option<String>,
        id: String,
        chunk: u32,
        off: u64,
        len: u32,
    },
    /// A chunk copied in: `len` bytes follow the line.
    VolPut {
        vol: String,
        #[serde(default)]
        user: Option<String>,
        id: String,
        chunk: u32,
        hash: String,
        len: u32,
    },
    /// Files copied in, removed: `len` bytes of JSON follow the line.
    VolCommit {
        vol: String,
        #[serde(default)]
        user: Option<String>,
        len: u32,
    },
}

/// How long each side waits for the other's part of the greeting.
const GREETING: Duration = Duration::from_secs(10);
/// A connection without a request for this long is closed.
const IDLE: Duration = Duration::from_secs(300);

/// One request line. Requests are short: a longer line is not one.
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut line = vec![];
    if (&mut *r).take(4096).read_until(b'\n', &mut line).await? == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        bail!("request too long or cut off");
    }
    Ok(Some(line))
}

fn listen(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let s = tokio::net::TcpSocket::new_v4()?;
    s.set_reuseaddr(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    s.set_reuseport(true)?;
    s.bind(addr)?;
    s.listen(128)
}

pub async fn serve(node: Arc<Node>) {
    // Every network of this machine has a server on this port: the first one's on all addresses,
    // a further one's on its own (the more specific address gets its connections).
    let listener = match listen(node.share_listen()) {
        Ok(l) => l,
        Err(e) => {
            warn!("sharing: cannot listen on port {PORT}: {e}");
            return;
        }
    };
    loop {
        // An error is mostly "too many open files", and that passes.
        let Ok((stream, addr)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let node = node.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_conn(&node, stream).await {
                debug!("share connection from {addr}: {e:#}");
            }
        });
    }
}

async fn serve_conn(node: &Arc<Node>, mut s: TcpStream) -> Result<()> {
    s.set_nodelay(true).ok();
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    s.write_all(&nonce).await?;
    let mut tag = [0u8; 32];
    tokio::time::timeout(GREETING, s.read_exact(&mut tag)).await??;
    let Some((version, _)) = node
        .network_key_versions()
        .into_iter()
        .find(|(_, k)| auth_tag(k, &nonce) == tag)
    else {
        bail!("not a member of this network");
    };
    let (r, mut w) = s.into_split();
    let mut r = BufReader::new(r);
    let hello = tokio::time::timeout(GREETING, read_line(&mut r))
        .await??
        .ok_or_else(|| anyhow!("closed before the hello"))?;
    let peer = match serde_json::from_slice::<Req>(&hello)? {
        Req::Hello { id, sig } if node.share_admits(&id, version, &nonce, &sig) => {
            w.write_all(&0u64.to_be_bytes()).await?;
            id
        }
        Req::Hello { id, .. } => bail!("{id} is not admitted to this network"),
        _ => bail!("no hello (a node older than 0.33.1?)"),
    };
    #[cfg(target_os = "linux")]
    let who = |user: Option<String>| crate::volume::Who { node: peer, user };
    #[cfg(not(target_os = "linux"))]
    let _ = peer;
    while let Some(line) = tokio::time::timeout(IDLE, read_line(&mut r)).await?? {
        let data: Option<Vec<u8>> = match serde_json::from_slice::<Req>(&line)? {
            Req::Hello { .. } => bail!("a second hello"),
            Req::Sink => {
                let mut buf = vec![0u8; 1 << 20];
                let mut got = 0u64;
                // A measurement takes seconds: what goes on for longer is something else.
                let end = tokio::time::Instant::now() + Duration::from_secs(60);
                loop {
                    match tokio::time::timeout_at(end, r.read(&mut buf)).await?? {
                        0 => break,
                        n => got += n as u64,
                    }
                }
                w.write_all(&got.to_be_bytes()).await?;
                return Ok(());
            }
            Req::Manifest { id } => node.shares.get(&id).map(|s| serde_json::to_vec(&s.manifest).unwrap()),
            #[cfg(target_os = "linux")]
            Req::VolHead { vol, user } => node.volumes.head(&vol, &who(user)),
            #[cfg(target_os = "linux")]
            Req::VolManifest { vol, user } => node.volumes.manifest_bytes(&vol, &who(user)),
            #[cfg(target_os = "linux")]
            Req::VolRead {
                vol,
                user,
                id,
                chunk,
                off,
                len,
            } => {
                static READS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);
                let _permit = READS.acquire().await;
                let (n, who) = (node.clone(), who(user));
                tokio::task::spawn_blocking(move || n.volumes.read_local(&vol, &who, &id, chunk, off, len))
                    .await
                    .ok()
                    .flatten()
            }
            #[cfg(target_os = "linux")]
            Req::VolPut {
                vol,
                user,
                id,
                chunk,
                hash,
                len,
            } => {
                if len as u64 > 64 << 20 {
                    bail!("chunk too large");
                }
                let mut data = vec![0u8; len as usize];
                tokio::time::timeout(Duration::from_secs(60), r.read_exact(&mut data)).await??;
                let (n, who) = (node.clone(), who(user));
                match tokio::task::spawn_blocking(move || n.volumes.put(&vol, &who, &id, chunk, &hash, &data)).await? {
                    Ok(()) => Some(vec![]),
                    Err(e) => {
                        debug!("volume chunk refused: {e:#}");
                        None
                    }
                }
            }
            #[cfg(target_os = "linux")]
            Req::VolCommit { vol, user, len } => {
                if len > 64 << 20 {
                    bail!("commit too large");
                }
                let mut data = vec![0u8; len as usize];
                tokio::time::timeout(Duration::from_secs(60), r.read_exact(&mut data)).await??;
                let answer = match serde_json::from_slice(&data) {
                    Ok(c) => match node.volumes.commit(&vol, &who(user), c).await {
                        Ok(v) => serde_json::json!({ "version": v }),
                        Err(e) => serde_json::json!({ "error": format!("{e:#}") }),
                    },
                    Err(e) => serde_json::json!({ "error": e.to_string() }),
                };
                Some(answer.to_string().into_bytes())
            }
            #[cfg(not(target_os = "linux"))]
            Req::VolHead { .. } | Req::VolManifest { .. } | Req::VolRead { .. } => None,
            #[cfg(not(target_os = "linux"))]
            Req::VolPut { .. } | Req::VolCommit { .. } => bail!("no volumes here"),
            Req::Chunk { id, file, index } => match node.shares.get(&id) {
                Some(s) if file < s.manifest.files.len() && index < s.manifest.files[file].chunks.len() => {
                    let path = s.file(file);
                    let size = s.manifest.files[file].size;
                    let cs = s.manifest.chunk_size;
                    let want = s.manifest.files[file].chunks[index].clone();
                    // A few reads at once (each holds up to a whole chunk in memory).
                    static READS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);
                    let _permit = READS.acquire().await;
                    tokio::task::spawn_blocking(move || -> Option<Vec<u8>> {
                        let off = index as u64 * cs;
                        let mut buf = vec![0u8; (size.saturating_sub(off)).min(cs) as usize];
                        let mut o = std::fs::OpenOptions::new();
                        o.read(true);
                        #[cfg(unix)]
                        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                        let f = o.open(path).ok()?;
                        // A regular file only (not a device a directory link leads to).
                        if !f.metadata().ok()?.is_file() {
                            return None;
                        }
                        f.read_exact_at(&mut buf, off).ok()?;
                        // Only what was shared: a file changed (or swapped for a link to another
                        // one) since then gives nothing.
                        (blake3::hash(&buf).to_hex().as_str() == want).then_some(buf)
                    })
                    .await
                    .ok()
                    .flatten()
                }
                _ => None,
            },
        };
        match data {
            Some(d) => {
                w.write_all(&(d.len() as u64).to_be_bytes()).await?;
                w.write_all(&d).await?;
            }
            None => w.write_all(&MISSING.to_be_bytes()).await?,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Fetching

/// A node that has the object, and how to reach its chunk server.
#[derive(Clone, Debug)]
pub struct Holder {
    pub name: String,
    pub mesh_ip: Ipv4Addr,
    /// Verified LAN address (faster, used when known).
    pub lan_ip: Option<Ipv4Addr>,
}

struct Conn {
    lines: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    w: tokio::net::tcp::OwnedWriteHalf,
}

async fn dial(node: &Node, h: &Holder) -> Result<TcpStream> {
    Ok(match (h.lan_ip, node.socks_addr()) {
        (Some(ip), _) => TcpStream::connect(SocketAddr::from((ip, PORT))).await?,
        (None, Some(socks)) => crate::link::socks5_connect(&socks, &format!("{}:{PORT}", h.mesh_ip)).await?,
        (None, None) => TcpStream::connect(SocketAddr::from((h.mesh_ip, PORT))).await?,
    })
}

/// The client's side of the greeting: a tag of the network key over the server's nonce, then
/// (`hello`) which node this is, signed over the same nonce.
async fn greet(node: &Node, stream: TcpStream, hello: bool) -> Result<Conn> {
    stream.set_nodelay(true).ok();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    let mut nonce = [0u8; 32];
    tokio::time::timeout(GREETING, r.read_exact(&mut nonce)).await??;
    let key = node
        .network_keys()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no network key"))?;
    w.write_all(&auth_tag(&key, &nonce)).await?;
    let mut c = Conn { lines: r, w };
    if hello {
        let (id, sig) = node.share_proof(&nonce);
        match tokio::time::timeout(GREETING, request(&mut c, &Req::Hello { id, sig })).await {
            Ok(Ok(Some(_))) => {}
            _ => bail!("the hello was not accepted"),
        }
    }
    Ok(c)
}

async fn connect(node: &Node, h: &Holder) -> Result<Conn> {
    match greet(node, dial(node, h).await?, true).await {
        Ok(c) => Ok(c),
        // A node older than 0.33.1 doesn't know the hello and closes at it: as before, then.
        Err(_) => greet(node, dial(node, h).await?, false).await,
    }
}

async fn request(c: &mut Conn, req: &Req) -> Result<Option<Vec<u8>>> {
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    c.w.write_all(&line).await?;
    let len = c.lines.read_u64().await?;
    if len == MISSING {
        return Ok(None);
    }
    if len > 128 * 1024 * 1024 {
        bail!("oversized answer");
    }
    let mut buf = vec![0u8; len as usize];
    c.lines.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Connections to other nodes' chunk servers for the volumes, kept open between reads.
#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct Pool {
    conns: Mutex<HashMap<crate::keys::NodeId, Vec<Conn>>>,
    /// Nodes that could not be reached, and when: not tried again for a few seconds.
    failed: Mutex<HashMap<crate::keys::NodeId, Instant>>,
}

#[cfg(target_os = "linux")]
impl Pool {
    pub fn new() -> Self {
        Self::default()
    }

    async fn ask(&self, node: &Node, peer: crate::keys::NodeId, req: &Req) -> Result<Option<Vec<u8>>> {
        if self
            .failed
            .lock()
            .unwrap()
            .get(&peer)
            .is_some_and(|t| t.elapsed() < Duration::from_secs(10))
        {
            bail!("not reachable just now");
        }
        let idle = self.conns.lock().unwrap().get_mut(&peer).and_then(|v| v.pop());
        let mut c = match idle {
            Some(c) => c,
            None => {
                let h = node.holder_of(&peer).ok_or_else(|| anyhow!("offline"))?;
                match tokio::time::timeout(Duration::from_secs(5), connect(node, &h)).await {
                    Ok(Ok(c)) => c,
                    _ => {
                        self.failed.lock().unwrap().insert(peer, Instant::now());
                        bail!("cannot connect to {}", h.name);
                    }
                }
            }
        };
        // A connection that fails is dropped; the next read opens a new one.
        let answer = request(&mut c, req).await?;
        let mut conns = self.conns.lock().unwrap();
        let idle = conns.entry(peer).or_default();
        if idle.len() < 32 {
            idle.push(c);
        }
        Ok(answer)
    }

    async fn ask_with(
        &self,
        node: &Node,
        peer: crate::keys::NodeId,
        req: &Req,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        if self
            .failed
            .lock()
            .unwrap()
            .get(&peer)
            .is_some_and(|t| t.elapsed() < Duration::from_secs(10))
        {
            bail!("not reachable just now");
        }
        let h = node.holder_of(&peer).ok_or_else(|| anyhow!("offline"))?;
        let mut c = tokio::time::timeout(Duration::from_secs(5), connect(node, &h))
            .await
            .map_err(|_| anyhow!("cannot connect to {}", h.name))??;
        let mut line = serde_json::to_vec(req)?;
        line.push(b'\n');
        line.extend_from_slice(body);
        c.w.write_all(&line).await?;
        let len = c.lines.read_u64().await?;
        if len == MISSING {
            return Ok(None);
        }
        if len > 128 * 1024 * 1024 {
            bail!("oversized answer");
        }
        let mut buf = vec![0u8; len as usize];
        c.lines.read_exact(&mut buf).await?;
        let mut conns = self.conns.lock().unwrap();
        let idle = conns.entry(peer).or_default();
        if idle.len() < 32 {
            idle.push(c);
        }
        Ok(Some(buf))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn volume_read(
        &self,
        node: &Node,
        peer: crate::keys::NodeId,
        vol: &str,
        user: Option<&str>,
        id: &str,
        chunk: u32,
        off: u64,
        len: u32,
    ) -> Result<Option<Vec<u8>>> {
        let req = Req::VolRead {
            vol: vol.into(),
            user: user.map(String::from),
            id: id.into(),
            chunk,
            off,
            len,
        };
        self.ask(node, peer, &req).await
    }

    pub async fn volume_head(
        &self,
        node: &Node,
        peer: crate::keys::NodeId,
        vol: &str,
        user: Option<&str>,
    ) -> Result<Option<Vec<u8>>> {
        let req = Req::VolHead {
            vol: vol.into(),
            user: user.map(String::from),
        };
        self.ask(node, peer, &req).await
    }

    pub async fn volume_manifest(
        &self,
        node: &Node,
        peer: crate::keys::NodeId,
        vol: &str,
        user: Option<&str>,
    ) -> Result<Option<Vec<u8>>> {
        let req = Req::VolManifest {
            vol: vol.into(),
            user: user.map(String::from),
        };
        self.ask(node, peer, &req).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn volume_put(
        &self,
        node: &Node,
        peer: crate::keys::NodeId,
        vol: &str,
        user: Option<&str>,
        id: &str,
        chunk: u32,
        hash: &str,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let req = Req::VolPut {
            vol: vol.into(),
            user: user.map(String::from),
            id: id.into(),
            chunk,
            hash: hash.into(),
            len: data.len() as u32,
        };
        self.ask_with(node, peer, &req, data).await
    }

    pub async fn volume_commit(
        &self,
        node: &Node,
        peer: crate::keys::NodeId,
        vol: &str,
        user: Option<&str>,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let req = Req::VolCommit {
            vol: vol.into(),
            user: user.map(String::from),
            len: body.len() as u32,
        };
        self.ask_with(node, peer, &req, body).await
    }
}

/// Throughput over a LAN path, Mbit/s: `streams` connections straight to `ip` (not through the
/// mesh, as NCCL and fetch use it), sending for `secs` seconds.
pub async fn lan_throughput(node: &Arc<Node>, ip: Ipv4Addr, streams: usize, secs: f64) -> Option<f32> {
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..streams {
        set.spawn(sink_stream(node.clone(), ip, secs));
    }
    let mut ok: Vec<(u64, f64)> = vec![];
    while let Some(r) = set.join_next().await {
        ok.extend(r.ok().flatten());
    }
    if ok.is_empty() {
        return None;
    }
    let bytes: u64 = ok.iter().map(|r| r.0).sum();
    let secs = ok.iter().map(|r| r.1).fold(0.0, f64::max);
    Some((bytes as f64 * 8.0 / secs / 1e6) as f32)
}

/// One connection of `lan_throughput`: (bytes the other side got, seconds).
async fn sink_stream(node: Arc<Node>, ip: Ipv4Addr, secs: f64) -> Option<(u64, f64)> {
    let dial = || async {
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(SocketAddr::from((ip, PORT))))
            .await
            .ok()?
            .ok()
    };
    let mut c = match greet(&node, dial().await?, true).await {
        Ok(c) => c,
        // A node older than 0.33.1 (see `connect`).
        Err(_) => greet(&node, dial().await?, false).await.ok()?,
    };
    c.w.write_all(b"\"sink\"\n").await.ok()?;
    let buf = vec![0u8; 1 << 20];
    let start = Instant::now();
    while start.elapsed().as_secs_f64() < secs {
        c.w.write_all(&buf).await.ok()?;
    }
    c.w.shutdown().await.ok()?;
    // Older nodes don't know the test: they just close.
    let got = tokio::time::timeout(Duration::from_secs(10), c.lines.read_u64())
        .await
        .ok()?
        .ok()?;
    Some((got, start.elapsed().as_secs_f64()))
}

#[derive(Serialize, Default, Clone)]
pub struct FetchReport {
    pub id: String,
    pub name: String,
    pub dest: String,
    pub bytes: u64,
    /// Bytes that were already there and verified (resumed or unchanged).
    pub reused_bytes: u64,
    pub seconds: f64,
    pub mbit_per_s: f64,
    /// Bytes per source node.
    pub from: HashMap<String, u64>,
}

/// Downloads object `id` into `dest` from `holders`, then serves it too.
pub async fn fetch(
    node: Arc<Node>,
    id: &str,
    dest: &Path,
    owner: Option<u32>,
    holders: Vec<Holder>,
) -> Result<FetchReport> {
    #[cfg(windows)]
    let _ = owner; // files belong to whoever runs the fetch
    if holders.is_empty() {
        bail!("object {id} not found on any online node (see meshvpn objects)");
    }
    let started = Instant::now();
    // The manifest, from the first holder that has it; it must hash to the id.
    let mut manifest = None;
    for h in &holders {
        let Ok(mut c) = connect(&node, h).await else { continue };
        if let Ok(Some(m)) = request(&mut c, &Req::Manifest { id: id.into() }).await
            && Manifest::id(&m) == id
            && let Ok(m) = serde_json::from_slice::<Manifest>(&m)
        {
            manifest = Some(m);
            break;
        }
    }
    let manifest = manifest.ok_or_else(|| anyhow!("could not get the manifest of {id} from any holder"))?;
    manifest.validate()?;
    #[cfg(unix)]
    safe_destination(dest, owner)?;
    let dest_new = !dest.exists();
    std::fs::create_dir_all(dest)?;
    let dest = dest.canonicalize()?;

    // Prepare files; chunks that are already there and correct are kept (resume).
    let man = manifest.clone();
    let root = dest.clone();
    // (chunks to fetch, bytes already there, directories made)
    type Prepared = (VecDeque<(usize, usize)>, u64, Vec<PathBuf>);
    let (todo, reused, mut created) = tokio::task::spawn_blocking(move || -> Result<Prepared> {
        let mut todo = VecDeque::new();
        let mut reused = 0;
        let mut created = vec![];
        for (fi, f) in man.files.iter().enumerate() {
            let path = inside(&root, &f.path, &mut created)?;
            // Files that weren't there before are this fetch's (and so the user's, `owner`).
            if std::fs::symlink_metadata(&path).is_err() {
                created.push(path.clone());
            }
            let mut opts = std::fs::OpenOptions::new();
            let file = opts
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .custom_flags(NOFOLLOW);
            let file = crate::sys::private(file).open(&path)?;
            if !file.metadata()?.is_file() {
                bail!("{} is not a regular file", path.display());
            }
            let had = file.metadata()?.len();
            file.set_len(f.size)?;
            let mut buf = vec![0u8; man.chunk_size as usize];
            for (ci, hash) in f.chunks.iter().enumerate() {
                let off = ci as u64 * man.chunk_size;
                let len = f.size.saturating_sub(off).min(man.chunk_size) as usize;
                if off + len as u64 <= had
                    && file.read_exact_at(&mut buf[..len], off).is_ok()
                    && blake3::hash(&buf[..len]).to_hex().as_str() == hash
                {
                    reused += len as u64;
                } else {
                    todo.push_back((fi, ci));
                }
            }
        }
        Ok((todo, reused, created))
    })
    .await??;
    if dest_new {
        created.push(dest.clone());
    }

    let total_chunks = todo.len();
    let queue = Arc::new(Mutex::new(todo));
    let report = Arc::new(Mutex::new(FetchReport::default()));
    let failed = Arc::new(Mutex::new(None::<String>));
    let manifest = Arc::new(manifest);
    let mut tasks = vec![];
    for w in 0..WORKERS.min(total_chunks.max(1)) {
        let (node, queue, report, failed, manifest, holders, dest) = (
            node.clone(),
            queue.clone(),
            report.clone(),
            failed.clone(),
            manifest.clone(),
            holders.clone(),
            dest.clone(),
        );
        let id = id.to_string();
        tasks.push(tokio::spawn(async move {
            // Spread the workers over the holders; on errors move on to the next one.
            let mut hi = w % holders.len();
            let mut conn: Option<(usize, Conn)> = None;
            loop {
                let Some((fi, ci)) = queue.lock().unwrap().pop_front() else {
                    return;
                };
                let f = &manifest.files[fi];
                let mut done = false;
                for _attempt in 0..holders.len() * 2 {
                    if conn.as_ref().is_none_or(|(i, _)| *i != hi) {
                        conn = connect(&node, &holders[hi]).await.ok().map(|c| (hi, c));
                    }
                    let got = match &mut conn {
                        Some((_, c)) => {
                            request(
                                c,
                                &Req::Chunk {
                                    id: id.clone(),
                                    file: fi,
                                    index: ci,
                                },
                            )
                            .await
                        }
                        None => Err(anyhow!("cannot connect")),
                    };
                    match got {
                        Ok(Some(data)) if blake3::hash(&data).to_hex().as_str() == f.chunks[ci] => {
                            let path = dest.join(&f.path);
                            let off = ci as u64 * manifest.chunk_size;
                            let len = data.len() as u64;
                            let wrote = tokio::task::spawn_blocking(move || {
                                std::fs::OpenOptions::new()
                                    .write(true)
                                    .custom_flags(NOFOLLOW)
                                    .open(path)?
                                    .write_all_at(&data, off)
                            })
                            .await;
                            if matches!(wrote, Ok(Ok(()))) {
                                let mut r = report.lock().unwrap();
                                r.bytes += len;
                                *r.from.entry(holders[hi].name.clone()).or_default() += len;
                                done = true;
                                break;
                            }
                        }
                        _ => {
                            conn = None;
                            hi = (hi + 1) % holders.len();
                        }
                    }
                }
                if !done {
                    *failed.lock().unwrap() = Some(format!("chunk {ci} of {} not available from any holder", f.path));
                    return;
                }
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    if let Some(e) = failed.lock().unwrap().take() {
        bail!("{e} - run the same fetch again to resume");
    }

    // Done: set modes and owner, and serve it from now on.
    for f in &manifest.files {
        let path = dest.join(&f.path);
        // Never setuid/setgid/sticky or writable by others, whatever the sender says; through the
        // file itself, so a symlink swapped in meanwhile isn't followed.
        if let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW)
            .open(&path)
        {
            #[cfg(unix)]
            let _ = file.set_permissions(std::fs::Permissions::from_mode(safe_mode(f.mode)));
            #[cfg(unix)]
            if let Some(uid) = owner
                && created.contains(&path)
            {
                let _ = std::os::unix::fs::fchown(&file, Some(uid), Some(gid_of(uid)));
            }
            #[cfg(windows)]
            let _ = file;
        }
    }
    // The directories this fetch made (not ones that were there: `sudo meshvpn fetch` into
    // /usr/local must not give /usr/local away).
    #[cfg(unix)]
    if let Some(uid) = owner {
        for d in created
            .iter()
            .filter(|d| std::fs::symlink_metadata(d).is_ok_and(|m| m.is_dir()))
        {
            let _ = std::os::unix::fs::lchown(d, Some(uid), Some(gid_of(uid)));
        }
    }
    let stored = Stored {
        id: id.to_string(),
        manifest: (*manifest).clone(),
        root: dest.clone(),
    };
    node.shares.add(stored)?;
    node.objects_changed();
    let mut r = report.lock().unwrap().clone();
    r.id = id.into();
    r.name = manifest.name.clone();
    r.dest = dest.display().to_string();
    r.reused_bytes = reused;
    r.seconds = started.elapsed().as_secs_f64();
    r.mbit_per_s = r.bytes as f64 * 8.0 / r.seconds.max(1e-6) / 1e6;
    info!("fetched {} ({}) in {:.1}s", id, manifest.name, r.seconds);
    Ok(r)
}

/// The file mode applied to fetched files: permission bits only, not writable by group/others.
pub(crate) fn safe_mode(mode: u32) -> u32 {
    mode & 0o755
}

/// `root/rel` with its parent directories created (added to `created`), refusing to leave
/// `root` (a canonical path) through symlinks already in the tree.
pub(crate) fn inside(root: &Path, rel: &str, created: &mut Vec<PathBuf>) -> Result<PathBuf> {
    let path = root.join(rel);
    let dir = path.parent().ok_or_else(|| anyhow!("bad path {rel}"))?;
    let mut missing = vec![];
    let mut d = Some(dir);
    while let Some(cur) = d.filter(|c| c.starts_with(root) && *c != root) {
        if std::fs::symlink_metadata(cur).is_ok() {
            break;
        }
        missing.push(cur.to_path_buf());
        d = cur.parent();
    }
    std::fs::create_dir_all(dir)?;
    created.extend(missing);
    if !dir.canonicalize()?.starts_with(root) {
        bail!("{rel} leads outside {}", root.display());
    }
    Ok(path)
}

/// Root writes the files: only below directories nobody else can change (no links, none
/// writable by others unless sticky like /tmp, none of another user's than `owner`), so no
/// one can swap a part of the way for a link while it writes.
#[cfg(unix)]
pub(crate) fn safe_destination(dest: &Path, owner: Option<u32>) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let abs = if dest.is_absolute() {
        dest.to_path_buf()
    } else {
        std::env::current_dir()?.join(dest)
    };
    let mut p = Some(abs.as_path());
    while let Some(cur) = p {
        if let Ok(m) = std::fs::symlink_metadata(cur) {
            if m.file_type().is_symlink() && cur.parent().is_some() {
                // A link the system made (e.g. /var/run) is fine if root's, in root's directory.
                let parent_root = cur
                    .parent()
                    .and_then(|d| std::fs::metadata(d).ok())
                    .is_some_and(|d| d.uid() == 0);
                if m.uid() != 0 || !parent_root {
                    bail!("{} is a link: fetch into the directory it points to", cur.display());
                }
            }
            let m = std::fs::metadata(cur)?;
            let theirs = m.uid() != 0 && Some(m.uid()) != owner;
            let open = m.mode() & 0o002 != 0 && m.mode() & 0o1000 == 0;
            if m.is_dir() && (theirs || open) {
                bail!(
                    "{} can be changed by others: fetch into a directory only you (or root) can write",
                    cur.display()
                );
            }
        }
        p = cur.parent();
    }
    Ok(())
}

/// The primary group of `uid`.
#[cfg(unix)]
pub(crate) fn gid_of(uid: u32) -> u32 {
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() { uid } else { (*pw).pw_gid }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetched_files_stay_inside_and_tame() {
        assert_eq!(safe_mode(0o4755), 0o755);
        assert_eq!(safe_mode(0o2777), 0o755);
        assert_eq!(safe_mode(0o644), 0o644);
        let dir = std::env::temp_dir().join(format!("meshvpn-inside-{}", std::process::id()));
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let mut made = vec![];
        assert!(inside(&root, "a/b/c.txt", &mut made).is_ok());
        assert_eq!(made.len(), 2, "a and a/b were made: {made:?}");
        // A symlink planted in the destination doesn't lead out of it.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&dir, root.join("out")).unwrap();
            assert!(inside(&root, "out/x.txt", &mut vec![]).is_err());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn manifests_have_names_records_may_carry() {
        let m = |name: &str| Manifest {
            name: name.into(),
            chunk_size: CHUNK,
            total: 0,
            files: vec![],
        };
        assert!(m("model v2 (final)").validate().is_ok());
        assert!(m("line\nbreak").validate().is_err());
        assert!(m("\x1b[31mred").validate().is_err());
        assert!(m(&"x".repeat(129)).validate().is_err());
    }
}
