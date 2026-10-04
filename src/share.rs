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
use std::os::unix::fs::{FileExt, PermissionsExt};
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
        let mut v: Vec<ObjectAd> = self.objects.lock().unwrap().values().map(Stored::ad).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v.truncate(256);
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
                mode: meta.permissions().mode() & 0o777,
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
    Manifest { id: String },
    Chunk { id: String, file: usize, index: usize },
}

pub async fn serve(node: Arc<Node>) {
    let listener = match TcpListener::bind(("0.0.0.0", PORT)).await {
        Ok(l) => l,
        Err(e) => {
            warn!("sharing: cannot listen on port {PORT}: {e}");
            return;
        }
    };
    while let Ok((stream, addr)) = listener.accept().await {
        let node = node.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_conn(&node, stream).await {
                debug!("share connection from {addr}: {e:#}");
            }
        });
    }
}

async fn serve_conn(node: &Node, mut s: TcpStream) -> Result<()> {
    s.set_nodelay(true).ok();
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    s.write_all(&nonce).await?;
    let mut tag = [0u8; 32];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut tag)).await??;
    if !node.network_keys().iter().any(|k| auth_tag(k, &nonce) == tag) {
        bail!("not a member of this network");
    }
    let (r, mut w) = s.into_split();
    let mut lines = BufReader::new(r).lines();
    while let Some(line) = lines.next_line().await? {
        let data: Option<Vec<u8>> = match serde_json::from_str::<Req>(&line)? {
            Req::Manifest { id } => node.shares.get(&id).map(|s| serde_json::to_vec(&s.manifest).unwrap()),
            Req::Chunk { id, file, index } => match node.shares.get(&id) {
                Some(s) if file < s.manifest.files.len() && index < s.manifest.files[file].chunks.len() => {
                    let path = s.file(file);
                    let size = s.manifest.files[file].size;
                    let cs = s.manifest.chunk_size;
                    tokio::task::spawn_blocking(move || -> Option<Vec<u8>> {
                        let off = index as u64 * cs;
                        let mut buf = vec![0u8; (size.saturating_sub(off)).min(cs) as usize];
                        std::fs::File::open(path).ok()?.read_exact_at(&mut buf, off).ok()?;
                        Some(buf)
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

async fn connect(node: &Node, h: &Holder) -> Result<Conn> {
    let stream = match (h.lan_ip, node.socks_addr()) {
        (Some(ip), _) => TcpStream::connect(SocketAddr::from((ip, PORT))).await?,
        (None, Some(socks)) => crate::link::socks5_connect(&socks, &format!("{}:{PORT}", h.mesh_ip)).await?,
        (None, None) => TcpStream::connect(SocketAddr::from((h.mesh_ip, PORT))).await?,
    };
    stream.set_nodelay(true).ok();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    let mut nonce = [0u8; 32];
    r.read_exact(&mut nonce).await?;
    let key = node
        .network_keys()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no network key"))?;
    w.write_all(&auth_tag(&key, &nonce)).await?;
    Ok(Conn { lines: r, w })
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
    std::fs::create_dir_all(dest)?;
    let dest = dest.canonicalize()?;

    // Prepare files; chunks that are already there and correct are kept (resume).
    let man = manifest.clone();
    let root = dest.clone();
    let (todo, reused) = tokio::task::spawn_blocking(move || -> Result<(VecDeque<(usize, usize)>, u64)> {
        let mut todo = VecDeque::new();
        let mut reused = 0;
        for (fi, f) in man.files.iter().enumerate() {
            let path = root.join(&f.path);
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&path)?;
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
        Ok((todo, reused))
    })
    .await??;

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
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(f.mode));
        if let Some(uid) = owner {
            chown_tree(&dest, &path, uid);
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

/// Gives `path` and its new parent directories below `dest` to `uid`.
fn chown_tree(dest: &Path, path: &Path, uid: u32) {
    let gid = unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() { uid } else { (*pw).pw_gid }
    };
    let mut p = Some(path);
    while let Some(cur) = p {
        if !cur.starts_with(dest) {
            break;
        }
        let _ = std::os::unix::fs::chown(cur, Some(uid), Some(gid));
        p = cur.parent();
    }
}
