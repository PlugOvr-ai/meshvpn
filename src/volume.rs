//! Volumes: storage made of the disks of a group of nodes (prototype).
//!
//! An admin makes a volume for a group of nodes (`meshvpn volume create NAME --nodes a,b,c`),
//! optionally filled from network storage that every node of the group has mounted at the same
//! path (`--from /mnt/lustre/imagenet`). The definition is an admin-signed document; the
//! volume's file list (the manifest) is kept by its first node, which numbers its versions, and
//! the others follow it.
//!
//! Files are cut into chunks of 4 MB. Which nodes keep a chunk follows from the node ids and
//! the file's id alone (rendezvous hashing). Files copied in (`meshvpn volume cp`, from any
//! member - a laptop too) go straight to those nodes, in `copies` copies (2 by default: there is
//! nothing behind them); then the first node takes them into the file list. Files from the
//! network storage are copied by each node itself, its share of them, all nodes at once; until
//! then, and when that node is offline, they are read from the storage.
//!
//! Every node of the group mounts the volume read-only (FUSE) at `/volumes/NAME`, without root
//! at `~/volumes/NAME`: a chunk comes from its own disk or from a node that keeps it (chunk
//! server, port 7871, over the LAN where there is one). The kernel's page cache keeps what was
//! read in RAM. Files change only by `volume cp` and `volume rm`, never by writing into the
//! mount: every node sees the same files.

pub mod fuse;

use crate::keys::NodeId;
use crate::node::Node;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tracing::{info, warn};

/// Document kind of a volume's definition: `volume/<name>`.
pub const KIND_PREFIX: &str = "volume/";
const CHUNK: u64 = 4 << 20;
const STAGE_THREADS: usize = 8;
const FUSE_THREADS: usize = 16;
const MAX_FILES: usize = 20_000_000;
const MAX_NODES: usize = 256;
/// Chunks no file refers to are deleted after this long (an upload may not have committed yet).
const GC_AFTER: Duration = Duration::from_secs(3600);
/// Files a commit may add at most (an upload sends more in several).
const COMMIT_FILES: usize = 5000;

/// A volume as the admins defined it (the data of its document).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Def {
    pub name: String,
    /// The nodes whose disks hold it; the first one keeps the file list.
    pub nodes: Vec<NodeId>,
    /// Network storage it was filled from (the same path on every node of the group).
    #[serde(default)]
    pub source: Option<String>,
    /// Copies of each chunk of a file copied in.
    pub copies: u8,
    /// When it was made (ms): a volume made again under the same name is another one.
    pub created: u64,
    #[serde(default)]
    pub removed: bool,
}

impl Def {
    /// This volume, as distinct from an earlier one of the same name.
    pub fn key(&self) -> String {
        format!("{}-{}", self.name, self.created)
    }

    pub fn keeper(&self) -> NodeId {
        self.nodes[0]
    }

    pub fn mount(&self) -> PathBuf {
        mount_root().join(&self.name)
    }

    fn store_dir(&self) -> PathBuf {
        store_root().join(self.key())
    }

    pub fn check(&self) -> Result<()> {
        valid_name(&self.name)?;
        if self.nodes.is_empty() || self.nodes.len() > MAX_NODES {
            bail!("a volume needs 1 to {MAX_NODES} nodes");
        }
        if self.copies == 0 || self.copies as usize > self.nodes.len().min(8) {
            bail!("copies: 1 to the number of nodes (at most 8)");
        }
        if self.source.as_ref().is_some_and(|s| !s.starts_with('/')) {
            bail!("the source must be an absolute path");
        }
        Ok(())
    }
}

pub fn valid_name(name: &str) -> Result<()> {
    let ok = (1..=48).contains(&name.len())
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b));
    if !ok {
        bail!("volume names are 1 to 48 of a-z, 0-9, '-', '_', '.' (not starting with '.')");
    }
    Ok(())
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
}

/// `/volumes`, without root `~/volumes`.
pub fn mount_root() -> PathBuf {
    if crate::config::rootless() {
        home().join("volumes")
    } else {
        PathBuf::from("/volumes")
    }
}

fn store_root() -> PathBuf {
    if crate::config::rootless() {
        std::env::var_os("XDG_CACHE_HOME")
            .map_or_else(|| home().join(".cache"), PathBuf::from)
            .join("meshvpn/volumes")
    } else {
        PathBuf::from("/var/lib/meshvpn/volumes")
    }
}

/// The files of a volume, in one version.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Manifest {
    pub volume: String,
    pub version: u64,
    pub chunk: u64,
    /// Sorted by path.
    pub files: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    /// Relative, with `/`.
    pub path: String,
    /// 32 hex digits; a file copied in again gets a new one.
    pub id: String,
    pub size: u64,
    pub mtime_ns: i64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// The account that copied it in (resolved to its uid on each node); it and root may
    /// replace or remove the file. None: from the storage, with the storage's uid and gid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// From the network storage (read there until it is copied, and when its node is offline).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub src: bool,
    /// BLAKE3 of each chunk (hex), for files copied in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<String>,
}

impl Entry {
    fn id128(&self) -> u128 {
        u128::from_str_radix(&self.id, 16).unwrap_or(0)
    }
}

fn valid_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 4096
        && !p.contains('\0')
        && !p.split('/').any(|c| c.is_empty() || c == "." || c == "..")
}

impl Manifest {
    fn validate(&self) -> Result<()> {
        if !(64 * 1024..=64 * 1024 * 1024).contains(&self.chunk) || self.files.len() > MAX_FILES {
            bail!("bad file list");
        }
        for f in &self.files {
            check_entry(f, self.chunk)?;
        }
        Ok(())
    }

    fn chunks(&self, f: &Entry) -> u64 {
        f.size.div_ceil(self.chunk)
    }

    fn chunk_len(&self, f: &Entry, c: u64) -> u64 {
        f.size.saturating_sub(c * self.chunk).min(self.chunk)
    }

    /// Applies a commit (files copied in, paths removed); the version goes up by one.
    fn apply(&mut self, c: &Commit) -> Result<()> {
        if c.add.len() > COMMIT_FILES {
            bail!("too many files in one commit");
        }
        for e in &c.add {
            check_entry(e, self.chunk)?;
            if e.src {
                bail!("{}: files copied in are not from the storage", e.path);
            }
        }
        // Built aside: a commit that doesn't fit leaves the list as it was.
        let mut files: Vec<Entry> = self.files.clone();
        for p in &c.remove {
            let dir = format!("{p}/");
            files.retain(|f| f.path != *p && !f.path.starts_with(&dir));
        }
        let added: HashSet<&str> = c.add.iter().map(|e| e.path.as_str()).collect();
        files.retain(|f| !added.contains(f.path.as_str()));
        files.extend(c.add.iter().cloned());
        files.sort_by(|a, b| a.path.cmp(&b.path));
        fuse::Tree::build(&files)?;
        self.files = files;
        self.version += 1;
        Ok(())
    }
}

fn check_entry(f: &Entry, chunk: u64) -> Result<()> {
    if !valid_path(&f.path) || f.id.len() != 32 || !f.id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("bad entry {:?}", f.path);
    }
    if !f.src && f.hashes.len() as u64 != f.size.div_ceil(chunk) {
        bail!("{}: the chunk list doesn't match the size", f.path);
    }
    Ok(())
}

/// Files copied in (`add`) and paths removed (files, or directories with everything in them).
#[derive(Serialize, Deserialize, Default)]
pub struct Commit {
    pub add: Vec<Entry>,
    pub remove: Vec<String>,
}

fn mtime_ns(m: &std::fs::Metadata) -> i64 {
    m.mtime() * 1_000_000_000 + m.mtime_nsec()
}

fn new_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// Lists the regular files under `root` (links and special files are left out: their count).
pub fn scan(root: &Path, volume: &str) -> Result<(Manifest, u64)> {
    fn walk(root: &Path, rel: &str, out: &mut Vec<Entry>, skipped: &mut u64, salt: &str) -> Result<()> {
        let dir = if rel.is_empty() {
            root.to_path_buf()
        } else {
            root.join(rel)
        };
        let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(&dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let file_name = e.file_name();
            let Some(n) = file_name.to_str() else {
                *skipped += 1;
                continue;
            };
            let p = if rel.is_empty() {
                n.to_string()
            } else {
                format!("{rel}/{n}")
            };
            let m = std::fs::symlink_metadata(e.path())?;
            if m.is_dir() {
                walk(root, &p, out, skipped, salt)?;
            } else if m.is_file() {
                // The same id for the same path in this volume: a node that lists the files again
                // after a crash keeps the chunks it copied.
                let id = blake3::hash(format!("{salt}\0{p}").as_bytes()).to_hex()[..32].to_string();
                out.push(Entry {
                    path: p,
                    id,
                    size: m.len(),
                    mtime_ns: mtime_ns(&m),
                    mode: m.mode() & 0o7777,
                    uid: m.uid(),
                    gid: m.gid(),
                    owner: None,
                    src: true,
                    hashes: vec![],
                });
                if out.len() > MAX_FILES {
                    bail!("more than {MAX_FILES} files");
                }
            } else {
                *skipped += 1;
            }
        }
        Ok(())
    }
    let mut files = vec![];
    let mut skipped = 0;
    walk(root, "", &mut files, &mut skipped, volume)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((
        Manifest {
            volume: volume.into(),
            version: 1,
            chunk: CHUNK,
            files,
        },
        skipped,
    ))
}

/// Network and cluster file systems: a volume's source must be on one. An admin decides what a
/// volume is, but not to copy a node's local files (`/root`, `/etc`) to the other nodes.
pub fn network_fs(path: &Path) -> Result<bool> {
    const TYPES: &[u32] = &[
        0x6969,      // NFS
        0x517b,      // SMB
        0xff53_4d42, // CIFS
        0xfe53_4d42, // SMB2
        0x0bd0_0bd0, // Lustre
        0x4750_4653, // GPFS / Spectrum Scale
        0x00c3_6400, // CephFS
        0x1983_0326, // BeeGFS
        0x0102_1997, // 9p
        0x5346_414f, // AFS
        0x6573_5546, // FUSE (sshfs, JuiceFS, ...)
        0x7461_636f, // OCFS2
        0x0116_1970, // GFS2
    ];
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: zeroed is a valid statfs; the path is a valid C string; the result is checked.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        bail!("{}: {}", path.display(), std::io::Error::last_os_error());
    }
    Ok(TYPES.contains(&((s.f_type as u64) as u32)))
}

/// The `k` nodes that keep chunk `chunk` of file `id`, best first (rendezvous hashing: a node
/// more or less moves only the chunks it takes or had).
fn keepers(nodes: &[NodeId], id: u128, chunk: u64, k: usize) -> Vec<NodeId> {
    let mut scored: Vec<(u64, NodeId)> = nodes
        .iter()
        .map(|n| {
            let mut h = blake3::Hasher::new();
            h.update(&n.0);
            h.update(&id.to_le_bytes());
            h.update(&chunk.to_le_bytes());
            (u64::from_le_bytes(h.finalize().as_bytes()[..8].try_into().unwrap()), *n)
        })
        .collect();
    scored.sort_by_key(|s| std::cmp::Reverse(s.0));
    scored.into_iter().take(k.max(1)).map(|(_, n)| n).collect()
}

// --------------------------------------------------------------------------------- user rights

/// A local account: what the kernel checks file access with.
#[derive(Clone, Debug)]
pub struct Creds {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

/// The account `name` on this machine.
pub fn creds_of(name: &str) -> Option<Creds> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam_r with buffers of the given sizes; the results are checked.
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        if libc::getpwnam_r(c.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) != 0 || out.is_null() {
            return None;
        }
        let mut groups = vec![0 as libc::gid_t; 256];
        let mut n = groups.len() as libc::c_int;
        if libc::getgrouplist(c.as_ptr(), pw.pw_gid, groups.as_mut_ptr(), &mut n) < 0 {
            n = 0;
        }
        groups.truncate(n.max(0) as usize);
        Some(Creds {
            uid: pw.pw_uid,
            gid: pw.pw_gid,
            groups,
        })
    }
}

/// uid and gid of a file as this node shows them: the storage's, or its owner's here (an
/// account that doesn't exist here: nobody).
pub fn owner_ids(e: &Entry) -> (u32, u32) {
    type Ids = Option<(Instant, HashMap<String, (u32, u32)>)>;
    static CACHE: Mutex<Ids> = Mutex::new(None);
    let Some(name) = &e.owner else {
        return (e.uid, e.gid);
    };
    let mut c = CACHE.lock().unwrap();
    if c.as_ref().is_none_or(|(at, _)| at.elapsed() > Duration::from_secs(60)) {
        *c = Some((Instant::now(), HashMap::new()));
    }
    let map = &mut c.as_mut().unwrap().1;
    *map.entry(name.clone())
        .or_insert_with(|| creds_of(name).map_or((65534, 65534), |c| (c.uid, c.gid)))
}

/// May `a` read `e`? As the kernel decides it for the mount: owner, group, others.
fn may_read(e: &Entry, a: &Creds) -> bool {
    if a.uid == 0 {
        return true;
    }
    let (uid, gid) = owner_ids(e);
    let bits = if a.uid == uid {
        e.mode >> 6
    } else if a.gid == gid || a.groups.contains(&gid) {
        e.mode >> 3
    } else {
        e.mode
    };
    bits & 0o4 != 0
}

/// May `a` replace or remove `e`? Its owner and root (directories are open to everyone with
/// access, as /tmp is: each changes only its own files).
fn may_change(e: &Entry, a: &Creds) -> bool {
    a.uid == 0 || owner_ids(e).0 == a.uid
}

/// Runs `f` with the file-system rights of `creds` (this thread only: Linux's fsuid, fsgid and
/// groups are per thread), so that the daemon opens and makes files as the user would - never
/// with root's rights on a user's behalf.
pub fn with_creds<T>(creds: Option<&Creds>, f: impl FnOnce() -> T) -> T {
    #[cfg(not(target_arch = "arm"))]
    use libc::{SYS_setfsgid as SETFSGID, SYS_setfsuid as SETFSUID, SYS_setgroups as SETGROUPS};
    #[cfg(target_arch = "arm")]
    use libc::{SYS_setfsgid32 as SETFSGID, SYS_setfsuid32 as SETFSUID, SYS_setgroups32 as SETGROUPS};
    let Some(c) = creds else { return f() };
    struct Back;
    impl Drop for Back {
        fn drop(&mut self) {
            // SAFETY: plain syscalls on this thread's credentials.
            unsafe {
                libc::syscall(SETFSUID, 0);
                libc::syscall(SETFSGID, 0);
                libc::syscall(SETGROUPS, 0, std::ptr::null::<libc::gid_t>());
            }
        }
    }
    let _back = Back;
    // SAFETY: as above; the groups outlive the call. The raw syscalls, not libc's wrappers:
    // those change every thread of the process.
    unsafe {
        libc::syscall(SETGROUPS, c.groups.len(), c.groups.as_ptr());
        libc::syscall(SETFSGID, c.gid);
        libc::syscall(SETFSUID, c.uid);
    }
    f()
}

/// Who asks: a user (None: the node itself, for its own mount) on a node.
#[derive(Clone, Debug)]
pub struct Who {
    pub node: NodeId,
    pub user: Option<String>,
}

/// The account `who` works as on this node. Here: the user itself. From another node: the one
/// its SSH access here gives it (`meshvpn ssh allow`) - the account of the same name if it may
/// log in as that, else the first that isn't root, else root. Without SSH access, none: only
/// who could log in to a node works with its volumes.
fn account(node: &Node, who: &Who) -> Result<(String, Creds)> {
    let user = who.user.clone().ok_or_else(|| anyhow!("no user"))?;
    if crate::config::rootless() {
        // A rootless install has one account, its own.
        let own = crate::sys::user_name_of(unsafe { libc::geteuid() }).ok_or_else(|| anyhow!("no account"))?;
        if who.node != node.id() && node.ssh_accounts(&who.node, &user).is_empty() {
            bail!(
                "{user}@{} has no SSH access to {}",
                node.node_names(&[who.node]).join(""),
                node.node_names(&[node.id()]).join("")
            );
        }
        let c = creds_of(&own).ok_or_else(|| anyhow!("no account {own}"))?;
        return Ok((own, c));
    }
    if who.node == node.id() {
        let c = creds_of(&user).ok_or_else(|| anyhow!("no account {user} here"))?;
        return Ok((user, c));
    }
    let mut accounts: Vec<(String, Creds)> = node
        .ssh_accounts(&who.node, &user)
        .into_iter()
        .filter_map(|a| creds_of(&a).map(|c| (a, c)))
        .collect();
    if accounts.is_empty() {
        bail!(
            "{user}@{} has no SSH access to {} (meshvpn ssh allow there)",
            node.node_names(&[who.node]).join(""),
            node.node_names(&[node.id()]).join("")
        );
    }
    accounts.sort_by_key(|(a, c)| (*a != user, c.uid == 0, a.clone()));
    Ok(accounts.swap_remove(0))
}

// ---------------------------------------------------------------------------------- the store

/// A node's chunks of one volume: `<dir>/<file id>/<chunk>`, written to a temporary name and
/// renamed (a crash leaves no half chunk under a real name).
struct Store {
    dir: PathBuf,
    have: RwLock<HashSet<(u128, u32)>>,
}

impl Store {
    fn open(dir: &Path) -> Result<Store> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let _ = std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        let mut have = HashSet::new();
        for d in std::fs::read_dir(dir)?.flatten() {
            let Some(id) = d.file_name().to_str().and_then(|n| u128::from_str_radix(n, 16).ok()) else {
                continue;
            };
            for c in std::fs::read_dir(d.path()).into_iter().flatten().flatten() {
                let name = c.file_name();
                let name = name.to_string_lossy();
                match name.parse::<u32>() {
                    Ok(n) => {
                        have.insert((id, n));
                    }
                    Err(_) => {
                        let _ = std::fs::remove_file(c.path()); // a temporary one
                    }
                }
            }
        }
        Ok(Store {
            dir: dir.into(),
            have: RwLock::new(have),
        })
    }

    fn path(&self, id: u128, chunk: u32) -> PathBuf {
        self.dir.join(format!("{id:032x}")).join(chunk.to_string())
    }

    fn has(&self, id: u128, chunk: u32) -> bool {
        self.have.read().unwrap().contains(&(id, chunk))
    }

    fn put(&self, id: u128, chunk: u32, bytes: &[u8]) -> Result<()> {
        let path = self.path(id, chunk);
        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(format!(".{chunk}.{}", rand::random::<u32>()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)?;
        self.have.write().unwrap().insert((id, chunk));
        Ok(())
    }

    /// `len` bytes from `within` of a chunk this node has.
    fn read(&self, id: u128, chunk: u32, within: u64, len: u32) -> Option<std::io::Result<Vec<u8>>> {
        if !self.has(id, chunk) {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        Some(
            std::fs::File::open(self.path(id, chunk))
                .and_then(|f| f.read_exact_at(&mut buf, within))
                .map(|_| buf),
        )
    }

    /// Deletes the chunks of files the volume no longer has (left alone for `GC_AFTER`: an
    /// upload may still commit them). Returns how many files' chunks went.
    fn collect(&self, keep: &HashSet<u128>) -> usize {
        let old: Vec<u128> = {
            let have = self.have.read().unwrap();
            let mut ids: Vec<u128> = have.iter().map(|(i, _)| *i).filter(|i| !keep.contains(i)).collect();
            ids.sort();
            ids.dedup();
            ids
        };
        let mut gone = 0;
        for id in old {
            let dir = self.dir.join(format!("{id:032x}"));
            let age = std::fs::metadata(&dir)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok());
            if age.is_some_and(|a| a >= GC_AFTER) && std::fs::remove_dir_all(&dir).is_ok() {
                self.have.write().unwrap().retain(|(i, _)| *i != id);
                gone += 1;
            }
        }
        gone
    }

    /// Room for more: a tenth of the disk (at least 1 GB) stays free.
    fn room(&self) -> bool {
        let Ok(c) = std::ffi::CString::new(self.dir.as_os_str().as_encoded_bytes()) else {
            return false;
        };
        // SAFETY: zeroed is a valid statvfs; the result is checked.
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
            return false;
        }
        let total = s.f_blocks as u64 * s.f_frsize as u64;
        let free = s.f_bavail as u64 * s.f_frsize as u64;
        free > (total / 10).max(1 << 30)
    }

    fn bytes(&self) -> u64 {
        let ids: HashSet<u128> = self.have.read().unwrap().iter().map(|(i, _)| *i).collect();
        ids.iter()
            .flat_map(|id| {
                std::fs::read_dir(self.dir.join(format!("{id:032x}")))
                    .into_iter()
                    .flatten()
                    .flatten()
            })
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    }
}

// ------------------------------------------------------------------------------- one volume

#[derive(Default)]
struct Stats {
    /// Chunks from the storage this node keeps, and how many of them it has.
    owned_chunks: AtomicU64,
    owned_bytes: AtomicU64,
    staged_chunks: AtomicU64,
    staged_bytes: AtomicU64,
    /// Files whose copy failed in the last pass (tried again).
    failed_files: AtomicU64,
    local_bytes: AtomicU64,
    remote_bytes: AtomicU64,
    source_bytes: AtomicU64,
    errors: AtomicU64,
    done: AtomicBool,
    stage_secs: AtomicU64,
    note: Mutex<Option<String>>,
}

impl Stats {
    fn note(&self, text: String) {
        let mut n = self.note.lock().unwrap();
        if n.as_deref() != Some(&text) {
            warn!("{text}");
        }
        *n = Some(text);
    }
}

fn open_source(source: &str, f: &Entry) -> Result<std::fs::File> {
    let path = Path::new(source).join(&f.path);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let m = file.metadata()?;
    if !m.is_file() || m.len() != f.size || mtime_ns(&m) != f.mtime_ns {
        bail!("{} changed on the storage since the volume was made", path.display());
    }
    Ok(file)
}

/// What everything that works on one volume shares: the file list, the store (None on a node
/// that only copies in or out), reading.
struct Vol {
    def: Def,
    me: NodeId,
    node: Arc<Node>,
    rt: tokio::runtime::Handle,
    pool: Arc<crate::share::Pool>,
    store: Option<Arc<Store>>,
    stats: Stats,
    man: RwLock<Arc<Manifest>>,
    /// Source files opened (and checked) for reads: a few (each is a descriptor).
    open_src: Mutex<HashMap<String, Arc<std::fs::File>>>,
}

impl Vol {
    fn manifest(&self) -> Arc<Manifest> {
        self.man.read().unwrap().clone()
    }

    fn source_file(&self, e: &Entry) -> Result<Arc<std::fs::File>, i32> {
        let Some(source) = &self.def.source else {
            return Err(libc::EIO);
        };
        if let Some(f) = self.open_src.lock().unwrap().get(&e.id) {
            return Ok(f.clone());
        }
        let f = Arc::new(open_source(source, e).map_err(|err| {
            self.stats.errors.fetch_add(1, Relaxed);
            self.stats.note(format!("volume {}: {err:#}", self.def.name));
            libc::EIO
        })?);
        let mut open = self.open_src.lock().unwrap();
        if open.len() >= 32 {
            open.clear();
        }
        open.insert(e.id.clone(), f.clone());
        Ok(f)
    }

    fn copies(&self, e: &Entry) -> usize {
        if e.src { 1 } else { self.def.copies as usize }
    }

    /// `len` bytes at `pos` of `e`, all in chunk `c`; `user`: for whom (None: this node's mount).
    #[allow(clippy::too_many_arguments)]
    fn piece(
        &self,
        e: &Entry,
        chunk: u64,
        c: u64,
        pos: u64,
        len: u32,
        user: Option<&str>,
        out: &mut Vec<u8>,
    ) -> Result<(), i32> {
        let id = e.id128();
        let within = pos - c * chunk;
        if let Some(Ok(b)) = self.store.as_ref().and_then(|s| s.read(id, c as u32, within, len)) {
            self.stats.local_bytes.fetch_add(len as u64, Relaxed);
            out.extend_from_slice(&b);
            return Ok(());
        }
        for keeper in keepers(&self.def.nodes, id, c, self.copies(e)) {
            if keeper == self.me {
                continue;
            }
            let key = self.def.key();
            let fetch = self
                .pool
                .volume_read(&self.node, keeper, &key, user, &e.id, c as u32, within, len);
            // The timer must be made inside the runtime: this is one of the FUSE threads.
            if let Ok(Ok(Some(b))) = self
                .rt
                .block_on(async { tokio::time::timeout(Duration::from_secs(10), fetch).await })
                && b.len() == len as usize
            {
                self.stats.remote_bytes.fetch_add(len as u64, Relaxed);
                out.extend_from_slice(&b);
                return Ok(());
            }
        }
        if !e.src {
            self.stats.errors.fetch_add(1, Relaxed);
            return Err(libc::EIO); // every node that keeps it is offline
        }
        // Not copied yet, or its node is offline: from the network storage.
        let src = self.source_file(e)?;
        let start = out.len();
        out.resize(start + len as usize, 0);
        src.read_exact_at(&mut out[start..], pos).map_err(|_| libc::EIO)?;
        self.stats.source_bytes.fetch_add(len as u64, Relaxed);
        Ok(())
    }

    fn read_entry(&self, e: &Entry, off: u64, size: u32, user: Option<&str>) -> Result<Vec<u8>, i32> {
        if off >= e.size {
            return Ok(vec![]);
        }
        let chunk = self.manifest().chunk;
        let end = off.saturating_add(size as u64).min(e.size);
        let mut out = Vec::with_capacity((end - off) as usize);
        let mut pos = off;
        while pos < end {
            let c = pos / chunk;
            let stop = ((c + 1) * chunk).min(end);
            self.piece(e, chunk, c, pos, (stop - pos) as u32, user, &mut out)?;
            pos = stop;
        }
        Ok(out)
    }

    /// A new version of the file list: the mount shows it, and chunks no file needs any more
    /// go (after a while).
    fn set_manifest(&self, m: Manifest, mount: Option<&fuse::Mount>) -> Result<()> {
        let tree = fuse::Tree::build(&m.files)?;
        if let Some(mount) = mount {
            mount.update(tree);
        }
        *self.man.write().unwrap() = Arc::new(m);
        Ok(())
    }

    fn collect(&self) {
        if let Some(store) = &self.store {
            let keep: HashSet<u128> = self.manifest().files.iter().map(Entry::id128).collect();
            let gone = store.collect(&keep);
            if gone > 0 {
                info!(
                    "volume {}: deleted the chunks of {gone} file(s) it no longer has",
                    self.def.name
                );
            }
        }
    }
}

struct Reader(Arc<Vol>);

impl fuse::Source for Reader {
    fn read(&self, e: &Entry, off: u64, size: u32) -> Result<Vec<u8>, i32> {
        self.0.read_entry(e, off, size, None)
    }
}

/// Copies this node's chunks of the files from the storage, `STAGE_THREADS` files at a time,
/// again and again until it has them all (and when the list changes).
fn stage(vol: &Vol, stop: &AtomicBool) {
    let Some(store) = &vol.store else { return };
    let Some(source) = vol.def.source.clone() else {
        vol.stats.done.store(true, Relaxed);
        return;
    };
    let started = Instant::now();
    let mut seen = 0u64;
    let mut retry_at: Option<Instant> = None;
    while !stop.load(Relaxed) {
        let man = vol.manifest();
        if man.version == seen && retry_at.is_none_or(|t| Instant::now() < t) {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }
        seen = man.version;
        let (mut owned, mut owned_bytes, mut staged, mut staged_bytes) = (0, 0, 0, 0);
        let mut work: Vec<(&Entry, Vec<u32>)> = vec![];
        for e in man.files.iter().filter(|e| e.src) {
            let mut todo = vec![];
            for c in 0..man.chunks(e) {
                if keepers(&vol.def.nodes, e.id128(), c, 1)[0] != vol.me {
                    continue;
                }
                let len = man.chunk_len(e, c);
                owned += 1;
                owned_bytes += len;
                if store.has(e.id128(), c as u32) {
                    staged += 1;
                    staged_bytes += len;
                } else {
                    todo.push(c as u32);
                }
            }
            if !todo.is_empty() {
                work.push((e, todo));
            }
        }
        let s = &vol.stats;
        s.owned_chunks.store(owned, Relaxed);
        s.owned_bytes.store(owned_bytes, Relaxed);
        s.staged_chunks.store(staged, Relaxed);
        s.staged_bytes.store(staged_bytes, Relaxed);
        if work.is_empty() {
            if !s.done.swap(true, Relaxed) {
                s.stage_secs.store(started.elapsed().as_secs(), Relaxed);
                info!(
                    "volume {}: this node's {} from the storage are on its disk ({} s)",
                    vol.def.name,
                    crate::cli::human_bytes(owned_bytes),
                    started.elapsed().as_secs()
                );
            }
            retry_at = None;
            continue;
        }
        s.done.store(false, Relaxed);
        let next = std::sync::atomic::AtomicUsize::new(0);
        let full = AtomicBool::new(false);
        let failed = AtomicU64::new(0);
        let puts = AtomicU64::new(0);
        std::thread::scope(|sc| {
            for _ in 0..STAGE_THREADS {
                sc.spawn(|| {
                    let mut buf = vec![0u8; man.chunk as usize];
                    'files: loop {
                        let Some((e, chunks)) = work.get(next.fetch_add(1, Relaxed)) else {
                            return;
                        };
                        let file = match open_source(&source, e) {
                            Ok(x) => x,
                            Err(err) => {
                                failed.fetch_add(1, Relaxed);
                                s.note(format!("volume {}: {err:#}", vol.def.name));
                                continue;
                            }
                        };
                        for &c in chunks {
                            if stop.load(Relaxed) || full.load(Relaxed) {
                                return;
                            }
                            if puts.fetch_add(1, Relaxed).is_multiple_of(16) && !store.room() {
                                full.store(true, Relaxed);
                                s.note(format!(
                                    "volume {}: the disk of {} is nearly full - the rest is read from the storage",
                                    vol.def.name,
                                    store.dir.display()
                                ));
                                return;
                            }
                            let len = man.chunk_len(e, c as u64) as usize;
                            if let Err(err) = file.read_exact_at(&mut buf[..len], c as u64 * man.chunk) {
                                failed.fetch_add(1, Relaxed);
                                s.note(format!("volume {}: reading {}: {err}", vol.def.name, e.path));
                                continue 'files;
                            }
                            if let Err(err) = store.put(e.id128(), c, &buf[..len]) {
                                s.note(format!(
                                    "volume {}: writing to {}: {err:#}",
                                    vol.def.name,
                                    store.dir.display()
                                ));
                                full.store(true, Relaxed);
                                return;
                            }
                            s.staged_chunks.fetch_add(1, Relaxed);
                            s.staged_bytes.fetch_add(len as u64, Relaxed);
                        }
                    }
                });
            }
        });
        s.failed_files.store(failed.load(Relaxed), Relaxed);
        // Whatever failed (or didn't fit) is tried again in a while; the rest is done.
        seen = 0;
        retry_at = Some(
            Instant::now()
                + Duration::from_secs(if failed.load(Relaxed) > 0 || full.load(Relaxed) {
                    30
                } else {
                    0
                }),
        );
    }
}

// ---------------------------------------------------------------------------------- volumes

struct Active {
    vol: Arc<Vol>,
    stop: Arc<AtomicBool>,
    mount: Mutex<Option<fuse::Mount>>,
    stager: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Active {
    fn shutdown(&self) {
        self.stop.store(true, Relaxed);
        drop(self.mount.lock().unwrap().take());
        if let Some(t) = self.stager.lock().unwrap().take() {
            let _ = t.join();
        }
    }
}

/// The volumes of this node: the file lists in `<dir>/volumes`, the chunks under `store_root()`.
pub struct Volumes {
    dir: PathBuf,
    active: Mutex<HashMap<String, Arc<Active>>>,
    /// Volumes that could not start: (key, when, why) - tried again after a few seconds.
    failed: Mutex<HashMap<String, (String, Instant, String)>>,
    pool: Arc<crate::share::Pool>,
    /// One commit at a time on the node that keeps a file list.
    commit_lock: tokio::sync::Mutex<()>,
}

impl Volumes {
    pub fn new(node_dir: &Path) -> Self {
        Volumes {
            dir: node_dir.join("volumes"),
            active: Mutex::new(HashMap::new()),
            failed: Mutex::new(HashMap::new()),
            pool: Arc::new(crate::share::Pool::new()),
            commit_lock: tokio::sync::Mutex::new(()),
        }
    }

    fn manifest_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    fn load_manifest(&self, key: &str) -> Option<Manifest> {
        let m: Manifest = serde_json::from_slice(&std::fs::read(self.manifest_path(key)).ok()?).ok()?;
        m.validate().ok()?;
        Some(m)
    }

    fn save_manifest(&self, m: &Manifest) -> Result<()> {
        crate::config::create_dir(&self.dir)?;
        let path = self.manifest_path(&m.volume);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(m)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    fn vol(&self, key: &str) -> Option<Arc<Vol>> {
        self.active
            .lock()
            .unwrap()
            .values()
            .find(|a| a.vol.def.key() == key)
            .map(|a| a.vol.clone())
    }

    // ------------------------------------------------------------- for the chunk server

    /// May `who` see the volume (its file list)? Its nodes (for their mounts), and users with
    /// SSH access here.
    fn sees(&self, v: &Vol, who: &Who) -> bool {
        (who.user.is_none() && v.def.nodes.contains(&who.node)) || account(&v.node, who).is_ok()
    }

    /// The version of the file list (on the node that keeps it).
    pub fn head(&self, key: &str, who: &Who) -> Option<Vec<u8>> {
        let v = self.vol(key)?;
        (v.def.keeper() == v.me && self.sees(&v, who)).then(|| v.manifest().version.to_be_bytes().to_vec())
    }

    pub fn manifest_bytes(&self, key: &str, who: &Who) -> Option<Vec<u8>> {
        let v = self.vol(key)?;
        if !self.sees(&v, who) {
            return None;
        }
        serde_json::to_vec(&*v.manifest()).ok()
    }

    /// Bytes of a chunk this node keeps (None: not here, or not for `who`: a user reads only
    /// what its account here may read; the volume's nodes read for their mounts, where the
    /// kernel checks).
    pub fn read_local(&self, key: &str, who: &Who, id: &str, chunk: u32, within: u64, len: u32) -> Option<Vec<u8>> {
        let v = self.vol(key)?;
        if len as u64 > v.manifest().chunk {
            return None;
        }
        if !(who.user.is_none() && v.def.nodes.contains(&who.node)) {
            let (_, creds) = account(&v.node, who).ok()?;
            let m = v.manifest();
            let e = m.files.iter().find(|f| f.id == id)?;
            if !may_read(e, &creds) {
                return None;
            }
        }
        let id = u128::from_str_radix(id, 16).ok()?;
        v.store.as_ref()?.read(id, chunk, within, len)?.ok()
    }

    /// A chunk copied in: kept if this node is one of the volume's, `who` has SSH access here,
    /// there is room, and it is what its hash says.
    pub fn put(&self, key: &str, who: &Who, id: &str, chunk: u32, hash: &str, data: &[u8]) -> Result<()> {
        let v = self.vol(key).ok_or_else(|| anyhow!("no volume {key} here"))?;
        account(&v.node, who)?;
        let store = v
            .store
            .as_ref()
            .ok_or_else(|| anyhow!("this node doesn't keep {key}"))?;
        if data.len() as u64 > v.manifest().chunk || blake3::hash(data).to_hex().as_str() != hash {
            bail!("the chunk is not what its hash says");
        }
        let id = u128::from_str_radix(id, 16)?;
        if !store.room() {
            bail!("the disk of {} is nearly full", v.node.node_names(&[v.me]).join(""));
        }
        store.put(id, chunk, data)
    }

    /// A commit, on the node that keeps the file list, for `who` (it needs SSH access here; the
    /// files become its account's, and it may replace and remove only its own). Returns the
    /// new version.
    pub async fn commit(&self, key: &str, who: &Who, mut c: Commit) -> Result<u64> {
        let _one = self.commit_lock.lock().await;
        let v = self.vol(key).ok_or_else(|| anyhow!("no volume {key} here"))?;
        if v.def.keeper() != v.me {
            bail!("this node doesn't keep the file list of {}", v.def.name);
        }
        let (name, creds) = account(&v.node, who)?;
        let mut m = (*v.manifest()).clone();
        let added: HashSet<&str> = c.add.iter().map(|e| e.path.as_str()).collect();
        for f in &m.files {
            let removed = c
                .remove
                .iter()
                .any(|p| f.path == *p || f.path.starts_with(&format!("{p}/")));
            if (removed || added.contains(f.path.as_str())) && !may_change(f, &creds) {
                bail!("{}:{} is not yours ({name}) to replace or remove", v.def.name, f.path);
            }
        }
        for e in &mut c.add {
            e.owner = Some(name.clone());
            e.mode &= 0o777;
        }
        m.apply(&c)?;
        let version = m.version;
        let saved = m.clone();
        let this = self.manifest_path(key);
        tokio::task::spawn_blocking({
            let dir = self.dir.clone();
            move || -> Result<()> {
                crate::config::create_dir(&dir)?;
                let tmp = this.with_extension("tmp");
                std::fs::write(&tmp, serde_json::to_vec(&saved)?)?;
                std::fs::rename(tmp, this)?;
                Ok(())
            }
        })
        .await??;
        let a = self
            .active
            .lock()
            .unwrap()
            .values()
            .find(|a| a.vol.def.key() == key)
            .cloned();
        if let Some(a) = a {
            a.vol.set_manifest(m, a.mount.lock().unwrap().as_ref())?;
        }
        Ok(version)
    }

    pub fn shutdown(&self) {
        let all: Vec<Arc<Active>> = self.active.lock().unwrap().drain().map(|(_, a)| a).collect();
        for a in all {
            a.shutdown();
        }
    }

    // ---------------------------------------------------------------- following the defs

    /// Starts the volumes of this node's groups, follows their file lists, stops the others.
    pub async fn run(node: Arc<Node>) {
        raise_open_files();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut round = 0u64;
        loop {
            node.volumes.reconcile(&node).await;
            node.volumes.follow(&node).await;
            if round.is_multiple_of(100) {
                let all: Vec<Arc<Vol>> = node
                    .volumes
                    .active
                    .lock()
                    .unwrap()
                    .values()
                    .map(|a| a.vol.clone())
                    .collect();
                let _ = tokio::task::spawn_blocking(move || all.iter().for_each(|v| v.collect())).await;
            }
            round += 1;
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    async fn reconcile(&self, node: &Arc<Node>) {
        let me = node.id();
        let defs = node.volume_defs();
        let wanted: HashMap<String, Def> = defs
            .iter()
            .filter(|d| !d.removed && d.nodes.contains(&me) && d.check().is_ok())
            .map(|d| (d.key(), d.clone()))
            .collect();
        let stopping: Vec<Arc<Active>> = {
            let mut active = self.active.lock().unwrap();
            let gone: Vec<String> = active.keys().filter(|k| !wanted.contains_key(*k)).cloned().collect();
            gone.iter().filter_map(|k| active.remove(k)).collect()
        };
        for a in stopping {
            info!("volume {}: stopping here", a.vol.def.name);
            let _ = tokio::task::spawn_blocking(move || a.shutdown()).await;
        }
        // What this node keeps of volumes it is no longer in (or that are gone).
        for d in &defs {
            if !wanted.contains_key(&d.key()) && (d.store_dir().exists() || self.manifest_path(&d.key()).exists()) {
                info!("volume {}: removing this node's copy", d.name);
                let (dir, list) = (d.store_dir(), self.manifest_path(&d.key()));
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = std::fs::remove_dir_all(dir);
                    let _ = std::fs::remove_file(list);
                })
                .await;
            }
        }
        for (key, def) in wanted {
            if self.active.lock().unwrap().contains_key(&key) {
                continue;
            }
            if self
                .failed
                .lock()
                .unwrap()
                .get(&def.name)
                .is_some_and(|(k, at, _)| *k == key && at.elapsed() < Duration::from_secs(10))
            {
                continue;
            }
            match self.start(node, &def).await {
                Ok(a) => {
                    self.failed.lock().unwrap().remove(&def.name);
                    self.active.lock().unwrap().insert(key, a);
                }
                Err(e) => {
                    warn!("volume {}: {e:#}", def.name);
                    self.failed
                        .lock()
                        .unwrap()
                        .insert(def.name.clone(), (key, Instant::now(), format!("{e:#}")));
                }
            }
        }
    }

    /// The nodes that don't keep the file list fetch its new versions.
    async fn follow(&self, node: &Arc<Node>) {
        let following: Vec<Arc<Active>> = self
            .active
            .lock()
            .unwrap()
            .values()
            .filter(|a| a.vol.def.keeper() != a.vol.me)
            .cloned()
            .collect();
        for a in following {
            let v = &a.vol;
            let Ok(m) = self.fetch_manifest(node, &v.def, v.manifest().version, None).await else {
                continue;
            };
            let Some(m) = m else { continue };
            if let Err(e) = self.save_manifest(&m) {
                warn!("volume {}: saving the file list: {e:#}", v.def.name);
            }
            if let Err(e) = v.set_manifest(m, a.mount.lock().unwrap().as_ref()) {
                warn!("volume {}: {e:#}", v.def.name);
            }
        }
    }

    /// The file list from the node that keeps it, if it is newer than `have`.
    async fn fetch_manifest(&self, node: &Node, def: &Def, have: u64, user: Option<&str>) -> Result<Option<Manifest>> {
        let keeper = def.keeper();
        let head = tokio::time::timeout(
            Duration::from_secs(5),
            self.pool.volume_head(node, keeper, &def.key(), user),
        )
        .await??
        .ok_or_else(|| match user {
            // The keeper answers a user only if it could log in there.
            Some(u) => anyhow!(
                "{u} may not use volume {}: that needs SSH access to {} (meshvpn ssh allow there)",
                def.name,
                node.node_names(&[keeper]).join("")
            ),
            None => anyhow!("{} has no file list for it", def.name),
        })?;
        let version = u64::from_be_bytes(head.get(..8).and_then(|b| b.try_into().ok()).unwrap_or_default());
        if version <= have {
            return Ok(None);
        }
        let bytes = tokio::time::timeout(
            Duration::from_secs(120),
            self.pool.volume_manifest(node, keeper, &def.key(), user),
        )
        .await??
        .ok_or_else(|| anyhow!("no file list"))?;
        let m: Manifest = serde_json::from_slice(&bytes)?;
        m.validate()?;
        if m.volume != def.key() {
            bail!("the file list of another volume");
        }
        Ok(Some(m))
    }

    /// The file list to start with: our saved copy, a new one (the node that keeps it: an
    /// empty volume, or the files of the source), or the keeper's.
    async fn first_manifest(&self, node: &Arc<Node>, def: &Def) -> Result<Manifest> {
        if let Some(m) = self.load_manifest(&def.key()) {
            return Ok(m);
        }
        let m = if def.keeper() == node.id() {
            match &def.source {
                Some(src) => {
                    let (src, key) = (PathBuf::from(src), def.key());
                    let (m, skipped) = tokio::task::spawn_blocking(move || scan(&src, &key)).await??;
                    info!(
                        "volume {}: {} files on the storage{}",
                        def.name,
                        m.files.len(),
                        if skipped > 0 {
                            format!(" ({skipped} links and special files left out)")
                        } else {
                            String::new()
                        }
                    );
                    m
                }
                None => Manifest {
                    volume: def.key(),
                    version: 1,
                    chunk: CHUNK,
                    files: vec![],
                },
            }
        } else {
            self.fetch_manifest(node, def, 0, None)
                .await
                .with_context(|| format!("the file list (from {})", node.node_names(&[def.keeper()]).join("")))?
                .ok_or_else(|| anyhow!("no file list yet"))?
        };
        self.save_manifest(&m)?;
        Ok(m)
    }

    async fn start(&self, node: &Arc<Node>, def: &Def) -> Result<Arc<Active>> {
        def.check()?;
        if let Some(src) = &def.source
            && !network_fs(Path::new(src)).with_context(|| format!("the source {src} is not here"))?
        {
            bail!("{src} is not on a network file system on this node");
        }
        let m = self.first_manifest(node, def).await?;
        let tree = fuse::Tree::build(&m.files)?;
        let dir = def.store_dir();
        let store = Arc::new(tokio::task::spawn_blocking(move || Store::open(&dir)).await??);
        let vol = Arc::new(Vol {
            def: def.clone(),
            me: node.id(),
            node: node.clone(),
            rt: tokio::runtime::Handle::current(),
            pool: self.pool.clone(),
            store: Some(store),
            stats: Stats::default(),
            man: RwLock::new(Arc::new(m)),
            open_src: Mutex::new(HashMap::new()),
        });
        let path = def.mount();
        let reader = Arc::new(Reader(vol.clone()));
        let user = crate::config::rootless();
        let mount = tokio::task::spawn_blocking(move || fuse::mount(&path, tree, reader, FUSE_THREADS, user)).await??;
        let stop = Arc::new(AtomicBool::new(false));
        let stager = {
            let (vol, stop) = (vol.clone(), stop.clone());
            std::thread::Builder::new()
                .name(format!("volume-copy-{}", def.name))
                .spawn(move || stage(&vol, &stop))?
        };
        info!(
            "volume {}: mounted at {} ({} files)",
            def.name,
            def.mount().display(),
            vol.manifest().files.len()
        );
        Ok(Arc::new(Active {
            vol,
            stop,
            mount: Mutex::new(Some(mount)),
            stager: Mutex::new(Some(stager)),
        }))
    }

    // ------------------------------------------------------------------- copying in and out

    /// The volume to copy into or out of, as this node can use it: its own (a node of the
    /// volume), or one that reads through the others.
    async fn handle(&self, node: &Arc<Node>, name: &str, user: Option<&str>) -> Result<Arc<Vol>> {
        let def = node
            .volume_defs()
            .into_iter()
            .find(|d| d.name == name && !d.removed)
            .ok_or_else(|| anyhow!("no volume {name} (see meshvpn volume list)"))?;
        if let Some(v) = self.vol(&def.key()) {
            return Ok(v);
        }
        let m = self
            .fetch_manifest(node, &def, 0, user)
            .await
            .with_context(|| format!("the file list of {name}"))?
            .ok_or_else(|| anyhow!("no file list"))?;
        Ok(Arc::new(Vol {
            def,
            me: node.id(),
            node: node.clone(),
            rt: tokio::runtime::Handle::current(),
            pool: self.pool.clone(),
            store: None,
            stats: Stats::default(),
            man: RwLock::new(Arc::new(m)),
            open_src: Mutex::new(HashMap::new()),
        }))
    }

    async fn send_commit(&self, node: &Arc<Node>, v: &Vol, user: Option<&str>, c: Commit) -> Result<u64> {
        if v.def.keeper() == v.me {
            let who = Who {
                node: v.me,
                user: user.map(String::from),
            };
            return self.commit(&v.def.key(), &who, c).await;
        }
        let body = serde_json::to_vec(&c)?;
        let answer = tokio::time::timeout(
            Duration::from_secs(120),
            self.pool.volume_commit(node, v.def.keeper(), &v.def.key(), user, &body),
        )
        .await??
        .ok_or_else(|| anyhow!("{} refused the files", node.node_names(&[v.def.keeper()]).join("")))?;
        let r: serde_json::Value = serde_json::from_slice(&answer)?;
        match (r["version"].as_u64(), r["error"].as_str()) {
            (Some(n), _) => Ok(n),
            (_, Some(e)) => bail!("{e}"),
            _ => bail!("no answer"),
        }
    }

    /// `meshvpn volume cp LOCAL... NAME:DIR`: every file into the volume (under DIR, with its
    /// name; directories with what is in them), for `user` (its files are read with `creds`).
    pub async fn upload(
        &self,
        node: &Arc<Node>,
        name: &str,
        dir: &str,
        local: Vec<PathBuf>,
        user: Option<String>,
        creds: Option<Creds>,
    ) -> Result<serde_json::Value> {
        let v = self.handle(node, name, user.as_deref()).await?;
        let dir = dir.trim_matches('/').to_string();
        if !dir.is_empty() && !valid_path(&dir) {
            bail!("bad path {dir:?} in the volume");
        }
        // (local file, path in the volume)
        let files = tokio::task::spawn_blocking({
            let (dir, creds) = (dir.clone(), creds.clone());
            move || -> Result<Vec<(PathBuf, String)>> {
                with_creds(creds.as_ref(), || -> Result<Vec<(PathBuf, String)>> {
                    let mut out = vec![];
                    for p in &local {
                        let base = p
                            .file_name()
                            .and_then(|n| n.to_str())
                            .ok_or_else(|| anyhow!("{}: no usable name", p.display()))?;
                        let target = if dir.is_empty() {
                            base.to_string()
                        } else {
                            format!("{dir}/{base}")
                        };
                        let m = std::fs::metadata(p).with_context(|| p.display().to_string())?;
                        if m.is_dir() {
                            let (list, _) = scan(p, "")?;
                            out.extend(
                                list.files
                                    .into_iter()
                                    .map(|e| (p.join(&e.path), format!("{target}/{}", e.path))),
                            );
                        } else {
                            out.push((p.clone(), target));
                        }
                    }
                    Ok(out)
                })
            }
        })
        .await??;
        let started = Instant::now();
        let chunk = v.manifest().chunk;
        let bytes = Arc::new(AtomicU64::new(0));
        let sem = Arc::new(tokio::sync::Semaphore::new(8));
        let mut set = tokio::task::JoinSet::new();
        for (local, path) in files {
            let (v, sem, bytes) = (v.clone(), sem.clone(), bytes.clone());
            let (this, user, creds) = (node.clone(), user.clone(), creds.clone());
            set.spawn(async move {
                let _p = sem.acquire_owned().await;
                upload_file(&this, &v, &local, path, chunk, &bytes, user.as_deref(), creds).await
            });
        }
        let mut add = vec![];
        let mut version = 0;
        let mut count = 0;
        while let Some(r) = set.join_next().await {
            add.push(r??);
            count += 1;
            if add.len() >= COMMIT_FILES {
                let c = Commit {
                    add: std::mem::take(&mut add),
                    remove: vec![],
                };
                version = self.send_commit(node, &v, user.as_deref(), c).await?;
            }
        }
        if !add.is_empty() {
            version = self
                .send_commit(node, &v, user.as_deref(), Commit { add, remove: vec![] })
                .await?;
        }
        let secs = started.elapsed().as_secs_f64();
        let b = bytes.load(Relaxed);
        Ok(serde_json::json!({
            "volume": name, "files": count, "bytes": b, "seconds": secs,
            "mb_s": b as f64 / secs.max(1e-6) / 1e6, "version": version,
        }))
    }

    /// `meshvpn volume rm NAME:PATH...`.
    pub async fn remove(&self, node: &Arc<Node>, name: &str, paths: Vec<String>, user: Option<String>) -> Result<u64> {
        let v = self.handle(node, name, user.as_deref()).await?;
        let paths: Vec<String> = paths.iter().map(|p| p.trim_matches('/').to_string()).collect();
        let m = v.manifest();
        for p in &paths {
            let dir = format!("{p}/");
            if !valid_path(p) || !m.files.iter().any(|f| f.path == *p || f.path.starts_with(&dir)) {
                bail!("{name}:{p} is not there");
            }
        }
        self.send_commit(
            node,
            &v,
            user.as_deref(),
            Commit {
                add: vec![],
                remove: paths,
            },
        )
        .await
    }

    /// `meshvpn volume cp NAME:PATH LOCAL`: a file or directory of the volume into the local
    /// directory `dest`, for `user`: only what it may read; the files are made with `creds`.
    pub async fn download(
        &self,
        node: &Arc<Node>,
        name: &str,
        path: &str,
        dest: PathBuf,
        user: Option<String>,
        creds: Option<Creds>,
    ) -> Result<serde_json::Value> {
        let v = self.handle(node, name, user.as_deref()).await?;
        let path = path.trim_matches('/').to_string();
        let m = v.manifest();
        let dir = format!("{path}/");
        let base = path.rsplit('/').next().unwrap_or("").to_string();
        // (entry, path below dest)
        let picked: Vec<(Entry, String)> = m
            .files
            .iter()
            .filter_map(|f| {
                if path.is_empty() {
                    Some((f.clone(), f.path.clone()))
                } else if f.path == path {
                    Some((f.clone(), base.clone()))
                } else {
                    f.path
                        .strip_prefix(&dir)
                        .map(|rest| (f.clone(), format!("{base}/{rest}")))
                }
            })
            .collect();
        if picked.is_empty() {
            bail!("{name}:{path} is not there");
        }
        // What the user may read, as the mount would let it (the nodes check it again).
        let reader = match &creds {
            Some(c) => c.clone(),
            None => creds_of(user.as_deref().unwrap_or("root")).unwrap_or(Creds {
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
                groups: vec![],
            }),
        };
        if let Some((e, _)) = picked.iter().find(|(e, _)| !may_read(e, &reader)) {
            bail!("{name}:{}: permission denied", e.path);
        }
        let started = Instant::now();
        let v2 = v.clone();
        let vname = name.to_string();
        let (count, bytes) = tokio::task::spawn_blocking(move || -> Result<(usize, u64)> {
            with_creds(creds.as_ref(), || -> Result<(usize, u64)> {
                std::fs::create_dir_all(&dest).with_context(|| dest.display().to_string())?;
                let dest = dest.canonicalize()?;
                let mut created = vec![];
                let mut bytes = 0;
                for (e, rel) in &picked {
                    let target = crate::share::inside(&dest, rel, &mut created)?;
                    let mut o = std::fs::OpenOptions::new();
                    o.write(true)
                        .create(true)
                        .truncate(true)
                        .custom_flags(libc::O_NOFOLLOW)
                        .mode(0o644);
                    let file = o.open(&target).with_context(|| target.display().to_string())?;
                    let mut off = 0;
                    while off < e.size {
                        let want = (e.size - off).min(4 << 20) as u32;
                        let data = v2.read_entry(e, off, want, user.as_deref()).map_err(|errno| {
                            anyhow!("{vname}:{}: {}", e.path, std::io::Error::from_raw_os_error(errno))
                        })?;
                        if data.is_empty() {
                            break;
                        }
                        file.write_all_at(&data, off)?;
                        off += data.len() as u64;
                    }
                    bytes += e.size;
                }
                Ok((picked.len(), bytes))
            })
        })
        .await??;
        let secs = started.elapsed().as_secs_f64();
        Ok(serde_json::json!({
            "volume": name, "files": count, "bytes": bytes, "seconds": secs,
            "mb_s": bytes as f64 / secs.max(1e-6) / 1e6,
        }))
    }

    /// `meshvpn volume list`: every volume, and how this node is doing with its own.
    pub fn status(&self, node: &Node) -> serde_json::Value {
        let defs = node.volume_defs();
        let active = self.active.lock().unwrap();
        let failed = self.failed.lock().unwrap();
        let list: Vec<serde_json::Value> = defs
            .iter()
            .filter(|d| !d.removed)
            .map(|d| {
                let here = active.get(&d.key()).map(|a| {
                    let (v, s) = (&a.vol, &a.vol.stats);
                    let m = v.manifest();
                    serde_json::json!({
                        "mounted": a.mount.lock().unwrap().is_some(),
                        "version": m.version,
                        "files": m.files.len(),
                        "bytes": m.files.iter().map(|f| f.size).sum::<u64>(),
                        "stored_bytes": v.store.as_ref().map_or(0, |s| s.bytes()),
                        "owned_bytes": s.owned_bytes.load(Relaxed),
                        "staged_bytes": s.staged_bytes.load(Relaxed),
                        "staged": s.done.load(Relaxed),
                        "stage_secs": s.stage_secs.load(Relaxed),
                        "failed_files": s.failed_files.load(Relaxed),
                        "read_local_bytes": s.local_bytes.load(Relaxed),
                        "read_remote_bytes": s.remote_bytes.load(Relaxed),
                        "read_source_bytes": s.source_bytes.load(Relaxed),
                        "errors": s.errors.load(Relaxed),
                        "note": s.note.lock().unwrap().clone(),
                    })
                });
                serde_json::json!({
                    "name": d.name,
                    "source": d.source,
                    "copies": d.copies,
                    "mount": d.mount(),
                    "nodes": node.node_names(&d.nodes),
                    "member": d.nodes.contains(&node.id()),
                    "here": here,
                    "error": failed.get(&d.name).filter(|(k, _, _)| *k == d.key()).map(|(_, _, e)| e.clone()),
                })
            })
            .collect();
        serde_json::json!({ "volumes": list })
    }
}

/// One file into the volume: each chunk to the nodes that keep it. The entry for the commit.
#[allow(clippy::too_many_arguments)]
async fn upload_file(
    node: &Arc<Node>,
    v: &Vol,
    local: &Path,
    path: String,
    chunk: u64,
    bytes: &AtomicU64,
    user: Option<&str>,
    creds: Option<Creds>,
) -> Result<Entry> {
    if !valid_path(&path) {
        bail!("bad path {path:?}");
    }
    // Opened with the user's rights: what it can't read, it can't copy in.
    let opened = local.to_path_buf();
    let file = Arc::new(
        tokio::task::spawn_blocking(move || {
            with_creds(creds.as_ref(), || {
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&opened)
            })
        })
        .await?
        .with_context(|| local.display().to_string())?,
    );
    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("{} is not a regular file", local.display());
    }
    let id = new_id();
    let id128 = u128::from_str_radix(&id, 16)?;
    let size = meta.len();
    let mut hashes = vec![];
    for c in 0..size.div_ceil(chunk) {
        let len = size.saturating_sub(c * chunk).min(chunk) as usize;
        let f = file.clone();
        let data = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            let mut buf = vec![0u8; len];
            f.read_exact_at(&mut buf, c * chunk)?;
            Ok(buf)
        })
        .await??;
        let hash = blake3::hash(&data).to_hex().to_string();
        let mut stored = 0;
        let mut why = String::new();
        for k in keepers(&v.def.nodes, id128, c, v.def.copies as usize) {
            let r = if k == v.me {
                let who = Who {
                    node: v.me,
                    user: user.map(String::from),
                };
                node.volumes.put(&v.def.key(), &who, &id, c as u32, &hash, &data)
            } else {
                match tokio::time::timeout(
                    Duration::from_secs(60),
                    v.pool
                        .volume_put(node, k, &v.def.key(), user, &id, c as u32, &hash, &data),
                )
                .await
                {
                    Ok(Ok(Some(_))) => Ok(()),
                    Ok(Ok(None)) => Err(anyhow!("refused (SSH access there, room on its disk?)")),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(anyhow!("timed out")),
                }
            };
            match r {
                Ok(()) => stored += 1,
                Err(e) => why = format!("{}: {e:#}", node.node_names(&[k]).join("")),
            }
        }
        // One copy is enough to go on (the others are missing until it is copied again).
        if stored == 0 {
            bail!("{}: no node took chunk {c} ({why})", local.display());
        }
        if stored < v.def.copies {
            warn!(
                "volume {}: {path}: chunk {c} in {stored} of {} copies ({why})",
                v.def.name, v.def.copies
            );
        }
        bytes.fetch_add(len as u64, Relaxed);
        hashes.push(hash);
    }
    Ok(Entry {
        path,
        id,
        size,
        mtime_ns: mtime_ns(&meta),
        mode: meta.mode() & 0o777,
        uid: 0,
        gid: 0,
        // The node that keeps the list sets it (whose the file is isn't the sender's to say).
        owner: None,
        src: false,
        hashes,
    })
}

/// A node serving many files (and FUSE) needs more descriptors than the usual 1024.
fn raise_open_files() {
    // SAFETY: zeroed is a valid rlimit; the results are checked.
    unsafe {
        let mut r: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) == 0 && r.rlim_cur < r.rlim_max {
            r.rlim_cur = r.rlim_max.min(1 << 20);
            libc::setrlimit(libc::RLIMIT_NOFILE, &r);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        crate::keys::Key32([b; 32])
    }

    #[test]
    fn chunks_spread_evenly_and_stay_put() {
        let three = [id(1), id(2), id(3)];
        let mut count: HashMap<NodeId, usize> = HashMap::new();
        for c in 0..3000 {
            *count.entry(keepers(&three, 42, c, 1)[0]).or_default() += 1;
        }
        assert!(count.values().all(|n| (850..1150).contains(n)), "{count:?}");
        // A fourth node takes about a quarter, only from the others: nothing moves between them.
        let four = [id(1), id(2), id(3), id(4)];
        let mut moved = 0;
        for c in 0..3000 {
            let (a, b) = (keepers(&three, 7, c, 1)[0], keepers(&four, 7, c, 1)[0]);
            if a != b {
                assert_eq!(b, id(4));
                moved += 1;
            }
        }
        assert!((600..900).contains(&moved), "{moved}");
        // Two copies: on two different nodes, the first as with one.
        for c in 0..100 {
            let two = keepers(&three, 9, c, 2);
            assert!(two.len() == 2 && two[0] != two[1] && two[0] == keepers(&three, 9, c, 1)[0]);
        }
    }

    #[test]
    fn store_keeps_chunks_across_restarts() {
        let dir = std::env::temp_dir().join(format!("meshvpn-vol-{}", rand::random::<u64>()));
        {
            let s = Store::open(&dir).unwrap();
            s.put(3, 0, b"hello").unwrap();
            s.put(3, 1, b"world!").unwrap();
            assert_eq!(s.read(3, 1, 1, 4).unwrap().unwrap(), b"orld");
            assert!(s.read(3, 1, 4, 4).unwrap().is_err());
        }
        // A temporary file of a crash is cleaned away.
        std::fs::write(dir.join(format!("{:032x}", 3u128)).join(".2.123"), b"half").unwrap();
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.read(3, 0, 0, 5).unwrap().unwrap(), b"hello");
        assert!(s.has(3, 1) && !s.has(3, 2) && !s.has(4, 0));
        // Fresh chunks of files the list doesn't have stay (an upload may commit them yet).
        assert_eq!(s.collect(&HashSet::new()), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn entry(p: &str, size: u64) -> Entry {
        Entry {
            path: p.into(),
            id: new_id(),
            size,
            mtime_ns: 0,
            mode: 0o644,
            uid: 0,
            gid: 0,
            owner: None,
            src: false,
            hashes: vec!["00".repeat(32); size.div_ceil(CHUNK) as usize],
        }
    }

    #[test]
    fn rights_as_the_kernel_has_them() {
        let mut e = entry("f", 1);
        (e.uid, e.gid, e.mode) = (1000, 100, 0o640);
        let who = |uid, gid, groups: &[u32]| Creds {
            uid,
            gid,
            groups: groups.to_vec(),
        };
        assert!(may_read(&e, &who(1000, 1000, &[])), "owner");
        assert!(may_read(&e, &who(1001, 5, &[100])), "group");
        assert!(!may_read(&e, &who(1001, 5, &[6])), "others");
        assert!(may_read(&e, &who(0, 0, &[])), "root");
        e.mode = 0o604;
        assert!(
            !may_read(&e, &who(1001, 100, &[])),
            "group bits count for the group, not others'"
        );
        assert!(may_read(&e, &who(1002, 7, &[])));
        assert!(may_change(&e, &who(1000, 1, &[])) && may_change(&e, &who(0, 0, &[])));
        assert!(!may_change(&e, &who(1001, 100, &[100])));
        // An owner by name that this machine doesn't have: nobody's.
        e.owner = Some("no-such-account-here".into());
        assert_eq!(owner_ids(&e), (65534, 65534));
        assert!(!may_change(&e, &who(1000, 100, &[])));
    }

    #[test]
    fn commits() {
        let mut m = Manifest {
            volume: "v-1".into(),
            version: 1,
            chunk: CHUNK,
            files: vec![],
        };
        m.apply(&Commit {
            add: vec![entry("a/b.bin", 10), entry("a/c.bin", CHUNK + 1), entry("d.bin", 0)],
            remove: vec![],
        })
        .unwrap();
        assert_eq!(m.version, 2);
        // A file replaced keeps its path, with a new id.
        let again = entry("a/b.bin", 20);
        m.apply(&Commit {
            add: vec![again.clone()],
            remove: vec![],
        })
        .unwrap();
        assert_eq!(m.files.len(), 3);
        assert!(m.files.contains(&again));
        // A file where a directory is: refused, nothing changes.
        assert!(
            m.apply(&Commit {
                add: vec![entry("a", 1)],
                remove: vec![]
            })
            .is_err()
        );
        assert_eq!((m.version, m.files.len()), (3, 3));
        // A directory removed with what is in it.
        m.apply(&Commit {
            add: vec![],
            remove: vec!["a".into()],
        })
        .unwrap();
        assert_eq!(m.files.len(), 1);
        // Paths that lead out, and chunk lists that don't fit.
        let mut bad = entry("x", 10);
        bad.path = "../etc/passwd".into();
        assert!(
            m.apply(&Commit {
                add: vec![bad],
                remove: vec![]
            })
            .is_err()
        );
        let mut bad = entry("x", 10);
        bad.hashes.clear();
        assert!(
            m.apply(&Commit {
                add: vec![bad],
                remove: vec![]
            })
            .is_err()
        );
        assert!(fuse::Tree::build(&m.files).is_ok());
    }
}
