//! A read-only file system in the kernel's FUSE protocol (`/dev/fuse`), for the volumes: the
//! tree is in memory and is replaced when the volume changes; file data comes from a `Source`.
//!
//! As root the daemon mounts with mount(2) itself; without root through `fusermount3` (the
//! setuid helper of the fuse3 package), which hands back the descriptor. Several threads read
//! requests from the same descriptor; the kernel gives each request to one of them.
//!
//! Inode numbers are hashes of the path (and, for files, of the file's id), so they stay the
//! same across versions of the tree, and a file that was replaced gets a new one (the kernel
//! must not answer from the old file's pages). Names and attributes are valid for a second: a
//! change on another node shows up that quickly. An open file keeps reading the version it
//! opened.

use super::Entry;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, HashMap};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use tracing::warn;

/// Where file data comes from.
pub trait Source: Send + Sync {
    /// `size` bytes of `file` from `off`, fewer at its end; Err is an errno.
    fn read(&self, file: &Entry, off: u64, size: u32) -> Result<Vec<u8>, i32>;
}

/// The file tree of one version of a volume.
pub struct Tree {
    nodes: HashMap<u64, TNode>,
    files: u64,
    bytes: u64,
}

struct TNode {
    parent: u64,
    mtime_ns: i64,
    kind: Kind,
}

enum Kind {
    /// Entries sorted by name.
    Dir(Vec<(String, u64)>),
    File(Arc<Entry>),
}

const ROOT: u64 = 1;

fn ino(path: &str, id: Option<&str>) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(path.as_bytes());
    if let Some(id) = id {
        h.update(b"\0");
        h.update(id.as_bytes());
    }
    u64::from_le_bytes(h.finalize().as_bytes()[..8].try_into().unwrap()).max(ROOT + 1)
}

impl Tree {
    pub fn build(files: &[Entry]) -> Result<Tree> {
        let mut nodes: HashMap<u64, TNode> = HashMap::new();
        let mut children: HashMap<u64, BTreeMap<String, u64>> = HashMap::new();
        nodes.insert(
            ROOT,
            TNode {
                parent: ROOT,
                mtime_ns: 0,
                kind: Kind::Dir(vec![]),
            },
        );
        children.insert(ROOT, BTreeMap::new());
        let mut bytes = 0;
        for f in files {
            let parts: Vec<&str> = f.path.split('/').collect();
            let mut cur = ROOT;
            let mut at = 0;
            for (i, part) in parts.iter().enumerate() {
                at += part.len() + usize::from(i > 0);
                let last = i + 1 == parts.len();
                let dir = children
                    .get_mut(&cur)
                    .with_context(|| format!("{}: a file is used as a directory", f.path))?;
                if let Some(&child) = dir.get(*part) {
                    if last {
                        bail!("{} is in the list twice (or also a directory)", f.path);
                    }
                    cur = child;
                    continue;
                }
                let n = if last {
                    ino(&f.path, Some(&f.id))
                } else {
                    ino(&f.path[..at], None)
                };
                dir.insert(part.to_string(), n);
                if nodes.contains_key(&n) {
                    bail!("inode number clash at {}", f.path);
                }
                if last {
                    bytes += f.size;
                    nodes.insert(
                        n,
                        TNode {
                            parent: cur,
                            mtime_ns: f.mtime_ns,
                            kind: Kind::File(Arc::new(f.clone())),
                        },
                    );
                } else {
                    nodes.insert(
                        n,
                        TNode {
                            parent: cur,
                            mtime_ns: f.mtime_ns,
                            kind: Kind::Dir(vec![]),
                        },
                    );
                    children.insert(n, BTreeMap::new());
                }
                cur = n;
            }
        }
        for (d, c) in children {
            if let Some(n) = nodes.get_mut(&d) {
                n.kind = Kind::Dir(c.into_iter().collect());
            }
        }
        Ok(Tree {
            nodes,
            files: files.len() as u64,
            bytes,
        })
    }

    fn lookup(&self, parent: u64, name: &[u8]) -> Option<u64> {
        let Kind::Dir(entries) = &self.nodes.get(&parent)?.kind else {
            return None;
        };
        let name = std::str::from_utf8(name).ok()?;
        entries
            .binary_search_by(|(n, _)| n.as_str().cmp(name))
            .ok()
            .map(|i| entries[i].1)
    }
}

// ------------------------------------------------------------------------------- the protocol

const FUSE_LOOKUP: u32 = 1;
const FUSE_FORGET: u32 = 2;
const FUSE_GETATTR: u32 = 3;
const FUSE_OPEN: u32 = 14;
const FUSE_READ: u32 = 15;
const FUSE_STATFS: u32 = 17;
const FUSE_RELEASE: u32 = 18;
const FUSE_FSYNC: u32 = 20;
const FUSE_FLUSH: u32 = 25;
const FUSE_INIT: u32 = 26;
const FUSE_OPENDIR: u32 = 27;
const FUSE_READDIR: u32 = 28;
const FUSE_RELEASEDIR: u32 = 29;
const FUSE_FSYNCDIR: u32 = 30;
const FUSE_INTERRUPT: u32 = 36;
const FUSE_DESTROY: u32 = 38;
const FUSE_BATCH_FORGET: u32 = 42;
/// Everything that would change something.
const WRITES: &[u32] = &[4, 6, 8, 9, 10, 11, 12, 13, 16, 21, 24, 35, 43, 45, 47];

const FUSE_ASYNC_READ: u32 = 1 << 0;
const FUSE_PARALLEL_DIROPS: u32 = 1 << 18;
const FUSE_MAX_PAGES: u32 = 1 << 22;
const FOPEN_KEEP_CACHE: u32 = 1 << 1;

/// The protocol version this side speaks (7.31: Linux 5.4 and later).
const MINOR: u32 = 31;
/// Largest read the kernel sends (FUSE_MAX_PAGES pages of 4 kB).
const MAX_PAGES: u16 = 256;
/// How long the kernel may keep names and attributes.
const VALID_SECS: u64 = 1;
const IN_HEADER: usize = 40;

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .map_or(0, |s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap()))
}

struct Out(Vec<u8>);

impl Out {
    fn new() -> Self {
        Out(Vec::with_capacity(128))
    }
    fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn zeros(mut self, n: usize) -> Self {
        self.0.resize(self.0.len() + n, 0);
        self
    }
}

/// `struct fuse_attr` (88 bytes). A file has its owner and mode (the kernel checks them:
/// `default_permissions`); directories are everyone's to read.
fn attr(out: Out, ino: u64, n: &TNode) -> Out {
    let (size, mode, nlink, uid, gid) = match &n.kind {
        Kind::Dir(_) => (0, libc::S_IFDIR | 0o755, 2, 0, 0),
        Kind::File(e) => {
            let (uid, gid) = super::owner_ids(e);
            (e.size, libc::S_IFREG | (e.mode & 0o777), 1, uid, gid)
        }
    };
    let secs = n.mtime_ns.div_euclid(1_000_000_000) as u64;
    let nsec = n.mtime_ns.rem_euclid(1_000_000_000) as u32;
    out.u64(ino)
        .u64(size)
        .u64(size.div_ceil(512))
        .u64(secs)
        .u64(secs)
        .u64(secs)
        .u32(nsec)
        .u32(nsec)
        .u32(nsec)
        .u32(mode)
        .u32(nlink)
        .u32(uid)
        .u32(gid)
        .u32(0) // rdev
        .u32(128 * 1024) // blksize: what programs take as a good read size
        .u32(0) // flags
}

/// `struct fuse_entry_out`; `ino` 0 is a name that isn't there (the kernel keeps that too).
fn entry(tree: &Tree, ino: u64) -> Vec<u8> {
    let o = Out::new()
        .u64(ino)
        .u64(1) // generation
        .u64(VALID_SECS)
        .u64(VALID_SECS)
        .u32(0)
        .u32(0);
    match tree.nodes.get(&ino) {
        Some(n) => attr(o, ino, n).0,
        None => o.zeros(88).0,
    }
}

/// What the answering threads share.
struct Fs {
    tree: RwLock<Arc<Tree>>,
    /// Open files: the version each was opened in.
    handles: Mutex<HashMap<u64, Arc<Entry>>>,
    next_fh: AtomicU64,
    src: Arc<dyn Source>,
}

pub struct Mount {
    path: PathBuf,
    fs: Arc<Fs>,
    user: bool,
    /// Open while mounted (the threads have it too).
    _fd: Arc<OwnedFd>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Mount {
    /// The volume changed: the new tree answers from now on.
    pub fn update(&self, tree: Tree) {
        *self.fs.tree.write().unwrap() = Arc::new(tree);
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        unmount(&self.path, self.user);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn cpath(p: &Path) -> Result<CString> {
    Ok(CString::new(p.as_os_str().as_encoded_bytes())?)
}

fn mounted(path: &Path) -> bool {
    std::fs::read_to_string("/proc/self/mounts").is_ok_and(|m| {
        m.lines().any(|l| {
            let mut f = l.split(' ');
            let (_, at, kind) = (f.next(), f.next(), f.next());
            at == Some(&*path.to_string_lossy()) && kind == Some("fuse.meshvpn")
        })
    })
}

/// Unmounts our file systems at `path` (also those of a daemon that ended without doing it:
/// their mount point only answers "not connected").
pub fn unmount(path: &Path, user: bool) {
    for _ in 0..8 {
        if !mounted(path) {
            return;
        }
        if user {
            for prog in ["fusermount3", "fusermount"] {
                if std::process::Command::new(prog)
                    .args(["-u", "-z", "--"])
                    .arg(path)
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success())
                {
                    break;
                }
            }
        } else if let Ok(c) = cpath(path) {
            // SAFETY: a valid C string.
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        }
    }
}

/// Mounts `tree` at `path` (made if missing), read-only, with `threads` threads answering.
/// `user`: without root, through fusermount3.
pub fn mount(path: &Path, tree: Tree, src: Arc<dyn Source>, threads: usize, user: bool) -> Result<Mount> {
    unmount(path, user);
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    let fd = Arc::new(if user { mount_user(path)? } else { mount_root(path)? });
    let fs = Arc::new(Fs {
        tree: RwLock::new(Arc::new(tree)),
        handles: Mutex::new(HashMap::new()),
        next_fh: AtomicU64::new(1),
        src,
    });
    let mut handles = vec![];
    for i in 0..threads.max(1) {
        let (fd, fs) = (fd.clone(), fs.clone());
        handles.push(
            std::thread::Builder::new()
                .name(format!("volume-fuse-{i}"))
                .spawn(move || serve(&fd, &fs))?,
        );
    }
    if !user {
        raise_readahead(path);
    }
    Ok(Mount {
        path: path.to_path_buf(),
        fs,
        user,
        _fd: fd,
        threads: handles,
    })
}

fn mount_root(path: &Path) -> Result<OwnedFd> {
    // SAFETY: a valid C string; the result is checked.
    let raw = unsafe { libc::open(c"/dev/fuse".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if raw < 0 {
        bail!("opening /dev/fuse: {}", std::io::Error::last_os_error());
    }
    // SAFETY: just opened, owned from here on.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let opts = CString::new(format!(
        "fd={raw},rootmode=40000,user_id=0,group_id=0,allow_other,default_permissions"
    ))?;
    let target = cpath(path)?;
    // SAFETY: valid C strings; the result is checked.
    let r = unsafe {
        libc::mount(
            c"meshvpn".as_ptr(),
            target.as_ptr(),
            c"fuse.meshvpn".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_RDONLY,
            opts.as_ptr().cast(),
        )
    };
    if r != 0 {
        bail!(
            "mounting at {}: {} (in a container: needs SYS_ADMIN and /dev/fuse)",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(fd)
}

/// Without root: fusermount3 mounts and sends the descriptor back over a socket
/// (`_FUSE_COMMFD`), as libfuse does it.
fn mount_user(path: &Path) -> Result<OwnedFd> {
    let mut sv = [0i32; 2];
    // SAFETY: sv has room for two descriptors; the result is checked.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        bail!("socketpair: {}", std::io::Error::last_os_error());
    }
    // SAFETY: just made, owned from here on.
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };
    // Others may read the mount only if the machine allows it (user_allow_other).
    let others =
        std::fs::read_to_string("/etc/fuse.conf").is_ok_and(|c| c.lines().any(|l| l.trim() == "user_allow_other"));
    let opts = format!(
        "ro,nosuid,nodev,default_permissions,fsname=meshvpn,subtype=meshvpn{}",
        if others { ",allow_other" } else { "" }
    );
    let theirs_raw = theirs.as_raw_fd();
    let mut last = None;
    for prog in ["fusermount3", "fusermount"] {
        let mut cmd = std::process::Command::new(prog);
        cmd.args(["-o", &opts, "--"])
            .arg(path)
            .env("_FUSE_COMMFD", theirs_raw.to_string());
        // SAFETY: only fcntl between fork and exec: the helper inherits its end.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut cmd, move || {
                libc::fcntl(theirs_raw, libc::F_SETFD, 0);
                Ok(())
            });
        }
        match cmd.output() {
            Ok(o) if o.status.success() => {
                drop(theirs);
                return receive_fd(&ours);
            }
            Ok(o) => last = Some(String::from_utf8_lossy(&o.stderr).trim().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => last = Some(e.to_string()),
        }
    }
    bail!(
        "mounting at {} without root: {}",
        path.display(),
        last.unwrap_or_else(|| "fusermount3 is missing (package fuse3)".into())
    )
}

fn receive_fd(sock: &OwnedFd) -> Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cbuf = [0u64; 8];
    // SAFETY: zeroed is a valid msghdr; every pointer set below outlives the call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
    // SAFETY: as above; the result and the control message are checked.
    unsafe {
        if libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) < 0 {
            bail!("receiving the FUSE descriptor: {}", std::io::Error::last_os_error());
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null() || (*c).cmsg_level != libc::SOL_SOCKET || (*c).cmsg_type != libc::SCM_RIGHTS {
            bail!("fusermount sent no descriptor");
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const i32);
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// The kernel reads ahead 128 kB on a FUSE mount by default: far too little for files that
/// come over the network. Best effort (needs root; in a container /sys is read-only).
fn raise_readahead(path: &Path) {
    use std::os::unix::fs::MetadataExt;
    for _ in 0..20 {
        if let Ok(m) = std::fs::metadata(path) {
            let dev = m.dev();
            let (major, minor) = (libc::major(dev), libc::minor(dev));
            let _ = std::fs::write(format!("/sys/class/bdi/{major}:{minor}/read_ahead_kb"), "4096");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn serve(fd: &OwnedFd, fs: &Fs) {
    let raw = fd.as_raw_fd();
    // At least what the kernel asks for (max_write plus headers).
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        // SAFETY: the buffer is valid for its length.
        let n = unsafe { libc::read(raw, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                // Interrupted, or a request taken back before we read it.
                Some(libc::EINTR | libc::EAGAIN | libc::ENOENT) => continue,
                // Unmounted (ENODEV) or broken: done.
                _ => return,
            }
        }
        let req = &buf[..n as usize];
        if req.len() < IN_HEADER {
            continue;
        }
        let opcode = u32_at(req, 4);
        let unique = u64_at(req, 8);
        let ino = u64_at(req, 16);
        let body = &req[IN_HEADER..];
        // A bug must not leave the program that reads waiting for good (nor end this thread).
        let reply = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle(fs, opcode, ino, body)))
            .unwrap_or(Some(Err(libc::EIO)));
        if let Some(r) = reply {
            send(raw, unique, r);
        }
    }
}

fn handle(fs: &Fs, opcode: u32, ino: u64, body: &[u8]) -> Option<Result<Vec<u8>, i32>> {
    let tree = fs.tree.read().unwrap().clone();
    Some(match opcode {
        FUSE_INIT => Ok(init(body)),
        FUSE_FORGET | FUSE_BATCH_FORGET | FUSE_INTERRUPT => return None,
        FUSE_LOOKUP => {
            let name = body.split(|b| *b == 0).next().unwrap_or(&[]);
            match tree.nodes.get(&ino) {
                Some(_) => Ok(entry(&tree, tree.lookup(ino, name).unwrap_or(0))),
                None => Err(libc::ENOENT),
            }
        }
        FUSE_GETATTR => match tree.nodes.get(&ino) {
            Some(n) => Ok(attr(Out::new().u64(VALID_SECS).u32(0).u32(0), ino, n).0),
            // A file replaced since it was opened.
            None => match fs.handles.lock().unwrap().get(&u64_at(body, 8)) {
                Some(e) => Ok(attr(
                    Out::new().u64(VALID_SECS).u32(0).u32(0),
                    ino,
                    &TNode {
                        parent: ROOT,
                        mtime_ns: e.mtime_ns,
                        kind: Kind::File(e.clone()),
                    },
                )
                .0),
                None => Err(libc::ENOENT),
            },
        },
        FUSE_OPEN => match tree.nodes.get(&ino).map(|n| &n.kind) {
            Some(Kind::File(e)) if u32_at(body, 0) as i32 & libc::O_ACCMODE == libc::O_RDONLY => {
                let fh = fs.next_fh.fetch_add(1, Relaxed);
                fs.handles.lock().unwrap().insert(fh, e.clone());
                Ok(Out::new().u64(fh).u32(FOPEN_KEEP_CACHE).u32(0).0)
            }
            Some(Kind::File(_)) => Err(libc::EROFS),
            Some(Kind::Dir(_)) => Err(libc::EISDIR),
            None => Err(libc::ENOENT),
        },
        FUSE_READ => {
            let e = fs.handles.lock().unwrap().get(&u64_at(body, 0)).cloned();
            match e {
                Some(e) => fs.src.read(&e, u64_at(body, 8), u32_at(body, 16)),
                None => Err(libc::EBADF),
            }
        }
        FUSE_RELEASE => {
            fs.handles.lock().unwrap().remove(&u64_at(body, 0));
            Ok(vec![])
        }
        FUSE_OPENDIR => match tree.nodes.get(&ino).map(|n| &n.kind) {
            Some(Kind::Dir(_)) => Ok(Out::new().u64(0).u32(0).u32(0).0),
            _ => Err(libc::ENOTDIR),
        },
        FUSE_READDIR => readdir(&tree, ino, u64_at(body, 8), u32_at(body, 16)),
        FUSE_STATFS => Ok(Out::new()
            .u64(tree.bytes.div_ceil(4096))
            .u64(0)
            .u64(0)
            .u64(tree.files)
            .u64(0)
            .u32(4096)
            .u32(255)
            .u32(4096)
            .u32(0)
            .zeros(24)
            .0),
        FUSE_RELEASEDIR | FUSE_FLUSH | FUSE_FSYNC | FUSE_FSYNCDIR | FUSE_DESTROY => Ok(vec![]),
        op if WRITES.contains(&op) => Err(libc::EROFS),
        _ => Err(libc::ENOSYS),
    })
}

fn send(fd: i32, unique: u64, r: Result<Vec<u8>, i32>) {
    let (error, data) = match r {
        Ok(d) => (0i32, d),
        Err(e) => (-e, vec![]),
    };
    let header = Out::new().u32((16 + data.len()) as u32).u32(error as u32).u64(unique).0;
    let iov = [
        libc::iovec {
            iov_base: header.as_ptr() as *mut _,
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: data.as_ptr() as *mut _,
            iov_len: data.len(),
        },
    ];
    // SAFETY: both buffers outlive the call. ENOENT (the request was interrupted) is fine.
    unsafe { libc::writev(fd, iov.as_ptr(), 2) };
}

fn init(body: &[u8]) -> Vec<u8> {
    let (major, minor) = (u32_at(body, 0), u32_at(body, 4));
    let readahead = u32_at(body, 8);
    let flags = u32_at(body, 12);
    let want = FUSE_ASYNC_READ | FUSE_PARALLEL_DIROPS | FUSE_MAX_PAGES;
    if major != 7 || minor < 26 {
        warn!("volumes: kernel FUSE {major}.{minor} - needs 7.26 or later");
    }
    Out::new()
        .u32(7)
        .u32(MINOR.min(minor))
        .u32(readahead)
        .u32(flags & want)
        .u16(64) // max_background
        .u16(48) // congestion_threshold
        .u32(128 * 1024) // max_write (nothing is written)
        .u32(1) // time_gran
        .u16(MAX_PAGES)
        .u16(0) // map_alignment
        .u32(0) // flags2
        .zeros(28)
        .0
}

fn readdir(tree: &Tree, ino: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
    let Some(n) = tree.nodes.get(&ino) else {
        return Err(libc::ENOENT);
    };
    let Kind::Dir(entries) = &n.kind else {
        return Err(libc::ENOTDIR);
    };
    let mut out = Vec::new();
    // ".", "..", then the entries; an entry's offset is the position after it.
    let all = entries.len() as u64 + 2;
    for pos in offset..all {
        let (name, child): (&str, u64) = match pos {
            0 => (".", ino),
            1 => ("..", n.parent),
            p => {
                let (name, c) = &entries[p as usize - 2];
                (name, *c)
            }
        };
        let kind = match tree.nodes.get(&child).map(|c| &c.kind) {
            Some(Kind::File(_)) => libc::DT_REG,
            _ => libc::DT_DIR,
        };
        let len = 24 + name.len();
        let padded = len.next_multiple_of(8);
        if out.len() + padded > size as usize {
            break;
        }
        out.extend_from_slice(&child.to_le_bytes());
        out.extend_from_slice(&(pos + 1).to_le_bytes());
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(&(kind as u32).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.resize(out.len() + padded - len, 0);
    }
    Ok(out)
}
