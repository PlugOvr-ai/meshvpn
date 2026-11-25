//! A desktop session that hangs is stopped instead of staying stuck.
//!
//! A program of the session can get stuck in the kernel - typically in a GPU driver that no
//! longer answers. The desktop then freezes, and everything that looks at that program hangs
//! too (`top`, `ps`, `nvidia-smi` read its /proc entries), until it is killed. So a thread
//! watches the session: when its own loop stops turning, or one of its programs hangs in the
//! kernel for a minute, it kills the session's programs and ends it. The next session says why
//! the last one was stopped, and starts without the GPU.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::warn;

/// The session's loop doesn't turn for this long: it is stuck.
const LOOP_STUCK: Duration = Duration::from_secs(30);
/// A program of the session in uninterruptible sleep (state D) for this long: it hangs.
const PROGRAM_STUCK: Duration = Duration::from_secs(60);
const CHECK_EVERY: Duration = Duration::from_secs(5);
/// Reading the process list doesn't take longer than this (unless something hangs).
const SCAN_LIMIT: Duration = Duration::from_secs(20);
/// Why the last session was stopped (read and removed by the next one).
const STOPPED: &str = "stopped";

static START: OnceLock<Instant> = OnceLock::new();
static BEAT: AtomicU64 = AtomicU64::new(0);
/// The session doesn't use the GPU (it doesn't answer, or the last session hung).
static NO_GPU: AtomicBool = AtomicBool::new(false);

fn now_ms() -> u64 {
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// The session's loop is turning.
pub fn beat() {
    BEAT.store(now_ms(), Ordering::Relaxed);
}

pub fn no_gpu() -> bool {
    NO_GPU.load(Ordering::Relaxed)
}

pub fn set_no_gpu() {
    NO_GPU.store(true, Ordering::Relaxed);
}

/// Why the last session in `dir` was stopped, if it was (once: the note is removed).
pub fn last_stopped(dir: &Path) -> Option<String> {
    let path = dir.join(STOPPED);
    let why = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    Some(why.trim().to_string()).filter(|w| !w.is_empty())
}

/// Watches this session (the process itself and its programs) from a thread of its own.
pub fn start(dir: PathBuf, sock: PathBuf) {
    beat();
    let me = std::process::id() as i32;
    std::thread::spawn(move || {
        let mut since: std::collections::HashMap<i32, Instant> = std::collections::HashMap::new();
        loop {
            std::thread::sleep(CHECK_EVERY);
            let quiet = Duration::from_millis(now_ms().saturating_sub(BEAT.load(Ordering::Relaxed)));
            let (procs, scan_ok) = scan(me);
            let mut why = None;
            if quiet > LOOP_STUCK {
                why = Some(format!("it stopped responding for {} s", quiet.as_secs()));
            } else if !scan_ok {
                why = Some("its programs could not even be listed (something hangs in the kernel)".to_string());
            }
            let stuck: Vec<&Proc> = procs.iter().filter(|p| p.state == 'D').collect();
            since.retain(|pid, _| stuck.iter().any(|p| p.pid == *pid));
            for p in &stuck {
                let t = *since.entry(p.pid).or_insert_with(Instant::now);
                if why.is_none() && t.elapsed() > PROGRAM_STUCK {
                    why = Some(format!(
                        "{} (pid {}) hung in the kernel for {} s{}",
                        p.comm,
                        p.pid,
                        t.elapsed().as_secs(),
                        if p.wchan.is_empty() || p.wchan == "0" {
                            String::new()
                        } else {
                            format!(" (in {})", p.wchan)
                        }
                    ));
                }
            }
            if let Some(why) = why {
                stop(&dir, &sock, &procs, &why);
            }
        }
    });
}

/// Kills the session's programs and ends it, noting why for the next session.
fn stop(dir: &Path, sock: &Path, procs: &[Proc], why: &str) -> ! {
    let hung: Vec<String> = procs
        .iter()
        .filter(|p| p.state == 'D')
        .map(|p| format!("{} (pid {}, in {})", p.comm, p.pid, p.wchan))
        .collect();
    warn!(
        "the desktop session is stuck: {why} - stopping it{}",
        if hung.is_empty() {
            String::new()
        } else {
            format!("; hanging in the kernel: {}", hung.join(", "))
        }
    );
    let _ = std::fs::remove_file(sock);
    let _ = std::fs::write(dir.join(STOPPED), why);
    for p in procs {
        unsafe { libc::kill(p.pid, libc::SIGKILL) };
    }
    std::process::exit(1);
}

struct Proc {
    pid: i32,
    comm: String,
    state: char,
    wchan: String,
}

/// The session's programs: started by it (descendants), or in its process session. Done in a
/// thread with a time limit: reading /proc can itself hang. False if it didn't finish.
fn scan(me: i32) -> (Vec<Proc>, bool) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(list(me));
    });
    match rx.recv_timeout(SCAN_LIMIT) {
        Ok(p) => (p, true),
        Err(_) => (vec![], false),
    }
}

fn list(me: i32) -> Vec<Proc> {
    // pid -> (ppid, sid, state, comm); only /proc/<pid>/stat, which doesn't wait for the
    // process (cmdline and environ do).
    let mut all = std::collections::HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return vec![];
    };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        if let Some(s) = parse_stat(&stat) {
            all.insert(pid, s);
        }
    }
    let ours = |mut pid: i32| {
        for _ in 0..64 {
            let Some((ppid, sid, ..)) = all.get(&pid) else {
                return false;
            };
            if *sid == me || *ppid == me {
                return true;
            }
            if *ppid <= 1 {
                return false;
            }
            pid = *ppid;
        }
        false
    };
    all.iter()
        .filter(|(pid, _)| **pid != me && ours(**pid))
        .map(|(pid, (_, _, state, comm))| Proc {
            pid: *pid,
            comm: comm.clone(),
            state: *state,
            wchan: if *state == 'D' {
                std::fs::read_to_string(format!("/proc/{pid}/wchan")).unwrap_or_default()
            } else {
                String::new()
            },
        })
        .collect()
}

/// (ppid, session id, state, name) from /proc/<pid>/stat: "pid (comm) S ppid pgrp session ...".
fn parse_stat(s: &str) -> Option<(i32, i32, char, String)> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let comm = s.get(open + 1..close)?.to_string();
    let mut f = s.get(close + 1..)?.split_whitespace();
    let state = f.next()?.chars().next()?;
    let ppid = f.next()?.parse().ok()?;
    let _pgrp = f.next()?;
    let sid = f.next()?.parse().ok()?;
    Some((ppid, sid, state, comm))
}

/// Runs `cmd` and waits at most `limit` for it; None if it didn't finish (it is killed, and
/// reaped in the background: a program stuck in the kernel dies only once it gets out).
pub fn output_within(cmd: &mut Command, limit: Duration) -> Option<std::process::Output> {
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let pid = child.id() as i32;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(limit) {
        Ok(out) => out.ok(),
        Err(_) => {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            None
        }
    }
}

/// NVIDIA's driver answers (nvidia-smi within 10 s). True without NVIDIA's tools: nothing to
/// ask.
pub fn nvidia_answers() -> bool {
    if !Path::new("/dev/nvidia0").exists() {
        return true;
    }
    let installed =
        std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("nvidia-smi").is_file()));
    !installed || output_within(Command::new("nvidia-smi").arg("-L"), Duration::from_secs(10)).is_some()
}

/// The NVIDIA GPUs here (their models), from the driver's own files (no program to run).
pub fn nvidia_models() -> Vec<String> {
    let Ok(rd) = std::fs::read_dir("/proc/driver/nvidia/gpus") else {
        return vec![];
    };
    rd.flatten()
        .filter_map(|e| std::fs::read_to_string(e.path().join("information")).ok())
        .filter_map(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("Model:").map(|m| m.trim().to_string()))
        })
        .collect()
}

/// Data center GPUs made for computing have no video encoder (NVENC).
pub fn without_nvenc(model: &str) -> bool {
    let m = model.to_ascii_uppercase();
    [
        "A100", "A800", "A30", "H100", "H800", "H200", "H20", "B100", "B200", "GB200", "B300",
    ]
    .iter()
    .any(|n| m.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| w == *n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_lines() {
        let s = "1234 (mate-panel) D 1200 1200 1100 0 -1 4194560 ...";
        assert_eq!(parse_stat(s), Some((1200, 1100, 'D', "mate-panel".into())));
        // A name with spaces and brackets.
        let s = "77 (Web Content (x)) S 1 77 77 0";
        assert_eq!(parse_stat(s), Some((1, 77, 'S', "Web Content (x)".into())));
    }

    #[test]
    fn gpus_without_encoder() {
        assert!(without_nvenc("NVIDIA A100-SXM4-40GB"));
        assert!(without_nvenc("NVIDIA H100 80GB HBM3"));
        assert!(!without_nvenc("NVIDIA A10"));
        assert!(!without_nvenc("NVIDIA RTX A6000"));
        assert!(!without_nvenc("NVIDIA L40S"));
        assert!(!without_nvenc("NVIDIA GeForce RTX 4090"));
    }
}
