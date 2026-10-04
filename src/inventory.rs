//! What this machine has: CPU, memory, disk, GPUs - gossiped so agents can pick nodes.

use std::process::{Command, Stdio};
use std::time::Duration;

use crate::proto::{Gpu, Inventory};

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect::<String>()
        .trim()
        .to_string()
}

fn meminfo_mb(text: &str, key: &str) -> u64 {
    text.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

/// Runs a command with a deadline (a hanging nvidia-smi must not stall the node).
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                return None;
            }
        }
    }
    let out = child.wait_with_output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn nvidia() -> (Vec<Gpu>, String, String) {
    let Some(csv) = run(
        "nvidia-smi",
        &[
            "--query-gpu=index,name,memory.total,memory.used,utilization.gpu,driver_version",
            "--format=csv,noheader,nounits",
        ],
    ) else {
        return (vec![], String::new(), String::new());
    };
    let mut gpus = vec![];
    let mut driver = String::new();
    for line in csv.lines() {
        let f: Vec<&str> = line.split(',').map(str::trim).collect();
        if f.len() < 6 {
            continue;
        }
        gpus.push(Gpu {
            index: f[0].parse().unwrap_or(0),
            name: clean(f[1]),
            mem_total_mb: f[2].parse().unwrap_or(0),
            mem_used_mb: f[3].parse().unwrap_or(0),
            util_pct: f[4].parse().unwrap_or(0),
        });
        driver = clean(f[5]);
    }
    let cuda = run("nvidia-smi", &[])
        .and_then(|t| {
            t.split("CUDA Version:")
                .nth(1)
                .and_then(|r| r.split_whitespace().next())
                .map(clean)
        })
        .unwrap_or_default();
    gpus.truncate(32);
    (gpus, driver, cuda)
}

/// Collects the inventory (blocking; call from a background thread).
pub fn collect(userspace: bool) -> Inventory {
    let os = read("/etc/os-release")
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| clean(v.trim_matches('"')))
        .unwrap_or_default();
    let cpuinfo = read("/proc/cpuinfo");
    let cpu_model = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name") || l.starts_with("Model") || l.starts_with("Hardware"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| clean(v))
        .unwrap_or_default();
    let meminfo = read("/proc/meminfo");
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let (disk_total_gb, disk_free_gb) = if unsafe { libc::statvfs(c"/".as_ptr(), &mut vfs) } == 0 {
        // The field types differ between 32 and 64 bit platforms.
        #[allow(clippy::useless_conversion)]
        let gb = |blocks| u64::from(blocks) * u64::from(vfs.f_frsize) / 1_000_000_000;
        (gb(vfs.f_blocks), gb(vfs.f_bavail))
    } else {
        (0, 0)
    };
    let (gpus, gpu_driver, cuda) = nvidia();
    Inventory {
        os,
        arch: std::env::consts::ARCH.into(),
        kernel: clean(read("/proc/sys/kernel/osrelease").trim()),
        cpu_model,
        cpu_cores: std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1),
        load1: read("/proc/loadavg")
            .split_whitespace()
            .next()
            .and_then(|l| l.parse().ok())
            .unwrap_or(0.0),
        mem_total_mb: meminfo_mb(&meminfo, "MemTotal:"),
        mem_avail_mb: meminfo_mb(&meminfo, "MemAvailable:"),
        disk_total_gb,
        disk_free_gb,
        gpus,
        gpu_driver,
        cuda,
        userspace,
    }
}
