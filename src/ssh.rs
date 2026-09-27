//! Keeps the SSH tunnel of a firewalled node alive.

use std::collections::HashSet;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::SshTunnel;

/// PIDs of running ssh processes, so a restart can take them down first.
static SSH_PIDS: Mutex<Option<HashSet<u32>>> = Mutex::new(None);

pub fn kill_all() {
    for pid in SSH_PIDS.lock().unwrap().take().unwrap_or_default() {
        unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    }
}

fn common_args(port: u16, identity: Option<&str>, known_hosts: Option<&str>) -> Vec<String> {
    let mut a: Vec<String> = [
        "-N",
        "-T",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    .map(String::from)
    .to_vec();
    if let Some(k) = known_hosts {
        a.extend(["-o".into(), format!("UserKnownHostsFile={k}")]);
    }
    a.extend(["-p".into(), port.to_string()]);
    if let Some(id) = identity {
        a.extend(["-i".into(), id.into()]);
    }
    a
}

/// This node is firewalled: publish our listener on the server, and get a SOCKS proxy out.
pub fn tunnel_args(t: &SshTunnel, local_port: u16) -> Vec<String> {
    let mut a = common_args(t.port, t.identity_file.as_deref(), None);
    if t.remote_port != 0 {
        // Empty bind address = all interfaces on the server (needs `GatewayPorts clientspecified`).
        a.extend(["-R".into(), format!(":{}:127.0.0.1:{}", t.remote_port, local_port)]);
    }
    if t.socks_port != 0 {
        a.extend(["-D".into(), format!("127.0.0.1:{}", t.socks_port)]);
    }
    a.extend(t.extra_args.iter().cloned());
    a.push(t.server.clone());
    a
}

/// Runs `ssh <args>` forever, restarting it with backoff.
pub async fn supervise(label: String, args: Vec<String>) {
    let mut delay = Duration::from_secs(2);
    loop {
        let mut cmd = Command::new("ssh");
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Take ssh down with us, even if we are killed hard.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
        let started = Instant::now();
        info!("starting {label}");
        match cmd.spawn() {
            Ok(mut child) => {
                let pid = child.id().unwrap_or(0);
                SSH_PIDS.lock().unwrap().get_or_insert_default().insert(pid);
                if let Some(err) = child.stderr.take() {
                    let label = label.clone();
                    tokio::spawn(async move {
                        let mut lines = BufReader::new(err).lines();
                        while let Ok(Some(l)) = lines.next_line().await {
                            warn!("{label}: ssh: {l}");
                        }
                    });
                }
                let status = child.wait().await;
                if let Some(pids) = SSH_PIDS.lock().unwrap().as_mut() {
                    pids.remove(&pid);
                }
                warn!("{label} exited ({status:?})");
            }
            Err(e) => warn!("cannot start ssh: {e} (is openssh-client installed?)"),
        }
        if started.elapsed() > Duration::from_secs(60) {
            delay = Duration::from_secs(2);
        }
        info!("restarting {label} in {}s", delay.as_secs());
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(60));
    }
}
