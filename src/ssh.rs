//! Keeps a reverse SSH tunnel alive for nodes behind a firewall.

use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::SshTunnel;

pub fn command(t: &SshTunnel, local_port: u16) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args(["-N", "-T"])
        .args(["-o", "ExitOnForwardFailure=yes"])
        .args(["-o", "ServerAliveInterval=15"])
        .args(["-o", "ServerAliveCountMax=3"])
        .args(["-o", "BatchMode=yes"])
        .args(["-o", "StrictHostKeyChecking=accept-new"])
        .args(["-p", &t.port.to_string()]);
    if let Some(id) = &t.identity_file {
        cmd.args(["-i", id]);
    }
    // Empty bind address = all interfaces on the server (needs `GatewayPorts clientspecified`).
    cmd.args(["-R", &format!(":{}:127.0.0.1:{}", t.remote_port, local_port)]);
    if t.socks_port != 0 {
        cmd.args(["-D", &format!("127.0.0.1:{}", t.socks_port)]);
    }
    cmd.args(&t.extra_args).arg(&t.server);
    cmd
}

pub async fn supervise(t: SshTunnel, local_port: u16) {
    let mut delay = Duration::from_secs(2);
    loop {
        let mut cmd = command(&t, local_port);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Take the tunnel down with us, even if we are killed hard.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
        let started = Instant::now();
        info!(
            "starting ssh tunnel: {} (public endpoint {})",
            t.server,
            t.public_endpoint()
        );
        match cmd.spawn() {
            Ok(mut child) => {
                if let Some(err) = child.stderr.take() {
                    tokio::spawn(async move {
                        let mut lines = BufReader::new(err).lines();
                        while let Ok(Some(l)) = lines.next_line().await {
                            warn!("ssh: {l}");
                        }
                    });
                }
                let status = child.wait().await;
                warn!("ssh tunnel exited ({status:?})");
            }
            Err(e) => warn!("cannot start ssh: {e} (is openssh-client installed?)"),
        }
        if started.elapsed() > Duration::from_secs(60) {
            delay = Duration::from_secs(2);
        }
        info!("restarting ssh tunnel in {}s", delay.as_secs());
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(60));
    }
}
