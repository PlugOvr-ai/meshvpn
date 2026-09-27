//! Hooks meshvpn into the local OpenSSH server for password-less logins between nodes.
//!
//! A drop-in config makes sshd ask `meshvpn ssh-authorized-keys <user>` for extra keys at
//! each login. meshvpn answers from this machine's own rules (`meshvpn ssh allow`), pinning
//! every key to its node's mesh IP. Everything else in the sshd config stays as it is.

use anyhow::{Context, Result, bail};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DROPIN: &str = "/etc/ssh/sshd_config.d/meshvpn.conf";

fn sshd_binary() -> Result<PathBuf> {
    for p in ["/usr/sbin/sshd", "/usr/bin/sshd", "/usr/local/sbin/sshd"] {
        if Path::new(p).exists() {
            return Ok(p.into());
        }
    }
    bail!("no SSH server installed here - install openssh-server first")
}

/// sshd only runs a root-owned command that nobody else can modify.
fn trusted_exe() -> Result<PathBuf> {
    let exe = crate::update::current_exe()?;
    let mut p = exe.as_path();
    loop {
        let m = std::fs::metadata(p)?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            bail!(
                "{} is not a root-owned, protected location that sshd accepts - install meshvpn with \
                 install.sh (to /usr/local/bin) and run this from there",
                exe.display()
            );
        }
        match p.parent() {
            Some(parent) => p = parent,
            None => return Ok(exe),
        }
    }
}

fn effective_command(sshd: &Path) -> Option<String> {
    let out = Command::new(sshd).arg("-T").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("authorizedkeyscommand ").map(str::to_string))
}

fn reload() {
    for unit in ["ssh", "sshd"] {
        let quiet = Command::new("systemctl")
            .args(["reload", unit])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if quiet.is_ok_and(|s| s.success()) {
            return;
        }
    }
    // No systemd: signal the listening sshd directly.
    let _ = Command::new("pkill").args(["-HUP", "-o", "-x", "sshd"]).status();
}

/// Installs the drop-in (once) and makes sure sshd actually uses it. Returns true if it
/// had to be set up now.
pub fn enable() -> Result<bool> {
    let sshd = sshd_binary()?;
    let exe = trusted_exe()?;
    let want = format!("{} ssh-authorized-keys %u", exe.display());
    if effective_command(&sshd).as_deref() == Some(want.as_str()) {
        return Ok(false);
    }
    if let Some(other) = effective_command(&sshd).filter(|c| c != "none") {
        bail!("sshd already uses AuthorizedKeysCommand {other:?}; meshvpn can't add its own");
    }
    let dir = Path::new(DROPIN).parent().unwrap();
    std::fs::create_dir_all(dir)?;
    let content = format!(
        "# Managed by meshvpn: password-less SSH logins from other mesh nodes.\n\
         # Who may log in: `meshvpn ssh list`. Remove this file to switch it off.\n\
         AuthorizedKeysCommand {want}\n\
         AuthorizedKeysCommandUser nobody\n"
    );
    std::fs::write(DROPIN, content).with_context(|| format!("writing {DROPIN}"))?;
    let check = Command::new(&sshd).arg("-t").output()?;
    if !check.status.success() {
        let _ = std::fs::remove_file(DROPIN);
        bail!(
            "sshd rejected the configuration: {}",
            String::from_utf8_lossy(&check.stderr).trim()
        );
    }
    if effective_command(&sshd).as_deref() != Some(want.as_str()) {
        let _ = std::fs::remove_file(DROPIN);
        bail!(
            "sshd does not read {} - add `Include /etc/ssh/sshd_config.d/*.conf` at the top of \
             /etc/ssh/sshd_config and try again",
            dir.display()
        );
    }
    reload();
    Ok(true)
}

pub fn disable() {
    if std::fs::remove_file(DROPIN).is_ok() {
        reload();
    }
}
