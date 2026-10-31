//! meshvpn as a library: the program (`cli::main`) and what extensions build on (`ext`).

// Servers (desktop, SSH sessions) are Unix-only; on Windows parts of their shared code stay unused.
#![cfg_attr(windows, allow(dead_code))]

mod agent;
mod config;
#[cfg(unix)]
mod console;
#[cfg(windows)]
mod console {
    pub fn run(_dir: &std::path::Path, _user: Option<String>) -> anyhow::Result<()> {
        anyhow::bail!(
            "the terminal console isn't available on Windows yet - use `meshvpn status`, `ssh <user>@<node>.mesh` \
             or `meshvpn desktop <node>`"
        )
    }
}
mod control;
mod desktop;
mod doctor;
mod gpu;
mod guide;
mod hosts;
mod inventory;
mod keys;
mod launch;
mod link;
mod mcp;
mod net;
mod node;
mod proto;
mod share;
mod ssh;
#[cfg(unix)]
mod sshd;
/// Windows: no sshd integration (logins go to the Linux and macOS nodes).
#[cfg(windows)]
mod sshd {
    pub const DROPIN: &str = "";

    pub fn enable_if_installed() -> anyhow::Result<bool> {
        Ok(false)
    }

    pub fn disable() {}
}
mod sshserver;
mod sys;
mod tui;
mod update;
mod userspace;

pub mod cli;
pub mod ext;
