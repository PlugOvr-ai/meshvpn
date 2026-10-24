//! `meshvpn desktop`: graphical desktops of mesh nodes in the browser - also in containers
//! without any X server (a static Xvfb comes with meshvpn's desktop bundle).

pub mod bundle;
pub mod client;
pub mod proto;
#[cfg(unix)]
pub mod session;

/// The desktop server side (Xvfb sessions) needs Unix; Windows machines connect to others.
#[cfg(windows)]
pub mod session {
    use anyhow::{Result, bail};

    pub fn stop() -> Result<bool> {
        Ok(false)
    }

    pub fn attach(_session: &str) -> Result<()> {
        bail!("desktop sessions run on Linux nodes - connect to one with `meshvpn desktop <node>`")
    }

    pub fn run(_session: &str) -> Result<()> {
        bail!("desktop sessions run on Linux nodes - connect to one with `meshvpn desktop <node>`")
    }
}
