//! The desktop bundle: a static Xvfb + xkbcomp, keyboard layouts and fonts, built in our CI
//! (desktop/build-bundle.sh) and published with each release. Installed per machine (root) or
//! per user (rootless, and for users logging in over SSH).

use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};

pub struct Bundle {
    pub dir: PathBuf,
}

impl Bundle {
    pub fn xvfb(&self) -> PathBuf {
        self.dir.join("bin/Xvfb")
    }
    pub fn bin_dir(&self) -> PathBuf {
        self.dir.join("bin")
    }
    pub fn xkb_dir(&self) -> PathBuf {
        self.dir.join("share/xkb")
    }
    pub fn fonts_dir(&self) -> PathBuf {
        self.dir.join("share/fonts")
    }
}

const SYSTEM: &str = "/var/lib/meshvpn/desktop";

fn user_base() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        Some(x) => PathBuf::from(x),
        None => PathBuf::from(std::env::var_os("HOME").filter(|v| !v.is_empty())?).join(".local/share"),
    };
    Some(base.join("meshvpn/desktop"))
}

/// Where `setup` installs: the machine-wide place as root, else the user's.
fn install_base() -> Result<PathBuf> {
    if unsafe { libc::geteuid() } == 0 && !crate::config::rootless() {
        Ok(PathBuf::from(SYSTEM))
    } else {
        user_base().ok_or_else(|| anyhow!("HOME is not set"))
    }
}

/// An installed bundle (the user's own wins over the machine-wide one).
pub fn find() -> Option<Bundle> {
    [user_base(), Some(PathBuf::from(SYSTEM))]
        .into_iter()
        .flatten()
        .map(|b| b.join("meshvpn-desktop"))
        .find(|d| d.join("bin/Xvfb").is_file() && d.join("bin/xkbcomp").is_file())
        .map(|dir| Bundle { dir })
}

/// `meshvpn desktop setup --xfce`: Xfce from the system's package manager - a real desktop
/// (panel with the applications menu, file manager, terminal) instead of the built-in one.
pub fn install_xfce() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("installing Xfce needs root (the system's package manager) - try again with sudo, or ask an admin");
    }
    let has = |c: &str| {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d.join(c).is_file()))
            .unwrap_or(false)
    };
    // Lean: the desktop, a terminal and D-Bus; no screensaver, power manager or display manager.
    let script = if has("apt-get") {
        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
         xfce4 xfce4-terminal dbus-x11 adwaita-icon-theme fonts-dejavu-core librsvg2-common"
    } else if has("dnf") {
        "dnf install -y xfce4-session xfwm4 xfce4-panel xfdesktop xfce4-settings Thunar xfce4-terminal \
         xfce4-appfinder dbus-x11 adwaita-icon-theme dejavu-sans-fonts"
    } else if has("apk") {
        "apk add xfce4 xfce4-terminal dbus-x11 adwaita-icon-theme font-dejavu librsvg"
    } else if has("zypper") {
        "zypper --non-interactive install xfce4-session xfwm4 xfce4-panel xfdesktop xfce4-settings thunar \
         xfce4-terminal dbus-1-x11 adwaita-icon-theme dejavu-fonts"
    } else {
        bail!("no supported package manager (apt, dnf, apk, zypper) - install Xfce yourself");
    };
    println!("Installing Xfce (this takes a few minutes)...");
    let ok = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .status()
        .context("running the package manager")?
        .success();
    if !ok {
        bail!("installing Xfce failed (see above)");
    }
    Ok(())
}

pub fn archive_name() -> String {
    format!("meshvpn-desktop-{}.tar.gz", std::env::consts::ARCH)
}

/// Installs the bundle from `from` (a downloaded archive) or from the GitHub release of this
/// meshvpn version.
pub fn setup(from: Option<&Path>) -> Result<Bundle> {
    let data = match from {
        Some(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        None => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let client = crate::update::client(None)?;
                let tag = if crate::update::is_dev_build() {
                    crate::update::latest_tag(&client).await?
                } else {
                    format!("v{}", crate::update::CURRENT)
                };
                crate::update::download_verified(&client, &tag, &archive_name())
                    .await
                    .with_context(|| {
                        format!(
                            "no desktop bundle for this machine - without internet, copy {} from a release \
                             here and run: meshvpn desktop setup --from <file>",
                            archive_name()
                        )
                    })
            })?
        }
    };
    install(&data)
}

fn install(data: &[u8]) -> Result<Bundle> {
    let base = install_base()?;
    std::fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    let tmp = base.join(format!(".unpack-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(data));
    tar.set_preserve_permissions(true);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        // Only plain relative paths inside meshvpn-desktop/.
        if !path.starts_with("meshvpn-desktop")
            || path.components().any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            bail!("unexpected path in the desktop bundle: {}", path.display());
        }
        entry.unpack_in(&tmp)?;
    }
    let unpacked = tmp.join("meshvpn-desktop");
    if !unpacked.join("bin/Xvfb").is_file() {
        let _ = std::fs::remove_dir_all(&tmp);
        bail!("this is not a meshvpn desktop bundle");
    }
    let dest = base.join("meshvpn-desktop");
    let old = base.join(format!(".old-{}", std::process::id()));
    if dest.exists() {
        std::fs::rename(&dest, &old)?;
    }
    std::fs::rename(&unpacked, &dest)?;
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(&old);
    Ok(Bundle { dir: dest })
}
