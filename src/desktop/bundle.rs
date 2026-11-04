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
    if crate::sys::is_root() && !crate::config::rootless() {
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
    if !crate::sys::is_root() {
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

/// The packed desktop was built for /nix/store, and that path is compiled into its programs and
/// libraries. Without root it can't be there, so every mention becomes another path of the same
/// length, which leaves the offsets inside the files valid.
pub fn relocate(dir: &Path, from: &str, to: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if from.len() != to.len() || from.is_empty() {
        bail!("the new path must be as long as the old one: {from} and {to}");
    }
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        // Nix makes everything read-only, and removing it later needs this too.
        let mode = std::fs::symlink_metadata(&d)?.permissions().mode();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode | 0o700))
            .with_context(|| format!("changing {}", d.display()))?;
        for entry in std::fs::read_dir(&d).with_context(|| format!("reading {}", d.display()))? {
            let path = entry?.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                todo.push(path);
            } else if meta.is_symlink() {
                let target = std::fs::read_link(&path)?;
                let text = target.to_string_lossy();
                if text.contains(from) {
                    let new = text.replace(from, to);
                    std::fs::remove_file(&path)?;
                    std::os::unix::fs::symlink(new, &path).with_context(|| format!("changing {}", path.display()))?;
                }
            } else if meta.is_file() {
                let mut data = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
                if replace_same_length(&mut data, from.as_bytes(), to.as_bytes()) > 0 {
                    let mode = meta.permissions().mode();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode | 0o200))?;
                    std::fs::write(&path, &data).with_context(|| format!("changing {}", path.display()))?;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
                }
            }
        }
    }
    Ok(())
}

fn replace_same_length(data: &mut [u8], from: &[u8], to: &[u8]) -> usize {
    let mut found = 0;
    let mut at = 0;
    while at + from.len() <= data.len() {
        // The first byte alone rules out nearly every place: this reads 2 GB in seconds.
        let Some(next) = data[at..=data.len() - from.len()].iter().position(|b| *b == from[0]) else {
            break;
        };
        at += next;
        if &data[at..at + from.len()] == from {
            data[at..at + from.len()].copy_from_slice(to);
            found += 1;
            at += from.len();
        } else {
            at += 1;
        }
    }
    found
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
                    format!("v{}", env!("CARGO_PKG_VERSION"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relocating_keeps_every_offset() {
        let mut data = b"/nix/store/a\0/nix/stor\0x/nix/store".to_vec();
        let len = data.len();
        assert_eq!(replace_same_length(&mut data, b"/nix/store", b"/tmp/mvab1"), 2);
        assert_eq!(data, b"/tmp/mvab1/a\0/nix/stor\0x/tmp/mvab1");
        assert_eq!(data.len(), len);
        let mut short = b"/nix".to_vec();
        assert_eq!(replace_same_length(&mut short, b"/nix/store", b"/tmp/mvab1"), 0);
    }

    #[test]
    fn relocating_a_tree() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mv-relocate-{}", std::process::id()));
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("prog"), b"run /nix/store/x").unwrap();
        std::fs::set_permissions(sub.join("prog"), std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::write(sub.join("other"), b"nothing").unwrap();
        std::os::unix::fs::symlink("/nix/store/y", sub.join("link")).unwrap();
        std::os::unix::fs::symlink("/elsewhere", sub.join("kept")).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o555)).unwrap();
        relocate(&dir, "/nix/store", "/tmp/mvab1").unwrap();
        assert_eq!(std::fs::read(sub.join("prog")).unwrap(), b"run /tmp/mvab1/x");
        assert_eq!(
            std::fs::metadata(sub.join("prog")).unwrap().permissions().mode() & 0o777,
            0o555
        );
        assert_eq!(std::fs::read_link(sub.join("link")).unwrap(), Path::new("/tmp/mvab1/y"));
        assert_eq!(std::fs::read_link(sub.join("kept")).unwrap(), Path::new("/elsewhere"));
        assert!(relocate(&dir, "/nix/store", "/short").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
