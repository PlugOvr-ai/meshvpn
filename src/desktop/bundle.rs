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

/// Where `meshvpn desktop setup --desktop` notes the machine's choice.
pub const DEFAULT_FILE: &str = "/var/lib/meshvpn/desktop/default-session";

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

/// VirtualGL's release used by `setup --gpu` (from its GitHub releases: the distributions don't
/// package it).
const VIRTUALGL: &str = "3.1.5";

/// The SHA-256 of each VirtualGL package (as GitHub records them for the 3.1.5 release): root
/// installs it, so nothing else will do.
const VIRTUALGL_SHA256: &[(&str, &str)] = &[
    (
        "virtualgl_3.1.5_amd64.deb",
        "df3f7788ce41b182a47c0d298e5cd6d2d63579522cb41825970b7726e825485e",
    ),
    (
        "virtualgl_3.1.5_arm64.deb",
        "9ac238e8a18c06d84ef65444a591a7a5bb4c4ce9e8cfdd92f8a2aea35edbb5d7",
    ),
    (
        "VirtualGL-3.1.5.x86_64.rpm",
        "6670b7f82dd602d47919af3a5c9f4e4348070e4eddce6083d388d14ec0336660",
    ),
    (
        "VirtualGL-3.1.5.aarch64.rpm",
        "38fb3bbc19cc57911795b30be83f9f701d485c6cbae67a1ccc2df36c2a852795",
    ),
];

/// `meshvpn desktop setup --gpu`: 3D on the GPU in desktop sessions (VirtualGL: OpenGL programs
/// render on the GPU, the picture goes into the session's X server) and the picture to the
/// browser encoded by the GPU (ffmpeg with NVENC or VA-API, and the VA-API drivers).
pub fn install_gpu() -> Result<()> {
    if !crate::sys::is_root() {
        bail!("installing the GPU support needs root (the system's package manager) - try again with sudo");
    }
    let has = |c: &str| {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d.join(c).is_file()))
            .unwrap_or(false)
    };
    let arch = std::env::consts::ARCH;
    let (file, install) = if has("apt-get") {
        let a = match arch {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => bail!("VirtualGL has no package for {arch}"),
        };
        (
            format!("virtualgl_{VIRTUALGL}_{a}.deb"),
            "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
             \"$PKG\" ffmpeg xvfb va-driver-all libegl1 libgl1 libgl1-mesa-dri mesa-utils"
                .to_string(),
        )
    } else if has("dnf") || has("zypper") {
        let file = format!("VirtualGL-{VIRTUALGL}.{arch}.rpm");
        let cmd = if has("dnf") {
            "dnf install -y \"$PKG\" ffmpeg-free xorg-x11-server-Xvfb libva mesa-dri-drivers mesa-libEGL glx-utils"
        } else {
            "zypper --non-interactive install --allow-unsigned-rpm \"$PKG\" ffmpeg xorg-x11-server-Xvfb libva2 Mesa-dri Mesa-libEGL1 Mesa-demo-x"
        };
        (file, cmd.to_string())
    } else {
        bail!("no supported package manager (apt, dnf, zypper) for VirtualGL - install it yourself");
    };
    let url = format!("https://github.com/VirtualGL/virtualgl/releases/download/{VIRTUALGL}/{file}");
    println!("Downloading VirtualGL {VIRTUALGL} ({file})...");
    let rt = tokio::runtime::Runtime::new()?;
    let data = rt
        .block_on(async {
            let c = crate::update::client(None)?;
            // GitHub's download servers answer 5xx now and then: a few tries.
            let mut tries = 0;
            loop {
                tries += 1;
                match c.get(&url).send().await.and_then(|r| r.error_for_status()) {
                    Ok(r) => break anyhow::Ok(r.bytes().await?),
                    Err(e) if tries < 4 && e.status().is_none_or(|s| s.is_server_error()) => {
                        eprintln!("  {e} - trying again");
                        tokio::time::sleep(std::time::Duration::from_secs(5 * tries)).await;
                    }
                    Err(e) => break Err(e.into()),
                }
            }
        })
        .with_context(|| format!("downloading {url}"))?;
    let want = VIRTUALGL_SHA256
        .iter()
        .find(|(f, _)| *f == file)
        .map(|(_, h)| *h)
        .with_context(|| format!("no checksum known for {file}"))?;
    let got = crate::update::sha256_hex(&data);
    if got != want {
        bail!("{url}: checksum {got}, expected {want} - not installed");
    }
    // In a new directory of root's alone: nobody can put something else in its place before
    // the package manager reads it.
    let dir = std::env::temp_dir().join(format!("meshvpn-gpu-{:016x}", rand::random::<u64>()));
    {
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&dir)?;
    }
    let tmp = dir.join(&file);
    std::fs::write(&tmp, &data)?;
    println!("Installing VirtualGL, ffmpeg and the GPU drivers' video parts...");
    let ok = std::process::Command::new("sh")
        .arg("-c")
        .arg(&install)
        .env("PKG", &tmp)
        .status()
        .context("running the package manager")?
        .success();
    let _ = std::fs::remove_dir_all(&dir);
    if !ok {
        bail!("installing the GPU support failed (see above)");
    }
    Ok(())
}

/// `meshvpn desktop setup --login`: "meshvpn desktop" in the login screen. Logging in with it
/// shows the user's meshvpn desktop on the monitor; it keeps running when they leave the desk
/// (Ctrl+Alt+End) and can be continued from a browser elsewhere, also while someone else sits
/// there with their own.
pub fn install_login_entry() -> Result<std::path::PathBuf> {
    if !crate::sys::is_root() {
        bail!("adding the login entry needs root - try again with sudo");
    }
    let exe = crate::update::current_exe()?;
    let dir = std::path::Path::new("/usr/share/xsessions");
    std::fs::create_dir_all(dir)?;
    let path = dir.join("meshvpn-desktop.desktop");
    std::fs::write(
        &path,
        format!(
            "[Desktop Entry]\nType=Application\nName=meshvpn desktop\n\
             Comment=Your meshvpn desktop: keeps running when you leave (Ctrl+Alt+End), also in the browser\n\
             Exec={} desktop local\n",
            exe.display()
        ),
    )?;
    Ok(path)
}

/// `meshvpn desktop setup --desktop NAME`: a desktop from the system's package manager (Xfce,
/// MATE or Cinnamon) instead of the built-in minimal one, and the machine's choice for
/// `meshvpn desktop <node>` from then on. Lean: the desktop, a terminal and D-Bus; no display
/// manager. Cinnamon draws with OpenGL: it also gets the system's Xvfb and Mesa (on the CPU).
pub fn install_desktop(name: &str) -> Result<()> {
    if !crate::sys::is_root() {
        bail!("installing a desktop needs root (the system's package manager) - try again with sudo, or ask an admin");
    }
    let has = |c: &str| {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d.join(c).is_file()))
            .unwrap_or(false)
    };
    let (label, apt, dnf, zypper, apk) = match name {
        "xfce" => (
            "Xfce",
            "xfce4 xfce4-terminal dbus-x11 adwaita-icon-theme fonts-dejavu-core librsvg2-common",
            "xfce4-session xfwm4 xfce4-panel xfdesktop xfce4-settings Thunar xfce4-terminal xfce4-appfinder \
             dbus-x11 adwaita-icon-theme dejavu-sans-fonts",
            "xfce4-session xfwm4 xfce4-panel xfdesktop xfce4-settings thunar xfce4-terminal dbus-1-x11 \
             adwaita-icon-theme dejavu-fonts",
            Some("xfce4 xfce4-terminal dbus-x11 adwaita-icon-theme font-dejavu librsvg"),
        ),
        "mate" => (
            "MATE",
            // The applets of Ubuntu's MATE panel layout ("familiar": the Brisk menu, indicators,
            // trash) - without them its top panel stays empty.
            "mate-session-manager mate-panel marco caja mate-terminal mate-control-center mate-settings-daemon \
             mate-themes mate-applet-brisk-menu mate-indicator-applet mate-applets dbus-x11 fonts-dejavu-core \
             librsvg2-common",
            "mate-session-manager mate-panel marco caja mate-terminal mate-control-center mate-settings-daemon \
             mate-themes dbus-x11 dejavu-sans-fonts",
            "mate-session-manager mate-panel marco caja mate-terminal mate-control-center mate-settings-daemon \
             dbus-1-x11 dejavu-fonts",
            Some("mate-desktop-environment dbus-x11 font-dejavu librsvg"),
        ),
        "cinnamon" => (
            "Cinnamon",
            "cinnamon-core dbus-x11 xvfb libgl1-mesa-dri fonts-dejavu-core librsvg2-common",
            "cinnamon cinnamon-session xorg-x11-server-Xvfb mesa-dri-drivers dbus-x11 dejavu-sans-fonts",
            "cinnamon xorg-x11-server-Xvfb Mesa-dri dbus-1-x11 dejavu-fonts",
            None,
        ),
        _ => bail!("no desktop called {name}: xfce, mate or cinnamon"),
    };
    let script = if has("apt-get") {
        format!(
            "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends {apt}"
        )
    } else if has("dnf") {
        format!("dnf install -y {dnf}")
    } else if has("zypper") {
        format!("zypper --non-interactive install {zypper}")
    } else if has("apk") {
        let Some(apk) = apk else {
            bail!("{label} isn't packaged for Alpine - use xfce or mate there");
        };
        format!("apk add {apk}")
    } else {
        bail!("no supported package manager (apt, dnf, zypper, apk) - install {label} yourself");
    };
    println!("Installing {label} (this takes a few minutes)...");
    let ok = std::process::Command::new("sh")
        .arg("-c")
        .arg(&script)
        .status()
        .context("running the package manager")?
        .success();
    if !ok {
        bail!("installing {label} failed (see above)");
    }
    let default = Path::new(DEFAULT_FILE);
    if let Some(d) = default.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(default, name)?;
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
                // The bundle is published with meshvpn's own releases, also for builds with an
                // extension (their releases elsewhere, their version number their own): those
                // and development builds take the newest one.
                let repo = crate::update::REPO;
                let own = crate::ext::get().and_then(|e| e.version()).is_none();
                let tag = if own && !crate::update::is_dev_build() {
                    format!("v{}", env!("CARGO_PKG_VERSION"))
                } else {
                    crate::update::latest_tag_of(&client, repo).await?
                };
                crate::update::download_verified(&client, repo, &tag, &archive_name())
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
        #[cfg_attr(not(unix), allow(unused_variables))]
        let mode = entry.header().mode().unwrap_or(0o644);
        entry.unpack_in(&tmp)?;
        // Programs, but never setuid/setgid ones (root unpacks it), nor writable by others.
        #[cfg_attr(not(unix), allow(unused_variables))]
        let out = tmp.join(&path);
        #[cfg(unix)]
        if mode & 0o7022 != 0 && std::fs::symlink_metadata(&out).is_ok_and(|m| m.is_file() || m.is_dir()) {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode & 0o755))?;
        }
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
