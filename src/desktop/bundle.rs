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

/// The desktop chosen when the packed desktop was installed without root (desktop/run-header.sh).
pub fn user_default_file() -> Option<PathBuf> {
    let data = std::env::var_os("XDG_DATA_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .map(|h| PathBuf::from(h).join(".local/share"))
        })?;
    Some(data.join("meshvpn/desktop-full/default-session"))
}

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

/// VirtualGL's package `file`, from MESHVPN_VIRTUALGL_DIR or GitHub, checked against its checksum.
fn virtualgl_package(file: &str) -> Result<Vec<u8>> {
    let url = format!("https://github.com/VirtualGL/virtualgl/releases/download/{VIRTUALGL}/{file}");
    // A copy at hand (machines without internet, tests): MESHVPN_VIRTUALGL_DIR/<file>. Checked
    // against the same checksum as a download.
    let local = std::env::var_os("MESHVPN_VIRTUALGL_DIR")
        .map(|d| std::path::PathBuf::from(d).join(file))
        .filter(|p| p.is_file());
    let data: Vec<u8> = if let Some(p) = local {
        println!("VirtualGL {VIRTUALGL} from {}", p.display());
        std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?
    } else {
        println!("Downloading VirtualGL {VIRTUALGL} ({file})...");
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let c = crate::update::client(None)?;
            // GitHub's download servers answer 5xx now and then: a few tries.
            let mut tries = 0;
            loop {
                tries += 1;
                match c.get(&url).send().await.and_then(|r| r.error_for_status()) {
                    Ok(r) => break anyhow::Ok(r.bytes().await?.to_vec()),
                    Err(e) if tries < 4 && e.status().is_none_or(|s| s.is_server_error()) => {
                        eprintln!("  {e} - trying again");
                        tokio::time::sleep(std::time::Duration::from_secs(5 * tries)).await;
                    }
                    Err(e) => break Err(e.into()),
                }
            }
        })
        .with_context(|| {
            format!(
                "downloading {url} (without internet: put {file} into a directory and set MESHVPN_VIRTUALGL_DIR to it)"
            )
        })?
    };
    let want = VIRTUALGL_SHA256
        .iter()
        .find(|(f, _)| *f == file)
        .map(|(_, h)| *h)
        .with_context(|| format!("no checksum known for {file}"))?;
    let got = crate::update::sha256_hex(&data);
    if got != want {
        bail!("{url}: checksum {got}, expected {want} - not installed");
    }
    Ok(data)
}

/// `meshvpn desktop setup --gpu`: 3D on the GPU in desktop sessions (VirtualGL: OpenGL programs
/// render on the GPU, the picture goes into the session's X server) and the picture to the
/// browser encoded by the GPU (ffmpeg with NVENC or VA-API, and the VA-API drivers).
pub fn install_gpu() -> Result<()> {
    if !crate::sys::is_root() || crate::config::rootless() {
        return install_gpu_user();
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
    let data = virtualgl_package(&file)?;
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

/// The packed desktop is installed here (for this user, or for the machine): its programs bring
/// their own libraries.
pub fn packed_installed() -> bool {
    user_base()
        .map(|b| b.with_file_name("desktop-full/opt/meshvpn-desktop-full"))
        .into_iter()
        .chain([PathBuf::from("/opt/meshvpn-desktop-full")])
        .any(|p| p.is_dir())
}

/// Where `setup --gpu` puts VirtualGL without root: `lib/` (the libraries sessions preload),
/// `bin/` (glxinfo, eglinfo, glxspheres64, to check it), `doc/` (its licence).
pub fn user_virtualgl_dir() -> Option<PathBuf> {
    user_base().map(|b| b.with_file_name("virtualgl"))
}

/// VirtualGL in the session's own libraries, if installed (the user's own, else the machine's).
pub fn virtualgl_lib() -> Option<PathBuf> {
    user_virtualgl_dir()
        .map(|d| d.join("lib"))
        .into_iter()
        .chain(["/usr/lib", "/usr/lib64", "/opt/VirtualGL/lib", "/opt/VirtualGL/lib64"].map(PathBuf::from))
        .find(|d| d.join("libvglfaker.so").is_file() && d.join("libdlfaker.so").is_file())
}

/// `setup --gpu` without root: VirtualGL's libraries from its Debian package (for any
/// distribution of this architecture: they need only the system's OpenGL and X libraries) into
/// the user's own directory. On NVIDIA that's all: VirtualGL drives its EGL without GLX in the
/// session's X server, so the bundled Xvfb will do. Mesa's EGL (Intel, AMD) needs GLX: the
/// system's Xvfb, which takes root to install. Not ffmpeg: the picture is encoded by an ffmpeg
/// found in the PATH, if there is one (see desktop::video).
fn install_gpu_user() -> Result<()> {
    let a = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => bail!("VirtualGL has no package for {other}"),
    };
    let dir = user_virtualgl_dir().ok_or_else(|| anyhow!("HOME is not set"))?;
    let deb = virtualgl_package(&format!("virtualgl_{VIRTUALGL}_{a}.deb"))?;
    let tmp = dir.with_extension(format!("new-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    for sub in ["lib", "bin", "doc"] {
        std::fs::create_dir_all(tmp.join(sub))?;
    }
    let xz = ar_member(&deb, "data.tar.xz").context("VirtualGL's package has no data.tar.xz")?;
    let mut tar_bytes = Vec::new();
    lzma_rs::xz_decompress(&mut std::io::Cursor::new(xz), &mut tar_bytes)
        .map_err(|e| anyhow!("unpacking VirtualGL's package: {e:?}"))?;
    let mut n = 0;
    for entry in tar::Archive::new(std::io::Cursor::new(tar_bytes)).entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().trim_start_matches("./").to_string();
        let name = path.rsplit('/').next().unwrap_or_default().to_string();
        let dest = if path.starts_with("usr/lib/") && name.ends_with(".so") {
            tmp.join("lib").join(&name)
        } else if ["glxinfo", "eglinfo", "glxspheres64", "eglxspheres64"]
            .map(|b| format!("opt/VirtualGL/bin/{b}"))
            .contains(&path)
        {
            tmp.join("bin").join(&name)
        } else if path.starts_with("usr/share/doc/") && name.ends_with(".txt") {
            tmp.join("doc").join(&name)
        } else {
            continue;
        };
        if entry.header().entry_type().is_file() {
            entry.unpack(&dest)?;
            n += 1;
        }
    }
    if !tmp.join("lib/libvglfaker.so").is_file() || !tmp.join("lib/libdlfaker.so").is_file() {
        let _ = std::fs::remove_dir_all(&tmp);
        bail!("VirtualGL's package has no libvglfaker.so ({n} files)");
    }
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::rename(&tmp, &dir)?;
    println!(
        "VirtualGL {VIRTUALGL} installed in {} (without root: for this user)",
        dir.display()
    );
    let has =
        |c: &str| std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(c).is_file()));
    let nvidia = unsafe { libc::access(c"/dev/nvidia0".as_ptr(), libc::R_OK | libc::W_OK) } == 0;
    if !nvidia
        && !["/usr/bin/Xvfb", "/usr/local/bin/Xvfb"]
            .iter()
            .any(|p| Path::new(p).is_file())
    {
        println!(
            "No NVIDIA GPU here: VirtualGL on other GPUs also needs the system's Xvfb (an admin: \
             sudo meshvpn desktop setup --gpu). Until then OpenGL runs on the CPU."
        );
    }
    if !has("ffmpeg") {
        println!(
            "No ffmpeg here: the picture is encoded on the CPU. An ffmpeg with NVENC or VA-API in the PATH \
             (e.g. ~/.local/bin) lets the GPU encode it too."
        );
    }
    Ok(())
}

/// The member `name` of an ar archive (a .deb is one).
fn ar_member<'a>(data: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let mut rest = data.strip_prefix(b"!<arch>\n")?;
    while rest.len() >= 60 {
        let (head, body) = rest.split_at(60);
        let member = std::str::from_utf8(&head[..16]).ok()?.trim_end().trim_end_matches('/');
        let size: usize = std::str::from_utf8(&head[48..58]).ok()?.trim().parse().ok()?;
        if body.len() < size {
            return None;
        }
        if member == name {
            return Some(&body[..size]);
        }
        rest = &body[(size + size % 2).min(body.len())..];
    }
    None
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
    if !crate::sys::is_root() || crate::config::rootless() {
        // The packed desktop (installed without root) has Xfce and MATE: choosing is all there is.
        let packed = user_base().map(|b| b.with_file_name("desktop-full/opt/meshvpn-desktop-full"));
        if ["xfce", "mate"].contains(&name)
            && let (Some(p), Some(f)) = (packed.filter(|p| p.is_dir()), user_default_file())
        {
            std::fs::write(&f, name)?;
            println!("{name} from the packed desktop in {}", p.display());
            return Ok(());
        }
        bail!(
            "installing a desktop needs root (the system's package manager) - try again with sudo, or ask an admin. \
             Without root: install.sh --user --desktop xfce|mate (the packed desktop)"
        );
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

/// A browser older than this has missed security fixes: Chromium publishes them about weekly.
const BROWSER_OLD_DAYS: u64 = 30;

/// The browser of a packed desktop, as its installer describes it (desktop/build-full.sh).
#[derive(Debug, PartialEq)]
pub struct PackedBrowser {
    pub version: String,
    pub days_old: u64,
}

impl PackedBrowser {
    pub fn is_old(&self) -> bool {
        self.days_old > BROWSER_OLD_DAYS
    }
}

fn parse_packed_browser(text: &str, now_secs: u64) -> Option<PackedBrowser> {
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('=').map(str::trim))
    };
    let date: u64 = field("date")?.parse().ok()?;
    Some(PackedBrowser {
        version: field("chromium")?.to_string(),
        days_old: now_secs.saturating_sub(date) / 86400,
    })
}

/// The installed packed desktop's browser, if there is one (the user's own wins, as in `find`).
pub fn packed_browser() -> Option<PackedBrowser> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let own = user_base().map(|b| b.with_file_name("desktop-full/opt/meshvpn-desktop-full/browser"));
    [own, Some(PathBuf::from("/opt/meshvpn-desktop-full/browser"))]
        .into_iter()
        .flatten()
        .find_map(|f| parse_packed_browser(&std::fs::read_to_string(f).ok()?, now))
}

/// The packed desktop was built for /nix/store, and that path is compiled into its programs and
/// libraries. Without root it can't be there, so every mention becomes another path of the same
/// length, which leaves the offsets inside the files valid.
#[cfg(not(unix))]
pub fn relocate(_dir: &Path, _from: &str, _to: &str) -> Result<()> {
    bail!("the packed desktop is for Linux")
}

#[cfg(unix)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_browser_age() {
        let day = 86400;
        let b = parse_packed_browser("chromium=156.0.1\nnixpkgs=abc\ndate=1000\n", 1000 + 31 * day).unwrap();
        assert_eq!(b.version, "156.0.1");
        assert_eq!(b.days_old, 31);
        assert!(b.is_old());
        assert!(
            !parse_packed_browser("chromium=1\ndate=1000\n", 1000 + 30 * day)
                .unwrap()
                .is_old()
        );
        // A clock behind the build isn't old, and a file we can't read isn't anything.
        assert_eq!(parse_packed_browser("chromium=1\ndate=1000\n", 5).unwrap().days_old, 0);
        assert!(parse_packed_browser("chromium=1\n", 5).is_none());
        assert!(parse_packed_browser("chromium=1\ndate=soon\n", 5).is_none());
    }

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

    #[cfg(unix)]
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
