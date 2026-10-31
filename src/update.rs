//! Self-update from GitHub releases.

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

pub const REPO: &str = "PlugOvr-ai/meshvpn";

/// Where releases of this build come from: an extension's own (enterprise builds update to
/// enterprise builds), else the open-source repository.
pub fn repo() -> String {
    crate::ext::get()
        .and_then(|e| e.release_repo())
        .unwrap_or_else(|| REPO.to_string())
}
/// The version of this build: the extension's (a build with its own releases), else meshvpn's.
pub fn current() -> String {
    crate::ext::get()
        .and_then(|e| e.version())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}
const TARGET: &str = env!("MESHVPN_RELEASE_TARGET");

/// HTTP client; `socks` routes through e.g. the SSH tunnel of a firewalled node.
pub fn client(socks: Option<&str>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .user_agent(concat!("meshvpn/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(300));
    if let Some(p) = socks {
        b = b.proxy(reqwest::Proxy::all(format!("socks5h://{p}"))?);
    }
    Ok(b.build()?)
}

fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim().trim_start_matches('v');
    let v = v.split(['-', '+']).next()?;
    let mut it = v.split('.').map(|p| p.parse::<u64>().ok());
    Some((it.next()??, it.next()?.unwrap_or(0), it.next().flatten().unwrap_or(0)))
}

/// `version` is `min` or newer (unknown versions are not).
pub fn at_least(version: &str, min: &str) -> bool {
    matches!((parse_version(version), parse_version(min)), (Some(v), Some(m)) if v >= m)
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    matches!((parse_version(latest), parse_version(current)), (Some(l), Some(c)) if l > c)
}

/// Tag of the latest release (e.g. `v0.2.0`). Uses the `releases/latest` redirect instead of
/// the GitHub API, so there is no rate limit to run into.
pub async fn latest_tag(client: &reqwest::Client) -> Result<String> {
    let url = format!("https://github.com/{}/releases/latest", repo());
    let resp = client.head(&url).send().await.context("contacting github.com")?;
    let final_url = resp.url().clone();
    let tag = final_url
        .path_segments()
        .and_then(|mut s| s.rfind(|_| true))
        .filter(|t| parse_version(t).is_some())
        .ok_or_else(|| anyhow!("no release found at {url}"))?;
    Ok(tag.to_string())
}

/// True for binaries run out of a cargo `target/` directory.
pub fn is_dev_build() -> bool {
    current_exe().is_ok_and(|p| p.components().any(|c| c.as_os_str() == "target"))
}

/// The path of the running binary, even if it has already been replaced on disk.
pub fn current_exe() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let s = exe.to_string_lossy();
    Ok(PathBuf::from(s.strip_suffix(" (deleted)").unwrap_or(&s)))
}

/// Downloads file `name` of release `tag` and checks it against the published `<name>.sha256`.
pub async fn download_verified(client: &reqwest::Client, tag: &str, name: &str) -> Result<Vec<u8>> {
    let base = format!("https://github.com/{}/releases/download/{tag}", repo());
    let get = |url: String| async move {
        let r = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("downloading {url}"))?;
        if !r.status().is_success() {
            bail!("downloading {url}: HTTP {}", r.status());
        }
        Ok::<_, anyhow::Error>(r.bytes().await?)
    };
    let data = get(format!("{base}/{name}")).await?;
    let sums = get(format!("{base}/{name}.sha256")).await?;
    let expected = String::from_utf8_lossy(&sums)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    let actual: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
    if expected != actual {
        bail!("checksum mismatch for {name} - not installing");
    }
    Ok(data.to_vec())
}

/// Downloads the meshvpn binary of release `tag` for `target` and verifies its checksum.
pub async fn download_binary(client: &reqwest::Client, tag: &str, target: &str) -> Result<Vec<u8>> {
    let base = format!("https://github.com/{}/releases/download/{tag}", repo());
    let archive = format!("meshvpn-{target}.tar.gz");
    let get = |url: String| async move {
        let r = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("downloading {url}"))?;
        if !r.status().is_success() {
            bail!("downloading {url}: HTTP {}", r.status());
        }
        Ok::<_, anyhow::Error>(r.bytes().await?)
    };
    let data = get(format!("{base}/{archive}")).await?;
    let sums = get(format!("{base}/{archive}.sha256")).await?;
    let expected = String::from_utf8_lossy(&sums)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    let actual: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
    if expected != actual {
        bail!("checksum mismatch for {archive} - not installing");
    }

    let mut binary = None;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(&data[..]));
    for entry in tar.entries()? {
        let mut entry = entry?;
        if entry
            .path()?
            .file_name()
            .is_some_and(|n| n == "meshvpn" || n == "meshvpn.exe")
        {
            let mut buf = vec![];
            entry.read_to_end(&mut buf)?;
            binary = Some(buf);
            break;
        }
    }
    binary.ok_or_else(|| anyhow!("{archive} does not contain meshvpn"))
}

/// Downloads release `tag`, verifies it and that it runs, then atomically replaces the
/// running binary. Returns the path of the new binary.
pub async fn install(client: &reqwest::Client, tag: &str) -> Result<PathBuf> {
    let binary = download_binary(client, tag, TARGET).await?;
    let exe = current_exe()?;
    let tmp = exe.with_file_name(if cfg!(windows) {
        ".meshvpn.update.exe"
    } else {
        ".meshvpn.update"
    });
    std::fs::write(&tmp, &binary).with_context(|| format!("writing {} (try again with sudo)", tmp.display()))?;
    crate::sys::set_mode(&tmp, 0o755)?;
    let want = tag.trim_start_matches('v');
    let out = std::process::Command::new(&tmp).arg("--version").output();
    match out {
        Ok(o) if String::from_utf8_lossy(&o.stdout).contains(want) => {}
        _ => {
            let _ = std::fs::remove_file(&tmp);
            bail!("the downloaded binary does not run on this machine - not installing");
        }
    }
    // Windows can't replace a running .exe, but can rename it out of the way.
    #[cfg(windows)]
    {
        let old = exe.with_extension("old.exe");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(&exe, &old).with_context(|| format!("moving {} aside", exe.display()))?;
    }
    std::fs::rename(&tmp, &exe).with_context(|| format!("replacing {}", exe.display()))?;
    Ok(exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering() {
        assert!(is_newer("v0.2.0", "0.1.9"));
        assert!(is_newer("v0.10.0", "0.9.0"));
        assert!(is_newer("1.0", "0.9.9"));
        assert!(!is_newer("v0.1.1", "0.1.1"));
        assert!(!is_newer("v0.1.0", "0.1.1"));
        assert!(!is_newer("nightly", "0.1.1"));
    }
}
