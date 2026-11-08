//! Self-update from GitHub releases.

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

/// SHA-256 of `data`, as hex.
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

pub const REPO: &str = "PlugOvr-ai/meshvpn";

/// Release signatures: two levels, as with TUF or Tailscale's distsign.
///
/// * The **root keys** (Ed25519, below) are kept offline. They rarely sign anything: a release
///   key's certificate, or a release itself in an emergency.
/// * The **release key** signs releases automatically in the release workflow (a GitHub secret,
///   only for `v*` tags, only on GitHub's own runners). A root key certifies it until a date:
///   `release-key.cert`, attached to every release.
///
/// `SHA256SUMS.sig` signs the release's `SHA256SUMS` (see `release_message`) with the release key
/// or a root key. A release key that leaks is replaced by certifying a new one; the old one
/// stops counting at its expiry date (and at once in builds that list it in `REVOKED_KEYS`),
/// without any update of the root keys.
const ROOT_KEYS: &[&str] = &["hHYAO3iLkvQIVXUW8GHBOaGOY-6HqTPAFEH7XofinYk"];
/// Release keys that no longer count, whatever their certificate says.
const REVOKED_KEYS: &[&str] = &[];
/// Releases from this version on are signed. Older ones are only checked against the
/// checksums they publish.
pub const SIGNED_FROM: &str = "0.27.0";

/// What a release signature covers: the tag (so an older release's list can't pass for a
/// newer one) and the checksum list.
pub fn release_message(tag: &str, sums: &[u8]) -> Vec<u8> {
    let mut m = format!("meshvpn release v1\n{}\n", tag.trim_start_matches('v')).into_bytes();
    m.extend_from_slice(sums);
    m
}

/// A root key's statement that `key` may sign releases until `expires_ms`.
#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct KeyCert {
    pub key: String,
    pub expires_ms: u64,
    #[serde(default)]
    pub expires: String,
    pub sig: String,
}

/// What a root key signs to certify a release key.
pub fn cert_message(key: &str, expires_ms: u64) -> Vec<u8> {
    format!("meshvpn release key v1\n{key}\n{expires_ms}\n").into_bytes()
}

fn verifies(key: &str, msg: &[u8], sig: &[u8]) -> bool {
    crate::keys::unb64_32(key).is_ok_and(|k| crate::keys::verify(&crate::keys::Key32(k), msg, sig).is_ok())
}

/// Checks release `tag`'s checksum list `sums` against its signature `sig`: made by a root key,
/// or by a release key that `cert` (the release's `release-key.cert`) certifies. An expired
/// release key still counts for releases no newer than `running` (the desktop bundle of this
/// version), never for an update.
/// The keys a check trusts, and the release keys it no longer does.
struct Trust<'a> {
    roots: &'a [&'a str],
    revoked: &'a [&'a str],
}

fn verify_with(
    trust: &Trust,
    tag: &str,
    sums: &[u8],
    sig: &[u8],
    cert: Option<&[u8]>,
    running: &str,
    now_ms: u64,
) -> Result<()> {
    let sig = crate::keys::unb64(&String::from_utf8_lossy(sig)).context("reading SHA256SUMS.sig")?;
    let msg = release_message(tag, sums);
    let (roots, revoked) = (trust.roots, trust.revoked);
    if roots.iter().any(|k| verifies(k, &msg, &sig)) {
        return Ok(());
    }
    let Some(cert) = cert else {
        bail!("the release signature doesn't verify (and the release has no key certificate) - not installing");
    };
    let c: KeyCert = serde_json::from_slice(cert).context("reading release-key.cert")?;
    let csig = crate::keys::unb64(&c.sig).context("reading release-key.cert")?;
    if !roots
        .iter()
        .any(|k| verifies(k, &cert_message(&c.key, c.expires_ms), &csig))
    {
        bail!("the release key's certificate isn't signed by a root key - not installing");
    }
    if revoked.contains(&c.key.as_str()) {
        bail!("the release was signed with a revoked key - not installing");
    }
    if now_ms > c.expires_ms && is_newer(tag, running) {
        bail!(
            "the release key expired ({}) - not installing",
            crate::node::fmt_time(c.expires_ms)
        );
    }
    if !verifies(&c.key, &msg, &sig) {
        bail!("the release signature doesn't verify - not installing");
    }
    Ok(())
}

/// Checks release `tag`'s `SHA256SUMS` against its `SHA256SUMS.sig` and `release-key.cert`
/// (the keys built in).
pub fn verify_release_sums(tag: &str, sums: &[u8], sig: &[u8], cert: Option<&[u8]>) -> Result<()> {
    let trust = Trust {
        roots: ROOT_KEYS,
        revoked: REVOKED_KEYS,
    };
    verify_with(&trust, tag, sums, sig, cert, &current(), crate::node::now_ms())
}

/// The checksum of `name` in the release's signed list.
pub fn signed_sum(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let (hash, file) = l.split_once(char::is_whitespace)?;
        (file.trim().trim_start_matches('*') == name).then(|| hash.to_lowercase())
    })
}

/// The SHA-256 `name` of release `tag` must have: from the signed `SHA256SUMS` (releases from
/// `SIGNED_FROM` on), else from the release's `<name>.sha256`.
async fn expected_sum(client: &reqwest::Client, repo: &str, tag: &str, name: &str) -> Result<String> {
    let base = format!("https://github.com/{repo}/releases/download/{tag}");
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
    if at_least(tag, SIGNED_FROM) {
        let sums = get(format!("{base}/SHA256SUMS")).await?;
        let sig = get(format!("{base}/SHA256SUMS.sig"))
            .await
            .context("release not signed (yet) - not installing; try again later")?;
        let cert = get(format!("{base}/release-key.cert")).await.ok();
        verify_release_sums(tag, &sums, &sig, cert.as_deref())?;
        return signed_sum(&String::from_utf8_lossy(&sums), name)
            .ok_or_else(|| anyhow!("{name} is not in the release's signed checksums"));
    }
    let sums = get(format!("{base}/{name}.sha256")).await?;
    Ok(String::from_utf8_lossy(&sums)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase())
}

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
    latest_tag_of(client, &repo()).await
}

/// The newest release of GitHub repository `repo` ("owner/name").
pub async fn latest_tag_of(client: &reqwest::Client, repo: &str) -> Result<String> {
    let url = format!("https://github.com/{repo}/releases/latest");
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

/// Downloads file `name` of release `tag` of GitHub repository `repo` and checks it against the
/// release's signed checksums (see `expected_sum`).
pub async fn download_verified(client: &reqwest::Client, repo: &str, tag: &str, name: &str) -> Result<Vec<u8>> {
    let base = format!("https://github.com/{repo}/releases/download/{tag}");
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
    let expected = expected_sum(client, repo, tag, name).await?;
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
    let expected = expected_sum(client, &repo(), tag, &archive).await?;
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
    use ed25519_dalek::{Signer, SigningKey};

    /// The old check (root keys only, no certificate).
    fn v(roots: &[&str], tag: &str, sums: &[u8], sig: &[u8]) -> Result<()> {
        verify_with(&Trust { roots, revoked: &[] }, tag, sums, sig, None, "0.27.0", 0)
    }

    fn b64sig(k: &SigningKey, msg: &[u8]) -> String {
        crate::keys::b64(&k.sign(msg).to_bytes())
    }

    #[test]
    fn the_release_key_certificate_in_the_repository_holds() {
        let c: KeyCert = serde_json::from_str(include_str!("../release-key.cert")).unwrap();
        let sig = crate::keys::unb64(&c.sig).unwrap();
        assert!(
            ROOT_KEYS
                .iter()
                .any(|k| verifies(k, &cert_message(&c.key, c.expires_ms), &sig)),
            "release-key.cert must be signed by a root key"
        );
        assert!(!REVOKED_KEYS.contains(&c.key.as_str()));
    }

    #[test]
    fn release_keys_certified_by_a_root_key() {
        let root = SigningKey::from_bytes(&[1u8; 32]);
        let other_root = SigningKey::from_bytes(&[2u8; 32]);
        let rel = SigningKey::from_bytes(&[3u8; 32]);
        let root_pk = crate::keys::b64(root.verifying_key().as_bytes());
        let rel_pk = crate::keys::b64(rel.verifying_key().as_bytes());
        let roots = [root_pk.as_str()];
        let sums = b"abc  meshvpn-x86_64-unknown-linux-musl.tar.gz\n";
        let day = 86_400_000u64;
        let cert = |by: &SigningKey, expires_ms: u64| {
            serde_json::to_vec(&KeyCert {
                key: rel_pk.clone(),
                expires_ms,
                expires: String::new(),
                sig: b64sig(by, &cert_message(&rel_pk, expires_ms)),
            })
            .unwrap()
        };
        let sig = b64sig(&rel, &release_message("v0.28.0", sums));
        let check = |cert: Option<&[u8]>, revoked: &[&str], running: &str, now: u64| {
            let trust = Trust { roots: &roots, revoked };
            verify_with(&trust, "v0.28.0", sums, sig.as_bytes(), cert, running, now)
        };
        let good = cert(&root, 400 * day);
        assert!(
            check(Some(&good), &[], "0.27.2", 10 * day).is_ok(),
            "certified release key"
        );
        assert!(
            check(None, &[], "0.27.2", 10 * day).is_err(),
            "no certificate: only root keys count"
        );
        assert!(
            check(Some(&cert(&other_root, 400 * day)), &[], "0.27.2", 10 * day).is_err(),
            "certified by an unknown key"
        );
        assert!(check(Some(&good), &[&rel_pk], "0.27.2", 10 * day).is_err(), "revoked");
        // Expired: no updates signed with it, but this version's own files still check out.
        assert!(
            check(Some(&good), &[], "0.27.2", 401 * day).is_err(),
            "expired, for an update"
        );
        assert!(
            check(Some(&good), &[], "0.28.0", 401 * day).is_ok(),
            "expired, this version's own release"
        );
        // A certificate whose dates were changed afterwards.
        let mut c: KeyCert = serde_json::from_slice(&good).unwrap();
        c.expires_ms = 9_000 * day;
        assert!(
            check(Some(&serde_json::to_vec(&c).unwrap()), &[], "0.27.2", 500 * day).is_err(),
            "changed date"
        );
        // A root key may still sign a release itself.
        let root_sig = b64sig(&root, &release_message("v0.28.0", sums));
        assert!(
            verify_with(
                &Trust {
                    roots: &roots,
                    revoked: &[]
                },
                "v0.28.0",
                sums,
                root_sig.as_bytes(),
                None,
                "0.27.2",
                0
            )
            .is_ok()
        );
        // The release key's signature for another version doesn't count.
        assert!(
            verify_with(
                &Trust {
                    roots: &roots,
                    revoked: &[]
                },
                "v0.28.1",
                sums,
                sig.as_bytes(),
                Some(&good),
                "0.27.2",
                0
            )
            .is_err()
        );
    }

    #[test]
    fn release_signatures() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = crate::keys::b64(sk.verifying_key().as_bytes());
        let sums = b"abc123  meshvpn-x86_64-unknown-linux-musl.tar.gz\ndef456  install.sh\n";
        let sig = crate::keys::b64(&sk.sign(&release_message("v0.27.0", sums)).to_bytes());
        assert!(v(&[&pk], "v0.27.0", sums, sig.as_bytes()).is_ok());
        assert!(
            v(&[&pk], "0.27.0", sums, sig.as_bytes()).is_ok(),
            "with or without the v"
        );
        assert!(v(&[&pk], "v0.27.1", sums, sig.as_bytes()).is_err(), "another tag");
        assert!(v(&[&pk], "v0.27.0", b"x", sig.as_bytes()).is_err(), "other sums");
        assert!(v(ROOT_KEYS, "v0.27.0", sums, sig.as_bytes()).is_err(), "another key");
        assert_eq!(
            signed_sum(std::str::from_utf8(sums).unwrap(), "install.sh").as_deref(),
            Some("def456")
        );
        assert_eq!(signed_sum("abc  *install.sh\n", "install.sh").as_deref(), Some("abc"));
        assert_eq!(signed_sum("abc  install.sh.bak\n", "install.sh"), None);
    }

    #[test]
    fn signatures_made_with_openssl_verify() {
        // scripts/sign-release.sh: openssl pkeyutl -sign -rawin, base64url without padding.
        let key = "Gv_DzljIyxqS1MSKeDBNz5o2Q1L1LklPqxsZs1RzMy0";
        let sig = "hAbSq0Z-ojsEd5vDcCt6WgnyVHL1ZPzTz9h06JpOMpg_1Pkd8QbLZbnD2mAHLzb93SXRmc2R5q_AVPvLs-9FCA";
        assert!(v(&[key], "v0.27.0", b"abc  x.tar.gz\n", sig.as_bytes()).is_ok());
    }

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
