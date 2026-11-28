//! Rendezvous through public Nostr relays: the same entries as in the DHT (see `rendezvous`),
//! stored as Nostr events. Relays are ordinary web servers reached over HTTPS (WebSocket, port
//! 443), so this works through a company's HTTP proxy or an SSH tunnel and looks like any other
//! web traffic - unlike the DHT's UDP to thousands of addresses.
//!
//! A place (a key seed and a salt, the same as the DHT's) becomes an addressable event (kind
//! 30078, "application data"):
//! * signed with a secp256k1 key derived from the seed - every member works it out, nobody
//!   else - and with a `d` tag from the salt: relays keep only the newest event per key and tag;
//! * its content is the sealed entry, base64: relays see noise;
//! * with an `expiration` tag (NIP-40): relays drop it after a few hours.
//!
//! Entries go to all relays, lookups ask all of them and take the newest entry that opens (the
//! entry inside is signed by the node itself, so a relay can't forge one; it can only withhold
//! it). Relays that want a login (NIP-42) get one with the same key.

use super::*;
use base64::Engine;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use sha2::Digest;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

/// Relays used when the configuration names none: large public ones, run by different people.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://nostr.mom",
    "wss://relay.nostr.net",
];
/// "Application data": an addressable kind (the newest event per key and `d` tag is kept).
const KIND: u64 = 30078;
/// Relays drop an entry after this (it is put again every half hour).
const EXPIRES_SECS: u64 = 3 * 3600;
const PUT_TIMEOUT: Duration = Duration::from_secs(15);
const GET_TIMEOUT: Duration = Duration::from_secs(12);
/// Places asked for in one lookup (filters in one request).
pub(super) const MAX_PLACES: usize = 16;

/// Where an entry is: the key seed and the salt, as for the DHT.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Place {
    pub seed: [u8; 32],
    pub salt: [u8; 20],
}

impl Place {
    fn key(&self) -> SigningKey {
        // A seed that is no valid secret key (about 1 in 2^128): derive again.
        let mut input = self.seed;
        loop {
            let k = rendezvous::derive("meshvpn nostr v1 key", &[&input]);
            if let Ok(key) = SigningKey::from_bytes(&k) {
                return key;
            }
            input = k;
        }
    }

    fn pubkey(&self) -> String {
        hex(&self.key().verifying_key().to_bytes())
    }

    fn d(&self) -> String {
        hex(&self.salt)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// NIP-01: the id is the SHA-256 of `[0, pubkey, created_at, kind, tags, content]`.
fn event_id(pubkey: &str, created_at: u64, kind: u64, tags: &serde_json::Value, content: &str) -> [u8; 32] {
    let ser = serde_json::to_string(&serde_json::json!([0, pubkey, created_at, kind, tags, content])).unwrap();
    sha2::Sha256::digest(ser.as_bytes()).into()
}

fn signed(key: &SigningKey, created_at: u64, kind: u64, tags: serde_json::Value, content: &str) -> serde_json::Value {
    let pubkey = hex(&key.verifying_key().to_bytes());
    let id = event_id(&pubkey, created_at, kind, &tags, content);
    let sig = key
        .sign_raw(&id, &crate::keys::random32())
        .expect("signing a 32-byte id");
    serde_json::json!({
        "id": hex(&id),
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": hex(&sig.to_bytes()),
    })
}

/// The event for an entry at `place`.
pub(super) fn event(place: &Place, value: &[u8], created_at: u64) -> serde_json::Value {
    let tags = serde_json::json!([
        ["d", place.d()],
        ["expiration", (created_at + EXPIRES_SECS).to_string()]
    ]);
    let content = base64::engine::general_purpose::STANDARD.encode(value);
    signed(&place.key(), created_at, KIND, tags, &content)
}

/// An event's value and time, if it is a correctly signed entry at `place`.
pub(super) fn check(ev: &serde_json::Value, place: &Place) -> Option<(Vec<u8>, u64)> {
    let pubkey = ev.get("pubkey")?.as_str()?;
    let kind = ev.get("kind")?.as_u64()?;
    let created_at = ev.get("created_at")?.as_u64()?;
    let tags = ev.get("tags")?;
    let content = ev.get("content")?.as_str()?;
    if kind != KIND || pubkey != place.pubkey() {
        return None;
    }
    let d = place.d();
    let has_d = tags.as_array()?.iter().any(|t| {
        t.as_array().is_some_and(|t| {
            t.first().and_then(|v| v.as_str()) == Some("d") && t.get(1).and_then(|v| v.as_str()) == Some(&d)
        })
    });
    if !has_d {
        return None;
    }
    let id = event_id(pubkey, created_at, kind, tags, content);
    if ev.get("id")?.as_str()? != hex(&id) {
        return None;
    }
    let sig = Signature::try_from(unhex(ev.get("sig")?.as_str()?)?.as_slice()).ok()?;
    let vk = VerifyingKey::from_bytes(&unhex(pubkey)?).ok()?;
    vk.verify_raw(&id, &sig).ok()?;
    let value = base64::engine::general_purpose::STANDARD.decode(content).ok()?;
    Some((value, created_at))
}

// ------------------------------------------------------------------ connections

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
type Ws = WebSocketStream<Pin<Box<dyn Stream>>>;

/// How to get out to the relays.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Via {
    Direct,
    /// An HTTP proxy (CONNECT), with `user:password` if it wants a login.
    Http {
        addr: String,
        auth: Option<String>,
    },
    Socks(String),
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A proxy URL from the environment (`http://user:pw@host:port`, `socks5h://host:port`).
fn parse_proxy(url: &str) -> Option<Via> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let rest = rest.split('/').next()?;
    let (auth, host) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(percent_decode(a)), h),
        None => (None, rest),
    };
    let scheme = scheme.to_ascii_lowercase();
    let default_port = if scheme.starts_with("socks") { 1080 } else { 80 };
    let host = if host.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) && !host.ends_with(']') {
        host.to_string()
    } else {
        format!("{host}:{default_port}")
    };
    if scheme.starts_with("socks") {
        Some(Via::Socks(host))
    } else {
        Some(Via::Http { addr: host, auth })
    }
}

fn no_proxy_for(host: &str, list: &str) -> bool {
    list.split(',').map(str::trim).filter(|e| !e.is_empty()).any(|e| {
        let e = e.trim_start_matches("*.").trim_start_matches('.');
        e == "*" || host == e || host.ends_with(&format!(".{e}"))
    })
}

/// The way to `host`: the configuration's SOCKS proxy (an SSH tunnel), else the proxy of the
/// environment (`https_proxy`, as `meshvpn install` saved it in proxy.env), else direct.
pub(super) fn via_for(socks: Option<String>, host: &str, tls: bool) -> Via {
    if let Some(s) = socks {
        return Via::Socks(s);
    }
    let env = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| std::env::var(n).ok().filter(|v| !v.trim().is_empty()))
    };
    if env(&["no_proxy", "NO_PROXY"]).is_some_and(|l| no_proxy_for(host, &l)) {
        return Via::Direct;
    }
    let names: &[&str] = if tls {
        &["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]
    } else {
        &["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"]
    };
    env(names).and_then(|u| parse_proxy(&u)).unwrap_or(Via::Direct)
}

/// A relay URL's host, port and whether it is TLS.
fn split_url(url: &str) -> Result<(String, u16, bool)> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("wss://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (false, r)
    } else {
        bail!("not a relay address (wss://...): {url}");
    };
    let hostport = rest.split('/').next().unwrap_or_default();
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !hostport.ends_with(']') => {
            (h.to_string(), p.parse().with_context(|| format!("bad port in {url}"))?)
        }
        _ => (hostport.to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        bail!("no host in {url}");
    }
    Ok((
        host.trim_start_matches('[').trim_end_matches(']').to_string(),
        port,
        tls,
    ))
}

async fn http_connect(proxy: &str, auth: Option<&str>, target: &str) -> Result<tokio::net::TcpStream> {
    let mut s = tokio::net::TcpStream::connect(proxy)
        .await
        .with_context(|| format!("proxy {proxy} not reachable"))?;
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(a) = auth {
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(a)
        ));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    // The reply's head, byte by byte (nothing of the tunnel's data may be read here).
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            bail!("proxy {proxy}: reply too long");
        }
        head.push(
            s.read_u8()
                .await
                .with_context(|| format!("proxy {proxy} closed the connection"))?,
        );
    }
    let line = String::from_utf8_lossy(&head);
    let status = line.lines().next().unwrap_or_default().to_string();
    match status.split_whitespace().nth(1) {
        Some("200") => Ok(s),
        Some("407") => bail!("proxy {proxy} wants a login (407)"),
        _ => bail!("proxy {proxy} refused: {status}"),
    }
}

fn tls_config() -> Arc<tokio_rustls::rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<tokio_rustls::rustls::ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = tokio_rustls::rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
            Arc::new(
                tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .expect("TLS versions")
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

async fn connect(url: &str, socks: Option<String>) -> Result<Ws> {
    let (host, port, tls) = split_url(url)?;
    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let tcp = match via_for(socks, &host, tls) {
        Via::Direct => tokio::net::TcpStream::connect(&target)
            .await
            .with_context(|| format!("{target} not reachable"))?,
        Via::Http { addr, auth } => http_connect(&addr, auth.as_deref(), &target).await?,
        Via::Socks(p) => crate::link::socks5_connect(&p, &target).await?,
    };
    let _ = tcp.set_nodelay(true);
    let stream: Pin<Box<dyn Stream>> = if tls {
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.clone())
            .with_context(|| format!("bad host name {host}"))?;
        let s = tokio_rustls::TlsConnector::from(tls_config())
            .connect(name, tcp)
            .await
            .with_context(|| format!("TLS with {host}"))?;
        Box::pin(s)
    } else {
        Box::pin(tcp)
    };
    let (ws, _) = tokio_tungstenite::client_async(url, stream)
        .await
        .with_context(|| format!("WebSocket with {url}"))?;
    Ok(ws)
}

async fn send(ws: &mut Ws, v: serde_json::Value) -> Result<()> {
    use futures_util::SinkExt;
    ws.send(Message::Text(v.to_string().into())).await?;
    Ok(())
}

/// The next relay message (a JSON array); None when the connection ended.
async fn recv(ws: &mut Ws) -> Option<Vec<serde_json::Value>> {
    use futures_util::StreamExt;
    loop {
        match ws.next().await? {
            Ok(Message::Text(t)) => {
                if let Ok(serde_json::Value::Array(a)) = serde_json::from_str(&t) {
                    return Some(a);
                }
            }
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

fn auth_event(key: &SigningKey, relay: &str, challenge: &str) -> serde_json::Value {
    let tags = serde_json::json!([["relay", relay], ["challenge", challenge]]);
    signed(key, now_ms() / 1000, 22242, tags, "")
}

fn text(a: &[serde_json::Value], i: usize) -> &str {
    a.get(i).and_then(|v| v.as_str()).unwrap_or_default()
}

/// Puts the event at one relay; Ok once the relay took it.
async fn put_one(url: &str, socks: Option<String>, place: &Place, ev: &serde_json::Value) -> Result<()> {
    let mut ws = connect(url, socks).await?;
    let id = ev["id"].as_str().unwrap_or_default().to_string();
    send(&mut ws, serde_json::json!(["EVENT", ev])).await?;
    let mut challenge: Option<String> = None;
    let mut resent = false;
    while let Some(m) = recv(&mut ws).await {
        match text(&m, 0) {
            "AUTH" => challenge = Some(text(&m, 1).to_string()),
            "OK" if text(&m, 1) == id => {
                if m.get(2).and_then(|v| v.as_bool()) == Some(true) || text(&m, 3).starts_with("duplicate") {
                    let _ = ws.close(None).await;
                    return Ok(());
                }
                let why = text(&m, 3).to_string();
                // A relay that wants a login (NIP-42): log in with the place's key, send again.
                if why.starts_with("auth-required")
                    && !resent
                    && let Some(c) = &challenge
                {
                    send(&mut ws, serde_json::json!(["AUTH", auth_event(&place.key(), url, c)])).await?;
                    resent = true;
                    send(&mut ws, serde_json::json!(["EVENT", ev])).await?;
                    continue;
                }
                bail!("{url} refused: {why}");
            }
            "NOTICE" => debug!("nostr: {url}: {}", text(&m, 1)),
            _ => {}
        }
    }
    bail!("{url} closed the connection")
}

/// The newest entry per place at one relay.
async fn get_one(url: &str, socks: Option<String>, places: &[Place]) -> Result<Vec<Option<(Vec<u8>, u64)>>> {
    let mut ws = connect(url, socks).await?;
    let filters: Vec<serde_json::Value> = places
        .iter()
        .map(|p| serde_json::json!({"kinds": [KIND], "authors": [p.pubkey()], "#d": [p.d()], "limit": 1}))
        .collect();
    let sub = hex(&crate::keys::random32()[..8]);
    let req = |sub: &str| {
        let mut r = vec![serde_json::json!("REQ"), serde_json::json!(sub)];
        r.extend(filters.iter().cloned());
        serde_json::Value::Array(r)
    };
    send(&mut ws, req(&sub)).await?;
    let mut out: Vec<Option<(Vec<u8>, u64)>> = vec![None; places.len()];
    let mut challenge: Option<String> = None;
    let mut retried = false;
    while let Some(m) = recv(&mut ws).await {
        match text(&m, 0) {
            "EVENT" if text(&m, 1) == sub => {
                let Some(ev) = m.get(2) else { continue };
                for (i, p) in places.iter().enumerate() {
                    if let Some((v, at)) = check(ev, p)
                        && out[i].as_ref().is_none_or(|(_, t)| at > *t)
                    {
                        out[i] = Some((v, at));
                    }
                }
            }
            "EOSE" if text(&m, 1) == sub => {
                let _ = ws.close(None).await;
                return Ok(out);
            }
            "AUTH" => challenge = Some(text(&m, 1).to_string()),
            "CLOSED" if text(&m, 1) == sub => {
                let why = text(&m, 2).to_string();
                if why.starts_with("auth-required")
                    && !retried
                    && let Some(c) = &challenge
                {
                    retried = true;
                    // One login per key asked for (NIP-42 allows several).
                    let mut keys: Vec<String> = vec![];
                    for p in places {
                        let pk = p.pubkey();
                        if !keys.contains(&pk) {
                            keys.push(pk);
                            send(&mut ws, serde_json::json!(["AUTH", auth_event(&p.key(), url, c)])).await?;
                        }
                    }
                    send(&mut ws, req(&sub)).await?;
                    continue;
                }
                bail!("{url} refused: {why}");
            }
            "NOTICE" => debug!("nostr: {url}: {}", text(&m, 1)),
            _ => {}
        }
    }
    bail!("{url} closed the connection")
}

/// What a put did: at how many relays it is, of how many, and the last error.
#[derive(Debug, Default, Clone)]
pub(super) struct Put {
    pub ok: usize,
    pub tried: usize,
    pub error: Option<String>,
}

/// Puts `value` at `place` on all relays (at once).
pub(super) async fn put(relays: &[String], socks: Option<String>, place: &Place, value: &[u8], created_at: u64) -> Put {
    let ev = Arc::new(event(place, value, created_at));
    let mut set = tokio::task::JoinSet::new();
    for url in relays {
        let (url, socks, ev, place) = (url.clone(), socks.clone(), ev.clone(), *place);
        set.spawn(async move {
            match tokio::time::timeout(PUT_TIMEOUT, put_one(&url, socks, &place, &ev)).await {
                Ok(r) => r,
                Err(_) => Err(anyhow!("{url} didn't answer")),
            }
        });
    }
    let mut out = Put {
        tried: relays.len(),
        ..Default::default()
    };
    while let Some(r) = set.join_next().await {
        match r {
            Ok(Ok(())) => out.ok += 1,
            Ok(Err(e)) => {
                debug!("nostr: {e:#}");
                out.error = Some(format!("{e:#}"));
            }
            Err(_) => {}
        }
    }
    out
}

/// The newest entry per place over all relays (at once), and the last error if none answered.
pub(super) async fn get(
    relays: &[String],
    socks: Option<String>,
    places: &[Place],
) -> (Vec<Option<(Vec<u8>, u64)>>, Option<String>) {
    let places: Arc<Vec<Place>> = Arc::new(places.to_vec());
    let mut set = tokio::task::JoinSet::new();
    for url in relays {
        let (url, socks, places) = (url.clone(), socks.clone(), places.clone());
        set.spawn(async move {
            match tokio::time::timeout(GET_TIMEOUT, get_one(&url, socks, &places)).await {
                Ok(r) => r,
                Err(_) => Err(anyhow!("{url} didn't answer")),
            }
        });
    }
    let mut out: Vec<Option<(Vec<u8>, u64)>> = vec![None; places.len()];
    let (mut answered, mut error) = (false, None);
    while let Some(r) = set.join_next().await {
        match r {
            Ok(Ok(found)) => {
                answered = true;
                for (i, f) in found.into_iter().enumerate() {
                    if let Some((v, at)) = f
                        && out[i].as_ref().is_none_or(|(_, t)| at > *t)
                    {
                        out[i] = Some((v, at));
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("nostr: {e:#}");
                error = Some(format!("{e:#}"));
            }
            Err(_) => {}
        }
    }
    (out, if answered { None } else { error })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn place(n: u8) -> Place {
        Place {
            seed: [n; 32],
            salt: [n + 1; 20],
        }
    }

    #[test]
    fn events_check_out_only_at_their_place() {
        let p = place(1);
        let ev = event(&p, b"sealed bytes", 1_800_000_000);
        assert_eq!(check(&ev, &p), Some((b"sealed bytes".to_vec(), 1_800_000_000)));
        assert_eq!(check(&ev, &place(2)), None, "another place");
        let other_salt = Place { salt: [9; 20], ..p };
        assert_eq!(check(&ev, &other_salt), None, "same key, another d tag");
        let mut bad = ev.clone();
        bad["content"] = serde_json::json!("c2VhbGVkIGJ5dGVa");
        assert_eq!(check(&bad, &p), None, "changed content");
        let mut bad = ev.clone();
        bad["created_at"] = serde_json::json!(1_800_000_001u64);
        assert_eq!(check(&bad, &p), None, "changed time");
        // Expires: the tag is there, a few hours on.
        let exp = ev["tags"][1][1].as_str().unwrap().parse::<u64>().unwrap();
        assert_eq!(exp, 1_800_000_000 + EXPIRES_SECS);
    }

    /// NIP-01's id over a known event (from a relay), and BIP-340's first test vector.
    #[test]
    fn ids_and_signatures_as_others_make_them() {
        let tags = serde_json::json!([]);
        let id = event_id(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            1,
            1,
            &tags,
            "a\"b\\c\nd",
        );
        // Serialized as [0,"79be...",1,1,[],"a\"b\\c\nd"].
        let ser = "[0,\"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\",1,1,[],\"a\\\"b\\\\c\\nd\"]";
        let want: [u8; 32] = sha2::Sha256::digest(ser.as_bytes()).into();
        assert_eq!(id, want);
        // BIP-340 test vector 0.
        let mut sk = [0u8; 32];
        sk[31] = 3;
        let key = SigningKey::from_bytes(&sk).unwrap();
        assert_eq!(
            hex(&key.verifying_key().to_bytes()),
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        );
        let sig = key.sign_raw(&[0u8; 32], &[0u8; 32]).unwrap();
        assert_eq!(
            hex(&sig.to_bytes()).to_uppercase(),
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
        );
    }

    #[test]
    fn places_differ_by_seed() {
        assert_ne!(place(1).pubkey(), place(2).pubkey());
        assert_eq!(place(1).pubkey(), place(1).pubkey());
        assert_eq!(place(1).d().len(), 40);
    }

    #[test]
    fn proxies_from_the_environment() {
        assert_eq!(
            parse_proxy("http://user:p%40ss@proxy.corp:3128/"),
            Some(Via::Http {
                addr: "proxy.corp:3128".into(),
                auth: Some("user:p@ss".into())
            })
        );
        assert_eq!(
            parse_proxy("proxy.corp"),
            Some(Via::Http {
                addr: "proxy.corp:80".into(),
                auth: None
            })
        );
        assert_eq!(
            parse_proxy("socks5h://127.0.0.1:1080"),
            Some(Via::Socks("127.0.0.1:1080".into()))
        );
        assert_eq!(parse_proxy(""), None);
        assert!(no_proxy_for("relay.damus.io", "localhost,.damus.io"));
        assert!(no_proxy_for("relay.damus.io", "*"));
        assert!(!no_proxy_for("nos.lol", "localhost,.damus.io"));
        assert_eq!(
            split_url("wss://relay.damus.io").unwrap(),
            ("relay.damus.io".into(), 443, true)
        );
        assert_eq!(
            split_url("ws://10.0.0.5:7777/x").unwrap(),
            ("10.0.0.5".into(), 7777, false)
        );
        assert!(split_url("https://x").is_err());
    }

    /// Against the public relays (needs the internet): `cargo test nostr_public -- --ignored`.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn nostr_public_relays() {
        let p = Place {
            seed: crate::keys::random32(),
            salt: crate::keys::random32()[..20].try_into().unwrap(),
        };
        let relays: Vec<String> = DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect();
        let value = crate::keys::random32().to_vec();
        let now = now_ms() / 1000;
        let put = put(&relays, None, &p, &value, now).await;
        eprintln!("put: {put:?}");
        for url in &relays {
            let one = put_one(url, None, &p, &event(&p, &value, now)).await;
            let got = get_one(url, None, &[p]).await;
            eprintln!(
                "{url}: put {:?}, get {:?}",
                one.as_ref().map_err(|e| format!("{e:#}")),
                got.as_ref()
                    .map(|v| v[0].as_ref().map(|(v2, _)| v2 == &value))
                    .map_err(|e| format!("{e:#}"))
            );
        }
        let (found, err) = get(&relays, None, &[p]).await;
        assert_eq!(found[0].as_ref().map(|(v, _)| v.clone()), Some(value), "{err:?}");
    }
}
