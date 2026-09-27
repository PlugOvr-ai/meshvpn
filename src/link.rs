//! Encrypted, authenticated point-to-point links over TCP (Noise XXpsk3).
//!
//! TCP is used on purpose: it is the only thing an SSH tunnel can carry.

use anyhow::{Context, Result, anyhow, bail};
use snow::{Builder, TransportState};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::keys::Key32;

const NOISE_PARAMS: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"meshvpn/1";
pub const MAX_MSG: usize = 65535;
/// Largest plaintext that fits into one Noise message.
pub const MAX_PLAINTEXT: usize = MAX_MSG - 16;

async fn write_raw(w: &mut (impl AsyncWriteExt + Unpin), msg: &[u8]) -> Result<()> {
    let mut buf = Vec::with_capacity(msg.len() + 2);
    buf.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    buf.extend_from_slice(msg);
    w.write_all(&buf).await?;
    Ok(())
}

async fn read_raw(r: &mut (impl AsyncReadExt + Unpin), buf: &mut [u8]) -> Result<usize> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    r.read_exact(&mut buf[..len]).await?;
    Ok(len)
}

/// Runs the Noise handshake. Both sides must know the network key (psk), which is
/// what makes the network private. Returns the remote's static (noise) key.
///
/// Both sides first announce the newest network key version they have and then use the
/// older of the two (the newer side keeps its old keys), so a member that missed a key
/// rotation can still connect and catch up. Returns the version used.
pub async fn handshake(
    stream: &mut TcpStream,
    initiator: bool,
    local_key: &[u8; 32],
    my_version: u32,
    keys: &HashMap<u32, [u8; 32]>,
) -> Result<(TransportState, Key32, u32)> {
    stream.write_all(&my_version.to_be_bytes()).await?;
    let mut theirs = [0u8; 4];
    stream.read_exact(&mut theirs).await?;
    let version = my_version.min(u32::from_be_bytes(theirs));
    let psk = keys
        .get(&version)
        .ok_or_else(|| anyhow!("the other side uses network key version {version}, which this node never had"))?;
    let builder = Builder::new(NOISE_PARAMS.parse()?)
        .local_private_key(local_key)?
        .psk(3, psk)?
        .prologue(PROLOGUE)?;
    let mut hs = if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    };
    let mut msg = vec![0u8; MAX_MSG];
    let mut payload = vec![0u8; MAX_MSG];
    let bad_key = || anyhow!("handshake failed - the other side is not in this network (different network key?)");
    if initiator {
        let n = hs.write_message(&[], &mut msg)?;
        write_raw(stream, &msg[..n]).await?;
        let n = read_raw(stream, &mut msg).await?;
        hs.read_message(&msg[..n], &mut payload).map_err(|_| bad_key())?;
        let n = hs.write_message(&[], &mut msg)?;
        write_raw(stream, &msg[..n]).await?;
    } else {
        let n = read_raw(stream, &mut msg).await?;
        hs.read_message(&msg[..n], &mut payload).map_err(|_| bad_key())?;
        let n = hs.write_message(&[], &mut msg)?;
        write_raw(stream, &msg[..n]).await?;
        let n = read_raw(stream, &mut msg).await?;
        hs.read_message(&msg[..n], &mut payload).map_err(|_| bad_key())?;
    }
    let remote = Key32::from_slice(hs.get_remote_static().context("no remote static key")?)?;
    Ok((hs.into_transport_mode()?, remote, version))
}

/// The two directions of an established link share the Noise state.
#[derive(Clone)]
pub struct Cipher(Arc<Mutex<TransportState>>);

impl Cipher {
    pub fn new(t: TransportState) -> Self {
        Cipher(Arc::new(Mutex::new(t)))
    }
}

pub struct LinkWriter {
    w: OwnedWriteHalf,
    cipher: Cipher,
    buf: Vec<u8>,
}

impl LinkWriter {
    pub fn new(w: OwnedWriteHalf, cipher: Cipher) -> Self {
        LinkWriter {
            w,
            cipher,
            buf: vec![0u8; MAX_MSG],
        }
    }
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() > MAX_PLAINTEXT {
            bail!("frame too large");
        }
        let n = self.cipher.0.lock().unwrap().write_message(plaintext, &mut self.buf)?;
        write_raw(&mut self.w, &self.buf[..n]).await
    }
}

pub struct LinkReader {
    r: OwnedReadHalf,
    cipher: Cipher,
    buf: Vec<u8>,
}

impl LinkReader {
    pub fn new(r: OwnedReadHalf, cipher: Cipher) -> Self {
        LinkReader {
            r,
            cipher,
            buf: vec![0u8; MAX_MSG],
        }
    }
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let n = read_raw(&mut self.r, &mut self.buf).await?;
        let mut out = vec![0u8; n];
        let m = self.cipher.0.lock().unwrap().read_message(&self.buf[..n], &mut out)?;
        out.truncate(m);
        Ok(out)
    }
}

/// Minimal SOCKS5 CONNECT (no auth), e.g. to `ssh -D`.
pub async fn socks5_connect(proxy: &str, target: &str) -> Result<TcpStream> {
    let (host, port) = target.rsplit_once(':').context("target must be host:port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().context("bad port")?;
    if host.len() > 255 {
        bail!("host name too long");
    }
    let mut s = TcpStream::connect(proxy)
        .await
        .with_context(|| format!("SOCKS proxy {proxy} not reachable (is the SSH tunnel up?)"))?;
    s.write_all(&[5, 1, 0]).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    if r != [5, 0] {
        bail!("SOCKS proxy refused");
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0 {
        bail!("SOCKS connect to {target} failed (code {})", head[1]);
    }
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => s.read_u8().await? as usize,
        _ => bail!("bad SOCKS reply"),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::random32;
    use tokio::net::TcpListener;

    type Hs = Result<(TransportState, Key32, u32)>;

    async fn pair(psk_a: [u8; 32], psk_b: [u8; 32]) -> (Hs, Hs) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (ka, kb) = (random32(), random32());
        let server = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            handshake(&mut s, false, &kb, 0, &HashMap::from([(0, psk_b)])).await
        });
        let mut c = TcpStream::connect(addr).await.unwrap();
        let a = handshake(&mut c, true, &ka, 0, &HashMap::from([(0, psk_a)])).await;
        drop(c);
        (a, server.await.unwrap())
    }

    #[tokio::test]
    async fn same_network_key_connects() {
        let psk = random32();
        let (a, b) = pair(psk, psk).await;
        let (mut ta, _, _) = a.unwrap();
        let (mut tb, _, _) = b.unwrap();
        let mut buf = [0u8; 64];
        let mut out = [0u8; 64];
        let n = ta.write_message(b"hi", &mut buf).unwrap();
        let m = tb.read_message(&buf[..n], &mut out).unwrap();
        assert_eq!(&out[..m], b"hi");
    }

    #[tokio::test]
    async fn different_network_key_is_rejected() {
        let (_, b) = pair(random32(), random32()).await;
        assert!(b.is_err(), "responder must reject a peer with the wrong network key");
    }
}
