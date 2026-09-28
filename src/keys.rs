//! Identities, key helpers and overlay address derivation.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::Ipv4Addr;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::Config;

/// A 32 byte public key, serialized as hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Key32(pub [u8; 32]);

/// A node is identified by its ed25519 public key.
pub type NodeId = Key32;

impl Key32 {
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
    pub fn short(&self) -> String {
        self.hex()[..8].to_string()
    }
    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() != 64 {
            bail!("expected 64 hex chars");
        }
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
        }
        Ok(Key32(out))
    }
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        Ok(Key32(s.try_into().map_err(|_| anyhow!("bad key length"))?))
    }
}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}
impl fmt::Display for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}
impl Serialize for Key32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}
impl<'de> Deserialize<'de> for Key32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Key32::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

pub fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn unb64(s: &str) -> Result<Vec<u8>> {
    B64.decode(s.trim()).context("invalid base64")
}

pub fn unb64_32(s: &str) -> Result<[u8; 32]> {
    unb64(s)?.try_into().map_err(|_| anyhow!("expected a 32 byte key"))
}

/// Everything secret about the local node.
pub struct Identity {
    pub signing: SigningKey,
    pub noise_secret: [u8; 32],
    pub noise_pub: Key32,
    pub id: NodeId,
}

impl Identity {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let signing = SigningKey::from_bytes(&unb64_32(&cfg.signing_key).context("signing_key")?);
        let noise_secret = unb64_32(&cfg.noise_key).context("noise_key")?;
        let noise_pub = Key32(PublicKey::from(&StaticSecret::from(noise_secret)).to_bytes());
        let id = Key32(signing.verifying_key().to_bytes());
        Ok(Identity {
            signing,
            noise_secret,
            noise_pub,
            id,
        })
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// Symmetric key shared with `peer` (static-static X25519), bound to `context`.
    fn shared_key(&self, peer_noise_pub: &Key32, purpose: &str, context: &[u8]) -> [u8; 32] {
        let dh = StaticSecret::from(self.noise_secret)
            .diffie_hellman(&PublicKey::from(peer_noise_pub.0))
            .to_bytes();
        let mut material = dh.to_vec();
        material.extend_from_slice(context);
        blake3::derive_key(purpose, &material)
    }

    /// End-to-end packet key with `peer`. Does not depend on the network key, so rotating
    /// it (on a ban) does not interrupt traffic.
    pub fn e2e_key(&self, peer_noise_pub: &Key32, network_id: &str) -> [u8; 32] {
        self.shared_key(peer_noise_pub, "meshvpn e2e packet key v2", network_id.as_bytes())
    }

    /// Key that seals a new network key (version `version`) for one member.
    pub fn envelope_key(&self, peer_noise_pub: &Key32, version: u32) -> [u8; 32] {
        self.shared_key(peer_noise_pub, "meshvpn key envelope v1", &version.to_be_bytes())
    }
}

pub fn verify(id: &NodeId, msg: &[u8], sig: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(&id.0).map_err(|_| anyhow!("invalid node key"))?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| anyhow!("bad signature length"))?;
    key.verify(msg, &Signature::from_bytes(&sig))
        .map_err(|_| anyhow!("bad signature"))
}

/// Overlay address: 100.64.0.0/10 (CGNAT range, like Tailscale) + 22 bits of hash(node id).
/// Deterministic, so no coordination server is needed to hand out addresses.
pub fn overlay_ip(id: &NodeId) -> Ipv4Addr {
    let h = blake3::hash(&id.0);
    let b = h.as_bytes();
    let mut n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x003f_ffff;
    if n == 0 {
        n = 1;
    }
    if n == 0x003f_ffff {
        n -= 1;
    }
    Ipv4Addr::from(0x6440_0000 | n)
}

/// Short public tag identifying a network (derived from its key). Records carry it so
/// leftovers from another network (e.g. after `init --force`) are rejected everywhere.
pub fn network_tag(network_key: &[u8; 32]) -> String {
    Key32(blake3::derive_key("meshvpn network tag v1", network_key)).hex()[..16].to_string()
}

pub const OVERLAY_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 192, 0, 0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_ips_stay_in_cgnat_range() {
        for _ in 0..1000 {
            let ip = overlay_ip(&Key32(random32()));
            let o = ip.octets();
            assert_eq!(o[0], 100);
            assert!((64..128).contains(&o[1]), "{ip}");
            assert_ne!(ip, Ipv4Addr::new(100, 64, 0, 0));
            assert_ne!(ip, Ipv4Addr::new(100, 127, 255, 255));
        }
    }

    #[test]
    fn e2e_key_is_symmetric() {
        let cfg = |_: u8| Identity::from_config(&crate::config::Config::new("a".into(), "n".into(), [0; 32])).unwrap();
        let (a, b) = (cfg(0), cfg(1));
        let psk = random32();
        assert_eq!(a.e2e_key(&b.noise_pub, "net"), b.e2e_key(&a.noise_pub, "net"));
        assert_eq!(a.envelope_key(&b.noise_pub, 3), b.envelope_key(&a.noise_pub, 3));
        assert_ne!(a.envelope_key(&b.noise_pub, 3), a.envelope_key(&b.noise_pub, 4));
        let _ = psk;
    }
}
