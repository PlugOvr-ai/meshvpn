//! Replay protection for end-to-end encrypted packets.
//!
//! Every packet's 24-byte XChaCha20 nonce is
//!   session 8 | counter 8 | marker 4 | sender id 4
//! where `session` grows with every start of the sender (when it started, in ms, but never less
//! than the last one, which is kept on disk) and `counter` counts its packets. Both ends of a
//! pair share a key, so the sender's id keeps their nonces apart; within one sender, session
//! and counter never repeat. The nonce is authenticated with the packet, so nobody can
//! change it. A receiver keeps, per sender, the newest session and a window of the last
//! `WINDOW` counters (packets arrive out of order over different paths) and drops anything it
//! has seen, anything older than the window and anything from an older session.
//!
//! Nodes before this scheme used random nonces, without the marker: their packets are taken as
//! before (unprotected) - until the node has sent a numbered one; from then on, unnumbered ones
//! (recorded before it was updated) count as replays.

use std::sync::atomic::{AtomicU64, Ordering};

const MARKER: [u8; 4] = *b"MVr1";
/// Counters remembered per sender (out-of-order arrival within this many packets is fine).
const WINDOW: u64 = 4096;
const WORDS: usize = (WINDOW / 64) as usize;

/// The sending side: one per node, for all its peers.
pub(crate) struct Sender {
    session: u64,
    counter: AtomicU64,
    me: [u8; 4],
}

impl Sender {
    /// The sender of node `id`; `dir` keeps the last session (so it grows even if the clock
    /// goes back between two starts).
    pub(crate) fn new(id: &[u8], dir: Option<&std::path::Path>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let file = dir.map(|d| d.join("nonce-session"));
        let last = file
            .as_ref()
            .and_then(|f| std::fs::read_to_string(f).ok())
            .and_then(|t| t.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let session = now.max(last + 1);
        if let Some(f) = &file {
            let _ = std::fs::write(f, format!("{session}\n"));
        }
        let mut me = [0u8; 4];
        me.copy_from_slice(&id[..4]);
        Sender {
            session,
            counter: AtomicU64::new(0),
            me,
        }
    }

    /// The nonce of the next packet.
    pub(crate) fn nonce(&self) -> [u8; 24] {
        let c = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut n = [0u8; 24];
        n[..8].copy_from_slice(&self.session.to_be_bytes());
        n[8..16].copy_from_slice(&c.to_be_bytes());
        n[16..20].copy_from_slice(&MARKER);
        n[20..].copy_from_slice(&self.me);
        n
    }
}

/// What a receiver makes of a packet's nonce.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Verdict {
    /// Seen before, or too old: drop it.
    Replay,
    /// New, and the newest so far (its path may move to where it came from).
    Newest,
    /// New, but arrived after newer ones (reordering).
    Late,
    /// From a node without counters (older version): taken as it is.
    Unnumbered,
}

/// The receiving side, for one sender.
pub(crate) struct Window {
    session: u64,
    /// The highest counter seen + 1 (0: nothing yet in this session).
    top: u64,
    /// Bit i: counter `top - 1 - i` was seen.
    seen: [u64; WORDS],
    /// The sender has sent numbered packets: unnumbered ones from it are old.
    numbered: bool,
}

impl Default for Window {
    fn default() -> Self {
        Window {
            session: 0,
            top: 0,
            seen: [0; WORDS],
            numbered: false,
        }
    }
}

impl Window {
    /// Checks a nonce; only call it for packets that decrypted (authentic ones).
    pub(crate) fn check(&mut self, nonce: &[u8; 24]) -> Verdict {
        if nonce[16..20] != MARKER {
            return if self.numbered {
                Verdict::Replay
            } else {
                Verdict::Unnumbered
            };
        }
        self.numbered = true;
        let session = u64::from_be_bytes(nonce[..8].try_into().unwrap());
        let c = u64::from_be_bytes(nonce[8..16].try_into().unwrap());
        if session < self.session {
            return Verdict::Replay;
        }
        if session > self.session {
            *self = Window {
                session,
                numbered: true,
                ..Default::default()
            };
        }
        if c >= self.top {
            self.shift(c + 1 - self.top);
            self.top = c + 1;
            self.set(0);
            return Verdict::Newest;
        }
        let back = self.top - 1 - c;
        if back >= WINDOW || self.get(back) {
            return Verdict::Replay;
        }
        self.set(back);
        Verdict::Late
    }

    fn get(&self, i: u64) -> bool {
        self.seen[(i / 64) as usize] >> (i % 64) & 1 == 1
    }

    fn set(&mut self, i: u64) {
        self.seen[(i / 64) as usize] |= 1 << (i % 64);
    }

    /// Moves the window `n` counters on (older bits towards the end).
    fn shift(&mut self, n: u64) {
        if n >= WINDOW {
            self.seen = [0; WORDS];
            return;
        }
        let (words, bits) = ((n / 64) as usize, n % 64);
        for i in (0..WORDS).rev() {
            let src = i.checked_sub(words);
            let hi = src.map_or(0, |s| self.seen[s] << bits);
            let lo = match src.and_then(|s| s.checked_sub(1)) {
                Some(s) if bits > 0 => self.seen[s] >> (64 - bits),
                _ => 0,
            };
            self.seen[i] = hi | lo;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(session: u64, c: u64) -> [u8; 24] {
        let mut n = [0u8; 24];
        n[..8].copy_from_slice(&session.to_be_bytes());
        n[8..16].copy_from_slice(&c.to_be_bytes());
        n[16..20].copy_from_slice(&MARKER);
        n
    }

    #[test]
    fn replays_are_dropped() {
        let mut w = Window::default();
        assert_eq!(w.check(&nonce(5, 0)), Verdict::Newest);
        assert_eq!(w.check(&nonce(5, 0)), Verdict::Replay);
        assert_eq!(w.check(&nonce(5, 3)), Verdict::Newest);
        assert_eq!(w.check(&nonce(5, 1)), Verdict::Late);
        assert_eq!(w.check(&nonce(5, 1)), Verdict::Replay);
        assert_eq!(w.check(&nonce(5, 2)), Verdict::Late);
        assert_eq!(w.check(&nonce(5, 3)), Verdict::Replay);
        // Far ahead: what is now behind the window is gone for good.
        assert_eq!(w.check(&nonce(5, 3 + WINDOW + 10)), Verdict::Newest);
        assert_eq!(w.check(&nonce(5, 4)), Verdict::Replay);
        assert_eq!(w.check(&nonce(5, 3 + 20)), Verdict::Late);
        assert_eq!(w.check(&nonce(5, 3 + 20)), Verdict::Replay);
        // A restart: a new session; the old one can't be replayed any more.
        assert_eq!(w.check(&nonce(6, 0)), Verdict::Newest);
        assert_eq!(w.check(&nonce(5, 3 + WINDOW + 11)), Verdict::Replay);
        // Old-format packets after numbered ones: recorded before the update, not taken.
        assert_eq!(w.check(&[7u8; 24]), Verdict::Replay);
        // From a node that never numbered its packets: taken as before.
        assert_eq!(Window::default().check(&[7u8; 24]), Verdict::Unnumbered);
    }

    #[test]
    fn the_window_keeps_what_it_saw_across_shifts() {
        let mut w = Window::default();
        for c in (0..2000).step_by(3) {
            assert_eq!(w.check(&nonce(1, c)), Verdict::Newest);
        }
        for c in (0..2000).step_by(3) {
            assert_eq!(w.check(&nonce(1, c)), Verdict::Replay, "{c}");
        }
        for c in (1..1998).step_by(3) {
            assert_eq!(w.check(&nonce(1, c)), Verdict::Late, "{c}");
        }
    }

    #[test]
    fn sender_counts() {
        let s = Sender::new(&[1, 2, 3, 4, 5], None);
        let (a, b) = (s.nonce(), s.nonce());
        assert_eq!(&a[20..], &[1, 2, 3, 4], "the sender's id keeps both ends apart");
        let dir = std::env::temp_dir().join(format!("replay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("nonce-session"), "99999999999999\n").unwrap();
        let later = Sender::new(&[1, 2, 3, 4], Some(&dir));
        assert_eq!(later.session, 100_000_000_000_000, "never below the last one");
        let _ = std::fs::remove_dir_all(&dir);
        let mut w = Window::default();
        assert_eq!(w.check(&a), Verdict::Newest);
        assert_eq!(w.check(&b), Verdict::Newest);
        assert_eq!(w.check(&a), Verdict::Replay);
    }
}
