// phinet-core/src/session.rs
//! Per-connection forward-secret sessions with traffic padding.

use crate::{crypto::{aead_decrypt, aead_encrypt, hkdf_derive}, Result};
use rand::{rngs::OsRng, RngCore};
use std::sync::atomic::{AtomicU64, Ordering};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const CELL_SIZE: usize = 512;

// ── Session ───────────────────────────────────────────────────────────

pub struct Session {
    send_key:   Zeroizing<[u8; 32]>,
    recv_key:   Zeroizing<[u8; 32]>,
    send_nonce: AtomicU64,
    recv_nonce: AtomicU64,
}

impl Session {
    pub fn new(shared: &[u8], initiator: bool) -> Self {
        let km = hkdf_derive(shared, b"phinet-session-v2", b"keys", 64);
        let (sk, rk) = if initiator {
            (km[..32].try_into().unwrap(), km[32..].try_into().unwrap())
        } else {
            (km[32..].try_into().unwrap(), km[..32].try_into().unwrap())
        };
        Self {
            send_key:   Zeroizing::new(sk),
            recv_key:   Zeroizing::new(rk),
            send_nonce: AtomicU64::new(0),
            recv_nonce: AtomicU64::new(0),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let n = self.send_nonce.fetch_add(1, Ordering::SeqCst);
        aead_encrypt(&self.send_key, n, b"", plaintext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let n = self.recv_nonce.fetch_add(1, Ordering::SeqCst);
        aead_decrypt(&self.recv_key, n, b"", ciphertext)
    }

    /// Derive a key for proving cert-rotation authenticity. Keyed by
    /// the session's own send_key but domain-separated so the raw
    /// AEAD key is never exposed and this key is unique per-direction.
    /// Both peers derive the same value from their (send_key, recv_key)
    /// pair because the derivation mixes both ends.
    pub fn rotation_link_key(&self) -> [u8; 32] {
        let mut material = Vec::with_capacity(64);
        // Always use the smaller key first so both sides agree.
        let a: &[u8] = self.send_key.as_ref();
        let b: &[u8] = self.recv_key.as_ref();
        if a < b {
            material.extend_from_slice(a);
            material.extend_from_slice(b);
        } else {
            material.extend_from_slice(b);
            material.extend_from_slice(a);
        }
        let out = hkdf_derive(&material, b"phinet-cert-rotate-v1", b"link", 32);
        let mut k = [0u8; 32];
        k.copy_from_slice(&out);
        k
    }
}

// ── Ephemeral keypair ─────────────────────────────────────────────────

/// One-time X25519 keypair for handshake key exchange.
pub struct EphemeralKeypair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] { *self.public.as_bytes() }

    pub fn dh(&self, peer: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer).to_bytes()
    }
}

// ── Traffic padding ───────────────────────────────────────────────────

pub struct TrafficPadder;

impl TrafficPadder {
    /// A dummy cell: first byte = 0xFF (PADDING marker), rest random.
    pub fn dummy_cell() -> Vec<u8> {
        let mut cell = vec![0u8; CELL_SIZE];
        cell[0] = 0xFF;
        OsRng.fill_bytes(&mut cell[1..]);
        cell
    }

    pub fn is_dummy(payload: &[u8]) -> bool {
        payload.first() == Some(&0xFF)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_encrypt_decrypt() {
        let s = [0x42u8; 64];
        let alice = Session::new(&s, true);
        let bob   = Session::new(&s, false);
        let ct = alice.encrypt(b"hello");
        assert_eq!(bob.decrypt(&ct).unwrap(), b"hello");
    }

    #[test]
    fn session_bidirectional() {
        let s = [0x11u8; 64];
        let alice = Session::new(&s, true);
        let bob   = Session::new(&s, false);
        assert_eq!(bob.decrypt(&alice.encrypt(b"a2b")).unwrap(), b"a2b");
        assert_eq!(alice.decrypt(&bob.encrypt(b"b2a")).unwrap(), b"b2a");
    }

    #[test]
    fn replay_rejected() {
        let s = [0x33u8; 64];
        let alice = Session::new(&s, true);
        let bob   = Session::new(&s, false);
        let ct = alice.encrypt(b"msg");
        assert!(bob.decrypt(&ct).is_ok());
        assert!(bob.decrypt(&ct).is_err()); // nonce counter advanced
    }

    #[test]
    fn dummy_cell_marker() {
        let d = TrafficPadder::dummy_cell();
        assert_eq!(d.len(), CELL_SIZE);
        assert!(TrafficPadder::is_dummy(&d));
        assert!(!TrafficPadder::is_dummy(&[0x00u8, 0x01]));
    }

    #[test]
    fn ephemeral_keypair_dh() {
        let a = EphemeralKeypair::generate();
        let b = EphemeralKeypair::generate();
        assert_eq!(a.dh(&b.public), b.dh(&a.public));
    }
}
