// phinet-core/src/crypto.rs
//! ΦNET Cryptographic Primitives
//!
//! Hybrid key exchange: X25519 (classical) + ML-KEM-1024 (post-quantum).
//! Session encryption: ChaCha20-Poly1305.
//! Key derivation: HKDF-SHA256.
//! Hashing: SHA-256, BLAKE2b-256.

use crate::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem1024,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

// ── Static X25519 keypair (long-lived per node) ───────────────────────

pub struct StaticKeypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl StaticKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] { *self.public.as_bytes() }
}

// ── ML-KEM-1024 sizes (confirmed by test) ────────────────────────────
pub const MLKEM_EK_BYTES: usize = 1568;
pub const MLKEM_CT_BYTES: usize = 1568;
pub const MLKEM_DK_BYTES: usize = 3168;
pub const MLKEM_SS_BYTES: usize = 32;

// ── Wire key bundle ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePublicKeys {
    pub x25519_pub: String, // hex 32 bytes
    pub mlkem_ek:   String, // hex 1568 bytes
}

// ── Key generation ────────────────────────────────────────────────────

/// Generate X25519 + ML-KEM-1024 keypairs.
/// Returns (public bundle, dk_bytes, x25519 secret).
pub fn generate_keypairs() -> (WirePublicKeys, Vec<u8>, StaticSecret) {
    let x_secret = StaticSecret::random_from_rng(OsRng);
    let x_public = PublicKey::from(&x_secret);
    let (dk, ek) = MlKem1024::generate(&mut OsRng);
    let ek_enc   = ek.as_bytes();
    let dk_enc   = dk.as_bytes();
    let bundle = WirePublicKeys {
        x25519_pub: hex::encode(x_public.as_bytes()),
        mlkem_ek:   hex::encode(ek_enc.as_slice()),
    };
    (bundle, dk_enc.to_vec(), x_secret)
}

// ── Hybrid ciphertext ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// Initiator ephemeral X25519 public key (hex 32 bytes)
    pub x25519_ephem_pub: String,
    /// ML-KEM-1024 ciphertext (hex 1568 bytes), empty = X25519 only
    pub mlkem_ct: String,
}

// ── Initiator: encapsulate ────────────────────────────────────────────

pub fn hybrid_encapsulate(
    peer: &WirePublicKeys,
) -> Result<(HybridCiphertext, Zeroizing<Vec<u8>>)> {
    // X25519 ephemeral DH
    let our_e    = StaticSecret::random_from_rng(OsRng);
    let our_epub = PublicKey::from(&our_e);
    let peer_x   = parse_x25519_pub(&peer.x25519_pub)?;
    let x_ss     = Zeroizing::new(our_e.diffie_hellman(&peer_x).to_bytes());

    // ML-KEM encapsulation
    let (mlkem_ct_hex, mlkem_ss) = encap_mlkem(&peer.mlkem_ek);

    let shared = combine(x_ss.as_ref(), mlkem_ss.as_slice());
    Ok((HybridCiphertext {
        x25519_ephem_pub: hex::encode(our_epub.as_bytes()),
        mlkem_ct: mlkem_ct_hex,
    }, shared))
}

fn encap_mlkem(ek_hex: &str) -> (String, Zeroizing<Vec<u8>>) {
    let zero_ss = || Zeroizing::new(vec![0u8; MLKEM_SS_BYTES]);
    let Ok(ek_raw) = hex::decode(ek_hex) else { return (String::new(), zero_ss()); };
    if ek_raw.len() != MLKEM_EK_BYTES { return (String::new(), zero_ss()); }

    let Ok(ek_enc) = ek_raw.as_slice().try_into() else { return (String::new(), zero_ss()); };
    let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(ek_enc);
    let Ok((ct, ss)) = ek.encapsulate(&mut OsRng) else { return (String::new(), zero_ss()); };
    // ct is Array<u8, CiphertextSize> — convert to &[u8] via as_slice()
    let ct_slice: &[u8] = ct.as_slice();
    (hex::encode(ct_slice), Zeroizing::new(ss.to_vec()))
}

// ── Responder: decapsulate ────────────────────────────────────────────

pub fn hybrid_decapsulate(
    x_secret: &StaticSecret,
    dk_bytes: &[u8],
    ct: &HybridCiphertext,
) -> Result<Zeroizing<Vec<u8>>> {
    let peer_e = parse_x25519_pub(&ct.x25519_ephem_pub)?;
    let x_ss   = Zeroizing::new(x_secret.diffie_hellman(&peer_e).to_bytes());
    let mlkem_ss = decap_mlkem(dk_bytes, &ct.mlkem_ct);
    Ok(combine(x_ss.as_ref(), mlkem_ss.as_slice()))
}

fn decap_mlkem(dk_bytes: &[u8], ct_hex: &str) -> Zeroizing<Vec<u8>> {
    let zero_ss = || Zeroizing::new(vec![0u8; MLKEM_SS_BYTES]);
    if ct_hex.is_empty() || dk_bytes.len() != MLKEM_DK_BYTES { return zero_ss(); }

    let Ok(ct_raw) = hex::decode(ct_hex) else { return zero_ss(); };
    if ct_raw.len() != MLKEM_CT_BYTES { return zero_ss(); }

    let Ok(dk_enc) = dk_bytes.try_into() else { return zero_ss(); };
    let dk = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(dk_enc);

    // Ciphertext<MlKem1024> = Array<u8, CiphertextSize>; convert via TryFrom
    let Ok(ct_arr) = ct_raw.as_slice().try_into() else { return zero_ss(); };
    let ct: Ciphertext<MlKem1024> = ct_arr;
    let Ok(ss) = dk.decapsulate(&ct) else { return zero_ss(); };
    Zeroizing::new(ss.to_vec())
}

fn combine(x: &[u8], k: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut ikm = Vec::with_capacity(x.len() + k.len());
    ikm.extend_from_slice(x);
    ikm.extend_from_slice(k);
    Zeroizing::new(hkdf_derive(&ikm, b"phinet-hybrid-v1", b"session", 64))
}

// ── AEAD ──────────────────────────────────────────────────────────────

pub fn aead_encrypt(key: &[u8; 32], nonce_ctr: u64, _aad: &[u8], pt: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(&nonce96(nonce_ctr), pt)
        .expect("aead encrypt")
}

pub fn aead_decrypt(key: &[u8; 32], nonce_ctr: u64, _aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(&nonce96(nonce_ctr), ct)
        .map_err(|_| Error::AuthFailed)
}

fn nonce96(ctr: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&ctr.to_le_bytes());
    Nonce::from(n)
}

// ── HKDF ──────────────────────────────────────────────────────────────

pub fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("hkdf expand");
    out
}

// ── Per-hop onion key ─────────────────────────────────────────────────

pub fn derive_hop_key(priv_key: &StaticSecret, peer_pub: &[u8; 32]) -> [u8; 32] {
    let shared = priv_key.diffie_hellman(&PublicKey::from(*peer_pub));
    hkdf_derive(shared.as_bytes(), b"phinet-onion-v1", b"hop-key", 32)
        .try_into()
        .unwrap()
}

// ── Hashing ───────────────────────────────────────────────────────────

pub fn sha256(data: &[u8]) -> [u8; 32] { Sha256::digest(data).into() }

pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2b, Digest as _};
    Blake2b::<blake2::digest::typenum::U32>::digest(data).into()
}

// ── Helpers ───────────────────────────────────────────────────────────

pub fn parse_x25519_pub(hex_str: &str) -> Result<PublicKey> {
    let b: [u8; 32] = hex::decode(hex_str)
        .map_err(|e| Error::Crypto(format!("x25519 hex: {e}")))?
        .try_into()
        .map_err(|_| Error::Crypto("x25519 wrong length".into()))?;
    Ok(PublicKey::from(b))
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip() {
        let k  = [0x42u8; 32];
        let ct = aead_encrypt(&k, 7, b"", b"hello phinet");
        assert_eq!(aead_decrypt(&k, 7, b"", &ct).unwrap(), b"hello phinet");
    }

    #[test]
    fn aead_wrong_key_fails() {
        let ct = aead_encrypt(&[1u8; 32], 0, b"", b"x");
        assert!(aead_decrypt(&[2u8; 32], 0, b"", &ct).is_err());
    }

    #[test]
    fn hkdf_is_deterministic() {
        let a = hkdf_derive(b"k", b"s", b"i", 32);
        assert_eq!(a, hkdf_derive(b"k", b"s", b"i", 32));
        assert_ne!(a, hkdf_derive(b"k2", b"s", b"i", 32));
    }

    #[test]
    fn x25519_dh_symmetric() {
        let a = StaticKeypair::generate();
        let b = StaticKeypair::generate();
        assert_eq!(
            a.secret.diffie_hellman(&b.public).as_bytes(),
            b.secret.diffie_hellman(&a.public).as_bytes(),
        );
    }

    #[test]
    fn hop_key_symmetric() {
        let a = StaticKeypair::generate();
        let b = StaticKeypair::generate();
        assert_eq!(
            derive_hop_key(&a.secret, b.public.as_bytes()),
            derive_hop_key(&b.secret, a.public.as_bytes()),
        );
    }

    #[test]
    fn hybrid_kem_full_roundtrip() {
        let (bundle, dk_bytes, x_secret) = generate_keypairs();
        let (ct, ss_i) = hybrid_encapsulate(&bundle).unwrap();
        let ss_r = hybrid_decapsulate(&x_secret, &dk_bytes, &ct).unwrap();
        assert_eq!(*ss_i, *ss_r, "shared secrets must match");
    }

    #[test]
    fn hybrid_kem_x25519_only_fallback() {
        let (mut bundle, _, x_secret) = generate_keypairs();
        bundle.mlkem_ek = String::new();
        let (ct, ss_i) = hybrid_encapsulate(&bundle).unwrap();
        let ss_r = hybrid_decapsulate(&x_secret, &[], &ct).unwrap();
        assert_eq!(*ss_i, *ss_r);
    }
}
