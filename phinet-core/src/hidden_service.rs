// phinet-core/src/hidden_service.rs
//! ΦNET Hidden Services

use crate::{
    cert::PhiCert,
    crypto::blake2b_256,
    pow::{IntroPuzzle, IntroPuzzleSolution, PuzzleController},
    store::SiteStore,
    wire::HsDescriptor,
};
use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

// ── Hidden service ────────────────────────────────────────────────────

pub struct HiddenService {
    pub hs_id:     String,
    pub name:      String,
    pub nonce:     [u8; 16],
    intro_secret:  StaticSecret,
    pub intro_pub: PublicKey,
    puzzle_ctl:    Mutex<PuzzleController>,
    rendezvous:    RwLock<HashMap<[u8; 32], RendezvousSlot>>,
}

#[allow(dead_code)]
struct RendezvousSlot {
    pub rend_host: String,
    pub rend_port: u16,
    pub created:   std::time::Instant,
}

impl HiddenService {
    pub fn new(cert: &PhiCert, name: &str) -> Self {
        let intro_secret = StaticSecret::random_from_rng(OsRng);
        let intro_pub    = PublicKey::from(&intro_secret);
        let mut nonce    = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let hs_id = derive_hs_id(&cert.j.to_bytes_be(), &nonce, name);
        HiddenService {
            hs_id,
            name:        name.to_string(),
            nonce,
            intro_secret,
            intro_pub,
            puzzle_ctl:  Mutex::new(PuzzleController::new(5.0)),
            rendezvous:  RwLock::new(HashMap::new()),
        }
    }

    pub fn descriptor(&self, intro_host: Option<&str>, intro_port: Option<u16>) -> HsDescriptor {
        HsDescriptor {
            hs_id:      self.hs_id.clone(),
            name:       self.name.clone(),
            intro_pub:  hex::encode(self.intro_pub.as_bytes()),
            intro_host: intro_host.map(|s| s.to_string()),
            intro_port,
        }
    }

    pub fn issue_puzzle(&self) -> IntroPuzzle {
        let d = self.puzzle_ctl.lock().unwrap().record_request();
        IntroPuzzle::generate(d)
    }

    pub fn verify_puzzle(&self, puzzle: &IntroPuzzle, sol: &IntroPuzzleSolution) -> bool {
        puzzle.is_fresh() && puzzle.verify(sol)
    }

    pub fn rotate_intro_key(&mut self) {
        self.intro_secret = StaticSecret::random_from_rng(OsRng);
        self.intro_pub    = PublicKey::from(&self.intro_secret);
    }

    pub async fn evict_old_rendezvous(&self) {
        self.rendezvous.write().await
            .retain(|_, s| s.created.elapsed() < std::time::Duration::from_secs(600));
    }
}

/// Derive hs_id = hex(BLAKE2b-256(J ‖ nonce ‖ name)[..20]).
pub fn derive_hs_id(j_bytes: &[u8], nonce: &[u8; 16], name: &str) -> String {
    let mut input = Vec::with_capacity(j_bytes.len() + 16 + name.len());
    input.extend_from_slice(j_bytes);
    input.extend_from_slice(nonce);
    input.extend_from_slice(name.as_bytes());
    hex::encode(&blake2b_256(&input)[..20])
}

// ── HS manager ────────────────────────────────────────────────────────

pub struct HsManager {
    services: RwLock<HashMap<String, Arc<HiddenService>>>,
    store:    Arc<SiteStore>,
}

impl HsManager {
    pub fn new(store: Arc<SiteStore>) -> Self {
        Self { services: RwLock::new(HashMap::new()), store }
    }

    pub async fn register(&self, cert: &PhiCert, name: &str) -> Arc<HiddenService> {
        let hs = Arc::new(HiddenService::new(cert, name));
        self.services.write().await.insert(hs.hs_id.clone(), Arc::clone(&hs));
        tracing::info!("HS registered: {} ({})", hs.hs_id, name);
        hs
    }

    pub async fn get(&self, hs_id: &str) -> Option<Arc<HiddenService>> {
        self.services.read().await.get(hs_id).cloned()
    }

    pub async fn list(&self) -> Vec<String> {
        self.services.read().await.keys().cloned().collect()
    }

    /// Serve an HTTP request from the local disk store.
    pub async fn serve_http(&self, hs_id: &str, path: &str) -> Option<(u16, String, Vec<u8>)> {
        self.store.get_file(hs_id, path).await
    }
}

// ── PIR-style oblivious lookup ────────────────────────────────────────

/// Return a shuffled batch of DHT keys that hides which hs_id we want.
pub fn pir_query_keys(hs_id: &str, noise: usize) -> Vec<String> {
    let mut keys = vec![format!("hs:{}", hs_id)];
    for _ in 0..noise {
        let mut rnd = [0u8; 10];
        OsRng.fill_bytes(&mut rnd);
        keys.push(format!("hs:{}", hex::encode(rnd)));
    }
    keys.shuffle(&mut OsRng);
    keys
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{CertBits, PhiCert};

    fn cert() -> PhiCert { PhiCert::generate(CertBits::B256).unwrap() }

    #[test]
    fn hs_id_is_40_hex() {
        let c  = cert();
        let hs = HiddenService::new(&c, "site");
        assert_eq!(hs.hs_id.len(), 40);
        assert!(hs.hs_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hs_id_deterministic() {
        let j = b"jbytes";
        let n = [0u8; 16];
        assert_eq!(derive_hs_id(j, &n, "a"), derive_hs_id(j, &n, "a"));
        assert_ne!(derive_hs_id(j, &n, "a"), derive_hs_id(j, &n, "b"));
    }

    #[test]
    fn puzzle_roundtrip() {
        let c      = cert();
        let hs     = HiddenService::new(&c, "t");
        let puzzle = hs.issue_puzzle();
        let sol    = puzzle.solve().unwrap();
        assert!(hs.verify_puzzle(&puzzle, &sol));
    }

    #[test]
    fn pir_contains_real_key() {
        let keys = pir_query_keys("aabbccdd1122334455aa", 7);
        assert_eq!(keys.len(), 8);
        assert!(keys.contains(&"hs:aabbccdd1122334455aa".to_string()));
    }

    #[tokio::test]
    async fn manager_register_get() {
        let store = Arc::new(SiteStore::new_test());
        let mgr   = HsManager::new(store);
        let c     = cert();
        let hs    = mgr.register(&c, "svc").await;
        assert_eq!(mgr.get(&hs.hs_id).await.unwrap().name, "svc");
    }
}
