// phinet-core/src/lib.rs
//! ΦNET Core Library
//!
//! All cryptographic primitives, certificate logic, onion routing,
//! DHT, hidden services, and message board for the ΦNET overlay network.

pub mod cert;
pub mod crypto;
pub mod ntor;
pub mod pow;
pub mod session;
pub mod wire;
pub mod onion;
pub mod circuit;
pub mod circuit_mgr;
pub mod rendezvous;
pub mod hs_identity;
pub mod guards;
pub mod replay;
pub mod timing;
pub mod stream;
pub mod exit_policy;
pub mod dht;
pub mod hidden_service;
pub mod board;
pub mod node;
pub mod directory;
pub mod transport;
pub mod path_select;
pub mod consensus_fetch;
pub mod padding;
pub mod client_auth;
pub mod vanguards;
pub mod store;
pub mod error;

pub use error::{Error, Result};

/// Restrict a file to owner-only read/write on Unix (0o600). No-op
/// on non-Unix. Best-effort: logs but doesn't fail if the chmod fails.
pub fn secure_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(
            path, std::fs::Permissions::from_mode(0o600))
        {
            tracing::warn!("chmod 600 {}: {}", path.display(), e);
        }
    }
    #[cfg(not(unix))]
    { let _ = path; }
}
