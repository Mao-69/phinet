// phinet-core/src/lib.rs
//! ΦNET Core Library
//!
//! All cryptographic primitives, certificate logic, onion routing,
//! DHT, hidden services, and message board for the ΦNET overlay network.

pub mod cert;
pub mod crypto;
pub mod pow;
pub mod session;
pub mod wire;
pub mod onion;
pub mod dht;
pub mod hidden_service;
pub mod board;
pub mod node;
pub mod store;
pub mod error;

pub use error::{Error, Result};
