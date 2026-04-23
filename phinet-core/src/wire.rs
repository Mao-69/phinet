// phinet-core/src/wire.rs
//! ΦNET wire protocol – framed JSON messages over TCP.
//!
//! Frame format: [4-byte LE length][payload bytes]
//! Payload is plain JSON before session, ChaCha20-Poly1305 after.

use crate::{session::Session, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

// ── Concrete I/O ──────────────────────────────────────────────────────

/// Send a [`Message`] without encryption (handshake phase).
pub async fn send_raw<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &Message) -> Result<()> {
    let payload = serde_json::to_vec(msg)?;
    w.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    w.write_all(&payload).await?;
    w.flush().await?;
    Ok(())
}

/// Receive a [`Message`] without decryption (handshake phase).
pub async fn recv_raw<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Message> {
    let mut lb = [0u8; 4];
    r.read_exact(&mut lb).await.map_err(|_| Error::Closed)?;
    let len = u32::from_le_bytes(lb) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len}"),
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(|_| Error::Closed)?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Encrypt and send a [`Message`] using an established session.
pub async fn send_session<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    msg: &Message,
    session: &Session,
) -> Result<()> {
    let payload   = serde_json::to_vec(msg)?;
    let encrypted = session.encrypt(&payload);
    w.write_all(&(encrypted.len() as u32).to_le_bytes()).await?;
    w.write_all(&encrypted).await?;
    w.flush().await?;
    Ok(())
}

/// Receive and decrypt a [`Message`] using an established session.
pub async fn recv_session<R: AsyncReadExt + Unpin>(
    r: &mut R,
    session: &Session,
) -> Result<Message> {
    let mut lb = [0u8; 4];
    r.read_exact(&mut lb).await.map_err(|_| Error::Closed)?;
    let len = u32::from_le_bytes(lb) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len}"),
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(|_| Error::Closed)?;
    let dec = session.decrypt(&buf)?;
    Ok(serde_json::from_slice(&dec)?)
}

// ── Message enum ──────────────────────────────────────────────────────

use crate::{
    cert::WireCert,
    pow::{AdmissionPoW, IntroPuzzle, IntroPuzzleSolution},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg_type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Message {
    PowChallenge(PowChallenge),
    Handshake(Handshake),
    HandshakeAck(HandshakeAck),
    Reject(Reject),
    Onion(Onion),
    CircuitCell(CircuitCellMsg),
    DhtFind(DhtFind),
    DhtFound(DhtFound),
    DhtStore(DhtStore),
    DhtFetch(DhtFetch),
    DhtValue(DhtValue),
    HsRegister(HsRegister),
    HsLookup(HsLookup),
    HsFound(HsFound),
    HsHttpRequest(HsHttpRequest),
    HsHttpResponse(HsHttpResponse),
    BoardPost(BoardPost),
    BoardFetch(BoardFetch),
    BoardPosts(BoardPosts),
    Padding(Padding),
    CertRotate(CertRotate),
}

// ── Handshake ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallenge {
    pub challenge: String,
    pub min_bits:  u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub version:       u32,
    pub cert:          WireCert,
    pub admission_pow: AdmissionPoW,
    /// X25519 ephemeral public key (hex)
    pub ephem_pub:     String,
    /// ML-KEM-1024 encapsulation key (hex) — empty if not supported
    pub mlkem_pub:     String,
    /// Static X25519 public key for onion routing (hex)
    pub static_pub:    String,
    pub listen_port:   u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeAck {
    pub cert:          WireCert,
    pub admission_pow: AdmissionPoW,
    pub ephem_pub:     String,
    /// ML-KEM ciphertext (hex) — empty if not supported
    pub mlkem_ct:      String,
    pub static_pub:    String,
    pub listen_port:   u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reject {
    pub reason: String,
}

// ── Onion ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Onion {
    pub cell: String, // hex-encoded layered ciphertext
}

/// Real circuit cell: 512 bytes hex-encoded. Used for the production
/// circuit protocol (CREATE / CREATED / RELAY / RELAY_EARLY / DESTROY).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitCellMsg {
    pub data: String,
}

// ── DHT ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtFind {
    pub req_id: String,
    pub target: String, // node_id hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtFound {
    pub req_id: String,
    pub target: String,
    pub nodes:  Vec<DhtPeerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPeerInfo {
    pub node_id:    String,
    pub host:       String,
    pub port:       u16,
    pub cert:       WireCert,
    pub static_pub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStore {
    pub key:   String,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtFetch {
    pub req_id: String,
    pub key:    String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtValue {
    pub req_id: String,
    pub key:    String,
    pub value:  Option<Value>,
}

// ── Hidden service ────────────────────────────────────────────────────

/// A hidden-service descriptor published to the DHT. Clients fetch
/// this by `hs_id` to learn where to send INTRODUCE1 cells.
///
/// # Authenticity
///
/// The descriptor is signed by the HS's long-term Ed25519 identity
/// key. The `hs_id` is derived deterministically from that identity
/// key (see `hs_identity::HsIdentity::hs_id`), so a client who learns
/// the `hs_id` out-of-band (e.g. from a link the HS operator shares)
/// can verify that the fetched descriptor really originated from the
/// HS with that ID — an HSDir that tried to substitute a forged
/// descriptor would need to also produce a valid signature under the
/// identity key matching `hs_id`, which it cannot.
///
/// # Epoch blinding
///
/// To prevent HSDirs from correlating descriptors across time (and
/// thus from mapping long-term identities to observed queries), real
/// descriptor publication uses an epoch-specific **blinded** signing
/// key derived from the identity key plus the current epoch. Clients
/// blind the `hs_id` the same way to request the right copy. The
/// `identity_pub` field here is the long-term key; the `sig` is made
/// under the blinded subkey for `epoch`. See `hs_identity.rs` for the
/// derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsDescriptor {
    pub hs_id:      String,
    pub name:       String,
    pub intro_pub:  String,
    pub intro_host: Option<String>,
    pub intro_port: Option<u16>,
    /// HS long-term Ed25519 public key, hex-encoded. The `hs_id`
    /// must equal the derived ID of this key.
    #[serde(default)]
    pub identity_pub: String,
    /// Publication epoch (monotonic, ~daily granularity). Signatures
    /// are valid only for descriptors fetched within the same epoch.
    #[serde(default)]
    pub epoch: u64,
    /// Ed25519 signature under the blinded key for this epoch, over
    /// the canonical descriptor bytes (all fields above except sig).
    /// Hex-encoded 64 bytes.
    #[serde(default)]
    pub sig: String,
    /// Blinded Ed25519 public key used to verify `sig`. Clients
    /// check the signature against this key. The binding between
    /// `blinded_pub` and (`identity_pub`, `epoch`) depends on the
    /// blinding scheme — see hs_identity.rs. Hex-encoded 32 bytes.
    #[serde(default)]
    pub blinded_pub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsRegister {
    pub descriptor: HsDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsLookup {
    pub req_id:           String,
    pub hs_id:            String,
    pub puzzle_solution:  Option<IntroPuzzleSolution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsFound {
    pub req_id:     String,
    pub hs_id:      String,
    pub descriptor: Option<HsDescriptor>,
    pub puzzle:     Option<IntroPuzzle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsHttpRequest {
    pub req_id:   String,
    pub hs_id:    String,
    pub method:   String,
    pub path:     String,
    pub body_hex: String,
    pub headers:  std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsHttpResponse {
    pub req_id:   String,
    pub status:   u16,
    pub headers:  std::collections::HashMap<String, String>,
    pub body_hex: String,
}

// ── Board ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardPost {
    pub msg_id:    String,
    pub channel:   String,
    pub text:      String,
    pub ts:        u64,
    pub ephem_pub: String,
    pub mac:       String,
    pub cluster:   Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardFetch {
    pub req_id:  String,
    pub channel: String,
    pub limit:   u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardPosts {
    pub req_id:  String,
    pub channel: String,
    pub posts:   Vec<BoardPost>,
}

// ── Padding ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Padding {
    pub data: String, // hex-encoded random bytes
}

/// Announced when a node rotates its cert. The new cert identifies a
/// fresh node_id; continuity with the old identity is proven by
/// `link_sig`, an HMAC keyed by a secret derived from the old cert's
/// connection-session key. A receiving peer who already had an open
/// session with the old node_id verifies link_sig before replacing
/// its routing-table entry, so an attacker cannot hijack a peer by
/// broadcasting a forged CertRotate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRotate {
    /// Previous node_id, hex-encoded. Receiver uses this to look up
    /// which session's HMAC-salt to verify `link_sig` against.
    pub old_node_id: String,
    /// New node_id, hex-encoded. Derived from the new cert.
    pub new_node_id: String,
    /// The new cert's public fields in JSON (serialized `PhiCert`).
    /// Receiver verifies the math before trusting anything else.
    pub new_cert_json: String,
    /// Monotonic sequence number. Must strictly increase per old_node_id
    /// to prevent replay of an older rotation announcement.
    pub seq: u64,
    /// Unix timestamp of rotation (sanity only, not security-critical).
    pub ts: u64,
    /// Hex-encoded 32-byte HMAC-SHA256 over
    ///   (old_node_id || new_node_id || new_cert_json || seq || ts)
    /// keyed by a value derived from the session key shared with the
    /// peer. See node.rs `build_cert_rotate` / `verify_cert_rotate`.
    pub link_sig: String,
}
