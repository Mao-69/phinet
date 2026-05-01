// phinet-core/src/node.rs
//! ΦNET Node — the full async network entity.

use crate::{
    board::MessageBoard,
    cert::PhiCert,
    crypto::StaticKeypair,
    dht::{DhtStore, PeerInfo, RoutingTable},
    error::{Error, Result},
    hidden_service::HsManager,
    onion::{self},
    pow::{solve_admission, verify_admission, AdmissionPoW},
    session::{EphemeralKeypair, Session, TrafficPadder},
    store::SiteStore,
    wire::{
        self, BoardFetch, BoardPost, BoardPosts, DhtFind, DhtFound,
        DhtPeerInfo, DhtValue, Handshake,
        HandshakeAck, HsFound, HsLookup, Message, Onion, Padding,
        PowChallenge, Reject,
    },
};
use rand::{rngs::OsRng, RngCore};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock, atomic::{AtomicU64, Ordering}},
    time::Duration,
};
use tokio::{
    io::{BufReader, BufWriter},
    net::TcpListener,
    sync::{mpsc, Mutex, RwLock as ARwLock},
    time,
};
use tracing::{debug, info, warn};
use x25519_dalek::PublicKey;

pub const PROTOCOL_VERSION: u32    = 2;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
pub const ROTATE_INTERVAL:   Duration = Duration::from_secs(3600);
pub const PADDING_RATE_HZ:   f64      = 1.0;

// ── Peer connection ───────────────────────────────────────────────────

pub struct PeerConn {
    pub info:    PeerInfo,
    sender:      mpsc::Sender<Vec<u8>>,
    pub session: Arc<Session>,
}

impl PeerConn {
    pub async fn send_msg(&self, msg: &Message) -> Result<()> {
        let payload   = serde_json::to_vec(msg)?;
        let encrypted = self.session.encrypt(&payload);
        let mut frame = Vec::with_capacity(4 + encrypted.len());
        frame.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
        frame.extend_from_slice(&encrypted);
        self.sender.send(frame).await.map_err(|_| Error::Closed)
    }
}

// ── Node ──────────────────────────────────────────────────────────────

/// HS-side pending rendezvous action. Queued by `handle_introduce2`
/// after successful decrypt + AUTH derivation; drained by
/// `hs_rendezvous_drainer` which builds the RP circuit and sends
/// RENDEZVOUS1 through it.
struct HsRendezvousIntent {
    rp_node_id: [u8; 32],
    rp_host:    String,
    rp_port:    u16,
    cookie:     [u8; 20],
    server_y:   [u8; 32],
    auth:       [u8; crate::rendezvous::HS_AUTH_LEN],
    e2e_keys:   crate::rendezvous::E2EKeys,
}

pub struct PhiNode {
    pub host:    String,
    pub port:    u16,
    pub cert:    RwLock<PhiCert>,
    pub keypair: StaticKeypair,
    pub pow:     AdmissionPoW,

    pub routing: RoutingTable,
    pub dht:     DhtStore,
    pub board:   MessageBoard,
    pub hs_mgr:  HsManager,
    pub store:   Arc<SiteStore>,

    peers:  ARwLock<HashMap<[u8; 32], Arc<PeerConn>>>,
    guards: ARwLock<Vec<PeerInfo>>,

    /// Persistent guard tracking. Survives daemon restarts to prevent
    /// the first-hop rotation attack.
    pub guard_mgr: Arc<crate::guards::GuardManager>,

    /// Per-node state machine for multi-hop circuits (CREATE/EXTEND2/RELAY).
    /// Shared across all peer connections so a RelayCircuit on one
    /// incoming conn can forward to a different outgoing conn.
    pub circuits: ARwLock<crate::circuit_mgr::CircuitManager>,

    /// HS-side pending rendezvous intents. Each entry is an
    /// INTRODUCE2 we've decrypted and ready to act on. A background
    /// task drains these, builds circuits to the named RPs, and sends
    /// RENDEZVOUS1. Queue is bounded to prevent OOM from a flood of
    /// introductions.
    hs_pending_rendezvous: ARwLock<std::collections::VecDeque<HsRendezvousIntent>>,

    /// Monotonic sequence number for our own cert rotations.
    /// Starts at 0; each rotation broadcast increments and includes it,
    /// so peers can reject replays and out-of-order announcements.
    rotation_seq: AtomicU64,

    /// Last rotation sequence accepted per old-node-id. Guards against
    /// replay of a stale CertRotate: a peer who sees a valid rotation
    /// with seq=N will reject any later rotation from the same old_id
    /// with seq≤N.
    seen_rotation_seqs: ARwLock<HashMap<[u8; 32], u64>>,

    /// Persistent replay cache for gossip messages (DHT stores, HS
    /// descriptors, board posts). Entries have a TTL so the cache
    /// stays bounded across long-running nodes.
    pub replay_cache: Arc<crate::replay::ReplayCache>,

    /// Exit-side TCP write halves, keyed by (circ_id, stream_id). When
    /// we accept a BEGIN from a client and open a TCP connection, the
    /// write half goes here so subsequent DATA cells can be pumped
    /// into the socket. Read half is owned by a spawned task.
    exit_writers: ARwLock<HashMap<
        (crate::circuit::CircuitId, u16),
        Arc<Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>>
    >>,

    /// Exit policy: rules for which destinations this node will
    /// open TCP connections to when acting as an exit. Default
    /// blocks private ranges, loopback, and common abuse ports.
    /// Wrapped in RwLock so operators (and integration tests) can
    /// adjust the policy at runtime without restarting.
    pub exit_policy: RwLock<crate::exit_policy::ExitPolicy>,

    pub high_security: bool,

    /// Triggered by `shutdown()`. Background loops observe this via
    /// `shutdown.notified()` and exit cleanly. The accept loop in
    /// `run()` selects on this too, so a shutdown signal causes
    /// `run()` to return `Ok(())` rather than hang forever.
    ///
    /// Using `Notify` (not `oneshot`) so multiple tasks can observe
    /// the same signal — notify_waiters wakes all current waiters.
    shutdown: Arc<tokio::sync::Notify>,

    /// Set once the node has started shutting down. Background tasks
    /// check this on each loop iteration to avoid racing past the
    /// shutdown signal. Without this flag, a task that's mid-sleep
    /// when `shutdown()` is called could wake up and do one more
    /// iteration before seeing the Notify.
    shutdown_flag: Arc<std::sync::atomic::AtomicBool>,

    /// Pluggable transport for peer-to-peer connections. Default
    /// is `PlainTcp`. Operators in censored regions can swap in a
    /// `SubprocessTransport` wrapping obfs4proxy/meek-client/snowflake-client
    /// to disguise ΦNET traffic.
    ///
    /// **Currently used for outbound `connect()` only.** The accept
    /// loop in `run()` still binds a raw TCP listener — relays accept
    /// connections from many transports, and which one a peer dialed
    /// in on isn't visible here (the obfs is on the wire below us).
    /// Replacing the listener with `transport.listen()` is a
    /// straightforward extension when needed.
    pub transport: Arc<dyn crate::transport::Transport>,
}

impl PhiNode {
    pub fn new(host: &str, port: u16, cert: PhiCert, store: Arc<SiteStore>) -> Arc<Self> {
        let node_id = cert.node_id();
        let pow     = solve_admission(&cert).expect("admission PoW failed");
        Arc::new(PhiNode {
            host:    host.to_string(),
            port,
            cert:    RwLock::new(cert),
            keypair: StaticKeypair::generate(),
            pow,
            routing: RoutingTable::new(node_id),
            dht:     DhtStore::new(),
            board:   {
                let dir = dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join(".phinet");
                let path = dir.join("board.log");
                MessageBoard::open(path).unwrap_or_else(|e| {
                    warn!("board: persistence disabled: {}", e);
                    MessageBoard::new()
                })
            },
            hs_mgr:  HsManager::new(store.clone()),
            store,
            peers:         ARwLock::new(HashMap::new()),
            guards:        ARwLock::new(Vec::new()),
            guard_mgr: {
                let dir = dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join(".phinet");
                let path = dir.join("guards.json");
                Arc::new(crate::guards::GuardManager::open(path).unwrap_or_else(|e| {
                    warn!("guards: persistence disabled: {}", e);
                    crate::guards::GuardManager::open(
                        std::path::PathBuf::from("/tmp/phinet_guards.json")
                    ).unwrap()
                }))
            },
            circuits:      ARwLock::new(crate::circuit_mgr::CircuitManager::new()),
            hs_pending_rendezvous: ARwLock::new(std::collections::VecDeque::new()),
            rotation_seq:          AtomicU64::new(0),
            seen_rotation_seqs:    ARwLock::new(HashMap::new()),
            replay_cache: {
                let dir = dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join(".phinet");
                let path = dir.join("replay.log");
                // 24-hour TTL: long enough that legitimate delayed
                // messages still dedupe, short enough that the cache
                // doesn't grow unbounded.
                Arc::new(crate::replay::ReplayCache::open(path, 24 * 3600).unwrap_or_else(|e| {
                    warn!("replay: persistence disabled: {}", e);
                    crate::replay::ReplayCache::open(
                        std::path::PathBuf::from("/tmp/phinet_replay.log"),
                        24 * 3600,
                    ).unwrap()
                }))
            },
            exit_writers:  ARwLock::new(HashMap::new()),
            exit_policy:   RwLock::new(crate::exit_policy::ExitPolicy::default()),
            high_security: false,
            shutdown:      Arc::new(tokio::sync::Notify::new()),
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            transport: Arc::new(crate::transport::PlainTcp),
        })
    }

    pub fn node_id(&self) -> [u8; 32]  { self.cert.read().unwrap().node_id() }
    pub fn node_id_hex(&self) -> String { hex::encode(self.node_id()) }

    /// Current depth of the HS-side pending-rendezvous queue. Used by
    /// integration tests to confirm INTRODUCE2 decryption and intent
    /// enqueueing succeeded.
    pub async fn hs_rendezvous_pending_len(&self) -> usize {
        self.hs_pending_rendezvous.read().await.len()
    }

    /// Current public x25519 static key for this node. Needed by
    /// rendezvous clients that are told about us via a descriptor.
    pub fn static_pub(&self) -> [u8; 32] {
        self.keypair.public_bytes()
    }

    /// Snapshot of currently-connected peers' PeerInfo. Used primarily
    /// for diagnostics, CLI status output, and integration tests.
    pub async fn peers_snapshot(&self) -> Vec<crate::dht::PeerInfo> {
        self.peers.read().await.values()
            .map(|p| p.info.clone())
            .collect()
    }

    // ── Server ────────────────────────────────────────────────────────

    pub async fn run(self: Arc<Self>) -> Result<()> {
        let addr     = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("ΦNET node listening on {}", addr);
        info!("  node_id = {}…", &self.node_id_hex()[..16]);

        // Background tasks
        {
            let n = Arc::clone(&self);
            tokio::spawn(async move { n.guard_refresh_loop().await });
        }
        {
            let n = Arc::clone(&self);
            tokio::spawn(async move { n.rotation_loop().await });
        }
        {
            let n = Arc::clone(&self);
            tokio::spawn(async move { n.hs_republish_loop().await });
        }
        {
            let n = Arc::clone(&self);
            tokio::spawn(async move {
                loop {
                    // Race sleep against shutdown so the task doesn't
                    // linger ~5 minutes after a shutdown signal.
                    tokio::select! {
                        _ = time::sleep(Duration::from_secs(300)) => {}
                        _ = n.shutdown.notified() => break,
                    }
                    if n.is_shutting_down() { break; }
                    n.dht.evict_expired();
                    let dropped = n.replay_cache.evict_expired();
                    if dropped > 0 {
                        debug!("replay: evicted {} expired entries", dropped);
                    }
                    // Idle circuit eviction: reclaim state from
                    // circuits that haven't been used in
                    // CIRCUIT_IDLE_TIMEOUT. Without this, a daemon
                    // running for weeks accumulates dead circuits
                    // forever (each one holds ~KB of key state +
                    // stream mux).
                    let (o, r) = {
                        let mut mgr = n.circuits.write().await;
                        mgr.evict_idle_circuits()
                    };
                    if o > 0 || r > 0 {
                        info!("evicted {} idle origin circuits and {} idle relay circuits",
                              o, r);
                    }
                }
                debug!("gc loop: shutting down");
            });
        }
        {
            let n = Arc::clone(&self);
            tokio::spawn(async move { n.hs_rendezvous_drain_loop().await });
        }

        loop {
            // Select on accept vs shutdown so shutdown() causes a
            // clean return rather than an orphaned accept loop.
            tokio::select! {
                accept_result = listener.accept() => {
                    let (stream, addr) = accept_result?;
                    let node = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = node.handle_incoming(stream, addr).await {
                            debug!("incoming {}: {}", addr, e);
                        }
                    });
                }
                _ = self.shutdown.notified() => {
                    info!("ΦNET node on {} shutting down", addr);
                    return Ok(());
                }
            }
        }
    }

    /// Signal every background task to stop, so `run()` returns
    /// cleanly. Idempotent — calling twice is fine.
    ///
    /// After shutdown, the PhiNode is no longer usable for new
    /// work. Outstanding operations (pending handshakes, in-flight
    /// circuit-build ntor steps) complete or fail based on their
    /// own timeouts; this method doesn't block to drain them.
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        // notify_waiters wakes every task currently awaiting notified().
        // Tasks that later call notified() will see shutdown_flag set.
        self.shutdown.notify_waiters();
    }

    /// True if `shutdown()` has been called. Background tasks check
    /// this in their loops to avoid racing past the shutdown signal.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    // ── Handshake (responder) ─────────────────────────────────────────

    async fn handle_incoming<S>(self: Arc<Self>, stream: S, addr: SocketAddr) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Use tokio::io::split (works on any Unpin AsyncRead+AsyncWrite)
        // instead of TcpStream::into_split. The latter is only on
        // OwnedReadHalf/OwnedWriteHalf which are TCP-specific. Going
        // generic lets the same handler accept connections from
        // PlainTcp transport, obfs4 SOCKS5 streams, future TLS-wrapped
        // streams, etc — exactly what the Transport abstraction is for.
        let (r, w)  = tokio::io::split(stream);
        let mut rd  = BufReader::new(r);
        let mut wr  = BufWriter::new(w);

        wire::send_raw(&mut wr, &Message::PowChallenge(PowChallenge {
            challenge: hex::encode(rand_bytes(32)),
            min_bits:  256,
        })).await?;

        let msg = time::timeout(HANDSHAKE_TIMEOUT, wire::recv_raw(&mut rd))
            .await.map_err(|_| Error::Handshake("timeout".into()))??;
        let hs = match msg {
            Message::Handshake(h) => h,
            _ => return Err(Error::Handshake("expected HANDSHAKE".into())),
        };

        let peer_cert = PhiCert::from_wire(&hs.cert)
            .map_err(|e| Error::Handshake(format!("cert: {e}")))?;
        if !peer_cert.verify() {
            wire::send_raw(&mut wr, &Message::Reject(Reject { reason: "invalid cert".into() })).await?;
            return Err(Error::Handshake("invalid cert".into()));
        }
        if !verify_admission(&peer_cert, &hs.admission_pow) {
            wire::send_raw(&mut wr, &Message::Reject(Reject { reason: "invalid pow".into() })).await?;
            return Err(Error::Handshake("invalid PoW".into()));
        }

        let ephem_peer: [u8; 32] = hex::decode(&hs.ephem_pub)
            .ok().and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::Handshake("bad ephem_pub".into()))?;
        let our_ephem = EphemeralKeypair::generate();
        let shared    = our_ephem.dh(&PublicKey::from(ephem_peer));
        let session   = Arc::new(Session::new(&shared, false));

        let my_cert = self.cert.read().unwrap().clone();
        wire::send_raw(&mut wr, &Message::HandshakeAck(HandshakeAck {
            cert:          my_cert.to_wire(),
            admission_pow: self.pow.clone(),
            ephem_pub:     hex::encode(our_ephem.public_bytes()),
            mlkem_ct:      String::new(),
            static_pub:    hex::encode(self.keypair.public_bytes()),
            listen_port:   self.port,
        })).await?;

        let info = PeerInfo {
            node_id:    peer_cert.node_id(),
            host:       addr.ip().to_string(),
            port:       hs.listen_port,
            cert:       hs.cert,
            static_pub: hs.static_pub,
        };
        self.register_peer(info, session, rd, wr).await
    }

    // ── Connect (initiator) ───────────────────────────────────────────

    pub async fn connect(self: Arc<Self>, host: &str, port: u16) -> Result<()> {
        // Dial via the configured transport. Default is PlainTcp; an
        // operator running with obfs4 / meek / snowflake configured
        // gets the obfuscated bytes-on-wire here transparently.
        let stream = self.transport.dial(host, port).await
            .map_err(|e| Error::Handshake(format!("transport dial: {e}")))?;
        let (r, w)  = tokio::io::split(stream);
        let mut rd  = BufReader::new(r);
        let mut wr  = BufWriter::new(w);

        // Consume challenge
        let _ = wire::recv_raw(&mut rd).await?;

        let cert      = self.cert.read().unwrap().clone();
        let our_ephem = EphemeralKeypair::generate();
        wire::send_raw(&mut wr, &Message::Handshake(Handshake {
            version:       PROTOCOL_VERSION,
            cert:          cert.to_wire(),
            admission_pow: self.pow.clone(),
            ephem_pub:     hex::encode(our_ephem.public_bytes()),
            mlkem_pub:     String::new(),
            static_pub:    hex::encode(self.keypair.public_bytes()),
            listen_port:   self.port,
        })).await?;

        let msg = time::timeout(HANDSHAKE_TIMEOUT, wire::recv_raw(&mut rd))
            .await.map_err(|_| Error::Handshake("timeout".into()))??;
        let ack = match msg {
            Message::HandshakeAck(a) => a,
            Message::Reject(r)       => return Err(Error::Handshake(r.reason)),
            _ => return Err(Error::Handshake("expected ACK".into())),
        };

        let ephem_peer: [u8; 32] = hex::decode(&ack.ephem_pub)
            .ok().and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::Handshake("bad ephem_pub".into()))?;
        let shared  = our_ephem.dh(&PublicKey::from(ephem_peer));
        let session = Arc::new(Session::new(&shared, true));

        let peer_cert = PhiCert::from_wire(&ack.cert)?;
        let info      = PeerInfo {
            node_id:    peer_cert.node_id(),
            host:       host.to_string(),
            port,
            cert:       ack.cert,
            static_pub: ack.static_pub,
        };
        self.register_peer(info, session, rd, wr).await
    }

    // ── Peer registration ─────────────────────────────────────────────

    async fn register_peer<R, W>(
        self: Arc<Self>,
        info: PeerInfo,
        session: Arc<Session>,
        reader: BufReader<R>,
        writer: BufWriter<W>,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Reject connections to ourselves
        if info.node_id == self.node_id() {
            debug!("Rejected self-connection from {}:{}", info.host, info.port);
            return Err(Error::Handshake("self-connection rejected".into()));
        }

        // Reject already-connected peers
        if self.peers.read().await.contains_key(&info.node_id) {
            debug!("Already connected to {}…", &hex::encode(info.node_id)[..12]);
            return Ok(());
        }

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
        let peer = Arc::new(PeerConn {
            info: info.clone(),
            sender: tx,
            session: Arc::clone(&session),
        });

        self.routing.add_peer(info.clone());
        self.peers.write().await.insert(info.node_id, Arc::clone(&peer));
        info!("Peer {}…  @{}:{}", &hex::encode(info.node_id)[..12], info.host, info.port);

        // Persistent guard tracking: every outbound-initiated successful
        // connection is a candidate for becoming a guard, and any
        // connection to an already-chosen guard should be marked.
        self.guard_mgr.add_candidate(&info.node_id, &info.host, info.port);
        self.guard_mgr.mark_success(&info.node_id);
        self.guard_mgr.save_best_effort();

        // Writer task
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut wr = writer;
            while let Some(frame) = rx.recv().await {
                if wr.write_all(&frame).await.is_err() { break; }
                if wr.flush().await.is_err()           { break; }
            }
        });

        // Padding task
        if PADDING_RATE_HZ > 0.0 {
            let p = Arc::clone(&peer);
            tokio::spawn(async move {
                let interval = Duration::from_secs_f64(1.0 / PADDING_RATE_HZ);
                loop {
                    time::sleep(interval).await;
                    let _ = p.send_msg(&Message::Padding(Padding {
                        data: hex::encode(TrafficPadder::dummy_cell()),
                    })).await;
                }
            });
        }

        // Reader task
        let node    = Arc::clone(&self);
        let peer_id = info.node_id;
        let sess    = Arc::clone(&session);
        tokio::spawn(async move {
            let mut rd = reader;
            loop {
                match wire::recv_session(&mut rd, &sess).await {
                    Ok(msg)            => Arc::clone(&node).dispatch(msg, &peer).await,
                    Err(Error::Closed) => break,
                    Err(e)             => { debug!("peer: {}", e); break; }
                }
            }
            node.peers.write().await.remove(&peer_id);
            info!("Peer {}… disconnected", &hex::encode(peer_id)[..12]);
        });

        Ok(())
    }

    // ── Dispatch ──────────────────────────────────────────────────────

    async fn dispatch(self: Arc<Self>, msg: Message, src: &Arc<PeerConn>) {
        match msg {
            Message::Onion(o)       => self.handle_onion(o).await,
            Message::CircuitCell(c)  => self.handle_circuit_cell(c, src).await,
            Message::DhtFind(f)     => self.handle_dht_find(f, src).await,
            Message::DhtFound(f)    => self.handle_dht_found(f),
            Message::DhtStore(s)    => {
                // DHT store: the key uniquely identifies the record,
                // so (key|first 8 bytes of value) is a natural replay ID.
                let rid = format!("dht:{}", hex::encode(&s.key));
                if !self.replay_cache.mark(&rid) {
                    debug!("dht store: replay rejected {}", &rid[..24.min(rid.len())]);
                } else {
                    self.dht.put(s.key, s.value)
                }
            }
            Message::DhtFetch(f)    => self.handle_dht_fetch(f, src).await,
            Message::HsRegister(r)  => {
                // Verify the descriptor was signed by its claimed HS
                // identity before caching it. An attacker who controls
                // an HSDir or who gossips descriptors can't redirect
                // clients to attacker-controlled intros because the
                // binding hs_id → identity_pub → signature is enforced.
                //
                // Descriptors without signatures (identity_pub or sig
                // fields empty) are rejected — v1 of the network
                // requires signed descriptors.
                if let Err(e) = crate::hs_identity::verify_descriptor(&r.descriptor) {
                    debug!("hs register: reject unsigned/invalid descriptor for {}: {}",
                           r.descriptor.hs_id, e);
                    return;
                }
                let rid = format!("hs:{}", r.descriptor.hs_id);
                if !self.replay_cache.mark(&rid) {
                    debug!("hs register: replay rejected {}", r.descriptor.hs_id);
                } else {
                    self.dht.put_hs(&r.descriptor)
                }
            }
            Message::HsLookup(l)    => self.handle_hs_lookup(l, src).await,
            Message::BoardPost(p)   => self.handle_board_post(p, src).await,
            Message::BoardFetch(f)  => self.handle_board_fetch(f, src).await,
            Message::Padding(_)     => {} // cover traffic, discard
            Message::CertRotate(r)  => self.handle_cert_rotate(r, src).await,
            _                       => {}
        }
    }

    // ── Onion ─────────────────────────────────────────────────────────

    async fn handle_onion(&self, msg: Onion) {
        match onion::peel(&msg.cell, &self.keypair.secret, &self.host, self.port) {
            Ok((Some(nh), Some(np), inner)) => {
                let cell = Message::Onion(Onion { cell: hex::encode(&inner) });
                let peers = self.peers.read().await;
                for p in peers.values() {
                    if p.info.host == nh && p.info.port == np {
                        let _ = p.send_msg(&cell).await;
                        return;
                    }
                }
            }
            Ok((None, _, payload)) => {
                if let Ok(inner) = serde_json::from_slice::<Message>(&payload) {
                    if let Message::BoardPost(p) = inner {
                        self.board.post(&p.channel, &p.text, None);
                    }
                }
            }
            Ok(_) => {} // partial Some/None — malformed cell, discard
            Err(e) => debug!("onion peel: {}", e),
        }
    }

    // ── Circuit cell dispatch ─────────────────────────────────────────

    /// Send a 512-byte cell to a specific peer by its node_id. Used
    /// both by the manager's forwarding logic and by origin-circuit
    /// construction. Returns Err if the peer is no longer connected.
    pub async fn send_circuit_cell(
        &self,
        peer_id: &[u8; 32],
        cell_bytes: &[u8; crate::circuit::CELL_SIZE],
    ) -> Result<()> {
        let peers = self.peers.read().await;
        let peer = peers.get(peer_id)
            .ok_or_else(|| Error::Handshake("peer not connected".into()))?;
        peer.send_msg(&Message::CircuitCell(crate::wire::CircuitCellMsg {
            data: hex::encode(cell_bytes),
        })).await
    }

    /// Dispatch an incoming CircuitCell from `src`. Decodes, consults
    /// the CircuitManager for the appropriate action, and forwards or
    /// handles terminally.
    async fn handle_circuit_cell(
        self: Arc<Self>,
        msg: crate::wire::CircuitCellMsg,
        src: &Arc<PeerConn>,
    ) {
        use crate::circuit::{Cell, CellCommand, CELL_SIZE, CircuitId};
        use crate::circuit_mgr::RelayAction;

        let raw = match hex::decode(&msg.data) {
            Ok(r) if r.len() == CELL_SIZE => r,
            _ => { debug!("circuit: malformed cell"); return; }
        };
        let mut cell_bytes = [0u8; CELL_SIZE];
        cell_bytes.copy_from_slice(&raw);
        let cell = match Cell::from_bytes(&cell_bytes) {
            Ok(c) => c,
            Err(e) => { debug!("circuit: parse: {}", e); return; }
        };
        let from_peer = src.info.node_id;

        match cell.command {
            CellCommand::Create => {
                // Peer is starting a circuit with us as guard-hop.
                let client_msg_bytes = &cell.payload[..crate::ntor::CLIENT_HANDSHAKE_LEN];
                let mut cmsg = [0u8; crate::ntor::CLIENT_HANDSHAKE_LEN];
                cmsg.copy_from_slice(client_msg_bytes);

                let mut mgr = self.circuits.write().await;
                let my_id  = self.node_id();
                let my_pub = self.keypair.public_bytes();
                match mgr.handle_create(
                    from_peer, cell.circ_id,
                    &my_id, &my_pub, &self.keypair.secret,
                    &cmsg,
                ) {
                    Ok(reply_bytes) => {
                        drop(mgr);
                        let _ = self.send_circuit_cell(&from_peer, &reply_bytes).await;
                    }
                    Err(e) => debug!("handle_create: {}", e),
                }
            }

            CellCommand::Created => {
                // Reply to a circuit we originated (we are client).
                // If instead this is for a circuit we're extending on
                // behalf of another client, wrap as EXTENDED2 and send
                // back on the previous hop.
                let server_reply_bytes = &cell.payload[..crate::ntor::SERVER_HANDSHAKE_LEN];
                let mut reply = [0u8; crate::ntor::SERVER_HANDSHAKE_LEN];
                reply.copy_from_slice(server_reply_bytes);

                let mut mgr = self.circuits.write().await;
                // Check: is this circuit one we originated directly?
                if mgr.origins.contains_key(&cell.circ_id) {
                    if let Err(e) = mgr.handle_created(cell.circ_id, &reply) {
                        debug!("handle_created (origin): {}", e);
                    }
                    return;
                }
                // Otherwise: maybe we're extending on behalf of a client.
                match mgr.handle_created_from_next(from_peer, cell.circ_id, &reply) {
                    Ok((prev_peer, bytes)) => {
                        drop(mgr);
                        let _ = self.send_circuit_cell(&prev_peer, &bytes).await;
                    }
                    Err(e) => debug!("handle_created_from_next: {}", e),
                }
            }

            CellCommand::Relay | CellCommand::RelayEarly => {
                // Forward direction from client OR backward direction
                // from next hop. Disambiguate by which table the
                // circuit is in.
                let mgr_read = self.circuits.read().await;
                let is_origin   = mgr_read.origins.contains_key(&cell.circ_id);
                let is_relay_fw = mgr_read.relays.contains_key(&(from_peer, cell.circ_id));
                let is_relay_bw = mgr_read.relay_by_next
                    .contains_key(&(from_peer, cell.circ_id));
                drop(mgr_read);

                if is_origin {
                    let mut mgr = self.circuits.write().await;
                    match mgr.handle_origin_relay(cell.circ_id, &cell.payload) {
                        Ok(None) => {} // EXTENDED2 consumed
                        Ok(Some((_hop, rc))) => {
                            use crate::circuit::RelayCommand;
                            match rc.command {
                                // HS side: intro relay confirmed our ESTABLISH_INTRO
                                RelayCommand::IntroEstablished => {
                                    debug!("intro point confirmed on circ {:?}", cell.circ_id);
                                }
                                // Client side: RP confirmed our ESTABLISH_RENDEZVOUS
                                RelayCommand::RendezvousEstablished => {
                                    debug!("rendezvous established on circ {:?}", cell.circ_id);
                                }
                                // HS side: INTRODUCE2 received on our intro circuit
                                RelayCommand::Introduce2 => {
                                    drop(mgr);
                                    self.handle_introduce2(cell.circ_id, &rc.data).await;
                                }
                                // Client side: RP delivered RENDEZVOUS2 with HS's reply
                                RelayCommand::Rendezvous2 => {
                                    drop(mgr);
                                    self.handle_rendezvous2(cell.circ_id, &rc.data).await;
                                }
                                // Client side: intro acknowledged delivery
                                RelayCommand::IntroduceAck => {
                                    debug!("introduce1 delivered on circ {:?}", cell.circ_id);
                                }

                                // Stream-layer cells: route to the per-circuit
                                // StreamMux. Each stream_id within a circuit
                                // identifies one application-level connection.
                                RelayCommand::Connected => {
                                    let streams = mgr.origins.get(&cell.circ_id)
                                        .map(|c| Arc::clone(&c.streams));
                                    drop(mgr);
                                    if let Some(m) = streams {
                                        let _ = m.with_stream(rc.stream_id, |s| {
                                            if let Err(e) = s.on_connected() {
                                                debug!("connected: {}", e);
                                            }
                                        }).await;
                                    }
                                }
                                RelayCommand::Data => {
                                    let streams = mgr.origins.get(&cell.circ_id)
                                        .map(|c| Arc::clone(&c.streams));
                                    // We also need to bump the
                                    // circuit-level delivered count.
                                    // Grab write access first so we
                                    // can check in the same critical
                                    // section — avoids a race where
                                    // two threads both think they
                                    // need to emit the sendme.
                                    let circ_sendme_due = mgr.origins
                                        .get_mut(&cell.circ_id)
                                        .map(|oc| {
                                            let due = oc.note_circ_delivered();
                                            if due { oc.reset_circ_delivered(); }
                                            due
                                        })
                                        .unwrap_or(false);
                                    drop(mgr);
                                    if let Some(m) = streams {
                                        // Per-stream delivery and
                                        // SENDME emission.
                                        let result = m.with_stream(rc.stream_id, |s| {
                                            s.on_data(&rc.data)
                                        }).await;
                                        if let Some(Ok(true)) = result {
                                            let _ = self.send_origin_relay(
                                                cell.circ_id,
                                                RelayCommand::SendMe,
                                                Vec::new(),
                                            ).await;
                                        }
                                    }
                                    // Circuit-level SENDME. Uses
                                    // stream_id = 0 as the
                                    // circuit-level convention
                                    // (which is what send_origin_relay
                                    // stamps by default).
                                    if circ_sendme_due {
                                        let _ = self.send_origin_relay(
                                            cell.circ_id,
                                            RelayCommand::SendMe,
                                            Vec::new(),
                                        ).await;
                                    }
                                }
                                RelayCommand::SendMe => {
                                    // stream_id == 0 is a circuit-
                                    // level SENDME, refilling the
                                    // circuit's outbound window.
                                    // stream_id != 0 refills a single
                                    // stream's window.
                                    if rc.stream_id == 0 {
                                        if let Some(oc) = mgr.origins
                                            .get_mut(&cell.circ_id)
                                        {
                                            oc.on_circ_sendme();
                                        }
                                        drop(mgr);
                                    } else {
                                        let streams = mgr.origins.get(&cell.circ_id)
                                            .map(|c| Arc::clone(&c.streams));
                                        drop(mgr);
                                        if let Some(m) = streams {
                                            m.with_stream(rc.stream_id, |s| s.on_sendme()).await;
                                        }
                                    }
                                }
                                RelayCommand::End => {
                                    let reason = rc.data.first().copied().unwrap_or(0);
                                    let streams = mgr.origins.get(&cell.circ_id)
                                        .map(|c| Arc::clone(&c.streams));
                                    drop(mgr);
                                    if let Some(m) = streams {
                                        m.with_stream(rc.stream_id, |s| {
                                            s.close(crate::stream::EndReason::from_byte(reason));
                                        }).await;
                                        // After both directions acked, clean up.
                                        // (For now, close on first END.)
                                        m.remove(rc.stream_id).await;
                                    }
                                }

                                _ => {
                                    debug!("origin cell cmd={:?} stream={}",
                                           rc.command, rc.stream_id);
                                }
                            }
                        }
                        Err(e) => debug!("origin relay: {}", e),
                    }
                    return;
                }

                if is_relay_bw {
                    // Backward cell: wrap and forward to previous peer.
                    let mut mgr = self.circuits.write().await;
                    if let Some((prev_peer, bytes)) = mgr.handle_backward_relay(
                        from_peer, cell.circ_id, cell.clone()
                    ) {
                        drop(mgr);
                        let _ = self.send_circuit_cell(&prev_peer, &bytes).await;
                    }
                    return;
                }

                if is_relay_fw {
                    let mut mgr = self.circuits.write().await;
                    let action  = mgr.handle_forward_relay(
                        from_peer, cell.circ_id, cell.clone(),
                    );
                    match action {
                        RelayAction::Handle(relay) => {
                            use crate::circuit::RelayCommand;
                            match relay.command {
                                RelayCommand::Extend2 => {
                                    let next = match crate::circuit::parse_extend2(&relay.data) {
                                        Ok((ls, _)) => ls,
                                        Err(e) => { debug!("parse extend2: {}", e); return; }
                                    };
                                    let next_cid = CircuitId(
                                        rand_u32() | 0x8000_0000
                                    );
                                    match mgr.begin_extend(
                                        from_peer, cell.circ_id,
                                        next.node_id, next_cid, &relay.data,
                                    ) {
                                        Ok(bytes) => {
                                            drop(mgr);
                                            if !self.peers.read().await
                                                    .contains_key(&next.node_id)
                                            {
                                                debug!("extend: next hop {} not connected",
                                                       hex::encode(&next.node_id[..6]));
                                                return;
                                            }
                                            let _ = self.send_circuit_cell(
                                                &next.node_id, &bytes).await;
                                        }
                                        Err(e) => debug!("begin_extend: {}", e),
                                    }
                                }

                                // Someone's HS is declaring this circuit as its
                                // intro point. Record the auth key so we know
                                // how to forward INTRODUCE1 cells later.
                                RelayCommand::EstablishIntro => {
                                    match crate::rendezvous::EstablishIntro::decode(&relay.data) {
                                        Ok(msg) => {
                                            mgr.register_intro_relay(
                                                from_peer, cell.circ_id, msg.auth_key_pub);
                                            drop(mgr);
                                            self.send_intro_established(from_peer, cell.circ_id).await;
                                        }
                                        Err(e) => debug!("establish_intro: {}", e),
                                    }
                                }

                                // Client is asking us (as an RP) to hold their
                                // cookie and splice when HS arrives.
                                RelayCommand::EstablishRendezvous => {
                                    match crate::rendezvous::EstablishRendezvous::decode(&relay.data) {
                                        Ok(msg) => {
                                            mgr.register_rendezvous_cookie(
                                                msg.cookie, from_peer, cell.circ_id);
                                            drop(mgr);
                                            self.send_rendezvous_established(from_peer, cell.circ_id).await;
                                        }
                                        Err(e) => debug!("establish_rendezvous: {}", e),
                                    }
                                }

                                // Client sent INTRODUCE1 to us as intro relay.
                                // Look up which HS circuit this auth_key maps to
                                // and forward the blob as INTRODUCE2.
                                RelayCommand::Introduce1 => {
                                    match crate::rendezvous::Introduce::decode(&relay.data) {
                                        Ok(intro_msg) => {
                                            let target = mgr.find_intro_target(&intro_msg.auth_key_pub);
                                            drop(mgr);
                                            match target {
                                                Some((hs_peer, hs_cid)) => {
                                                    self.forward_introduce2(
                                                        hs_peer, hs_cid, &relay.data).await;
                                                    // ACK back to client on THEIR circuit
                                                    self.send_introduce_ack(from_peer, cell.circ_id).await;
                                                }
                                                None => {
                                                    debug!("introduce1: no matching intro for auth_key");
                                                }
                                            }
                                        }
                                        Err(e) => debug!("introduce1 decode: {}", e),
                                    }
                                }

                                // HS sent RENDEZVOUS1 to us as RP. Look up cookie,
                                // splice to the client's circuit as RENDEZVOUS2.
                                RelayCommand::Rendezvous1 => {
                                    match crate::rendezvous::Rendezvous1::decode(&relay.data) {
                                        Ok(r1) => {
                                            let target = mgr.consume_rendezvous_cookie(&r1.cookie);
                                            drop(mgr);
                                            match target {
                                                Some((client_peer, client_cid)) => {
                                                    self.splice_rendezvous2(
                                                        client_peer, client_cid,
                                                        &r1.server_y, &r1.auth).await;
                                                }
                                                None => {
                                                    debug!("rendezvous1: unknown cookie");
                                                }
                                            }
                                        }
                                        Err(e) => debug!("rendezvous1 decode: {}", e),
                                    }
                                }

                                // Exit side: client asked us to open a
                                // TCP connection to the named target. We
                                // parse the target, open TCP, record a
                                // stream in the relay-circuit mux, and
                                // kick off a forwarding task that pumps
                                // bytes between TCP and circuit.
                                RelayCommand::Begin => {
                                    drop(mgr);
                                    Arc::clone(&self).handle_exit_begin(
                                        from_peer, cell.circ_id,
                                        relay.stream_id,
                                        &relay.data,
                                    ).await;
                                }

                                // Exit side: DATA from client on an open
                                // stream — write to the TCP socket.
                                RelayCommand::Data => {
                                    drop(mgr);
                                    self.handle_exit_data(
                                        from_peer, cell.circ_id,
                                        relay.stream_id,
                                        &relay.data,
                                    ).await;
                                }

                                // Exit side: client closed a stream.
                                RelayCommand::End => {
                                    drop(mgr);
                                    self.handle_exit_end(
                                        from_peer, cell.circ_id,
                                        relay.stream_id,
                                    ).await;
                                }

                                // Exit side: client acknowledged our DATA.
                                RelayCommand::SendMe => {
                                    drop(mgr);
                                    self.handle_exit_sendme(
                                        from_peer, cell.circ_id,
                                        relay.stream_id,
                                    ).await;
                                }

                                other => {
                                    debug!("relay handle: unexpected cmd {:?}", other);
                                }
                            }
                        }
                        RelayAction::Forward(next_peer, bytes) => {
                            drop(mgr);
                            let _ = self.send_circuit_cell(&next_peer, &bytes).await;
                        }
                        RelayAction::Drop => {}
                    }
                    return;
                }

                debug!("relay cell on unknown circuit id={:?}", cell.circ_id);
            }

            CellCommand::Destroy => {
                let mut mgr = self.circuits.write().await;
                mgr.destroy(from_peer, cell.circ_id);
            }

            _ => {
                debug!("circuit cell: unsupported cmd {:?}", cell.command);
            }
        }
    }

    // ── Rendezvous helpers ────────────────────────────────────────────
    //
    // These send single relay cells toward specific peers and circuits.
    // They share a pattern:
    //   1. Build a RelayCell with the desired command and data
    //   2. Stamp the backward digest at our hop state
    //   3. Layered-encrypt backward to the target
    //   4. Send the enclosing Cell over the peer connection

    /// Send RELAY_INTRO_ESTABLISHED backward on a relay circuit to
    /// confirm to the HS that we've registered as its intro point.
    async fn send_intro_established(&self, to_peer: [u8; 32], cid: crate::circuit::CircuitId) {
        self.send_backward_relay(
            to_peer, cid,
            crate::circuit::RelayCommand::IntroEstablished,
            Vec::new(),
        ).await;
    }

    /// Send RELAY_RENDEZVOUS_ESTABLISHED backward on a relay circuit
    /// to confirm to the client we've registered their cookie.
    async fn send_rendezvous_established(&self, to_peer: [u8; 32], cid: crate::circuit::CircuitId) {
        self.send_backward_relay(
            to_peer, cid,
            crate::circuit::RelayCommand::RendezvousEstablished,
            Vec::new(),
        ).await;
    }

    /// Send RELAY_INTRODUCE_ACK backward to a client after forwarding
    /// their INTRODUCE1 as INTRODUCE2 to the HS.
    async fn send_introduce_ack(&self, to_peer: [u8; 32], cid: crate::circuit::CircuitId) {
        self.send_backward_relay(
            to_peer, cid,
            crate::circuit::RelayCommand::IntroduceAck,
            Vec::new(),
        ).await;
    }

    /// Forward an INTRODUCE1 body as INTRODUCE2 on the HS-facing
    /// circuit. We're acting as intro relay; the HS established the
    /// circuit ending at us and is now expecting INTRODUCE2 cells
    /// backward.
    async fn forward_introduce2(
        &self,
        hs_peer: [u8; 32],
        hs_cid: crate::circuit::CircuitId,
        data: &[u8],
    ) {
        self.send_backward_relay(
            hs_peer, hs_cid,
            crate::circuit::RelayCommand::Introduce2,
            data.to_vec(),
        ).await;
    }

    /// Splice: send RELAY_RENDEZVOUS2(Y, AUTH) backward on the client's
    /// circuit. We're acting as RP; client built circuit to us and is
    /// blocked waiting for this cell.
    async fn splice_rendezvous2(
        &self,
        client_peer: [u8; 32],
        client_cid: crate::circuit::CircuitId,
        server_y: &[u8; 32],
        auth: &[u8; crate::rendezvous::HS_AUTH_LEN],
    ) {
        let r2 = crate::rendezvous::Rendezvous2 {
            server_y: *server_y,
            auth:     *auth,
        };
        self.send_backward_relay(
            client_peer, client_cid,
            crate::circuit::RelayCommand::Rendezvous2,
            r2.encode(),
        ).await;
    }

    /// Internal: build a backward-direction relay cell on a relay
    /// circuit (we are mid-hop), stamp digest, encrypt our backward
    /// layer, wrap in a Cell, and send to the previous peer.
    async fn send_backward_relay(
        &self,
        to_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        cmd: crate::circuit::RelayCommand,
        data: Vec<u8>,
    ) {
        use crate::circuit::{Cell, CellCommand, RelayCell, onion_encrypt_backward};
        let relay = match RelayCell::new(cmd, 0, data) {
            Ok(r) => r,
            Err(e) => { debug!("send_backward_relay: build: {}", e); return; }
        };

        let mut mgr = self.circuits.write().await;
        let Some(rc) = mgr.relays.get_mut(&(to_peer, cid)) else {
            debug!("send_backward_relay: no relay circuit for {:?}", cid);
            return;
        };

        let mut relay = relay;
        relay.stamp_digest(&mut rc.hop.backward_digest);
        let mut payload = relay.to_payload();
        onion_encrypt_backward(&mut rc.hop, &mut payload);
        let prev_peer    = rc.prev_peer;
        let prev_cid     = rc.prev_circ_id;
        drop(mgr);

        let out_cell = Cell { circ_id: prev_cid, command: CellCommand::Relay, payload };
        let _ = self.send_circuit_cell(&prev_peer, &out_cell.to_bytes()).await;
    }

    /// Internal: same as send_backward_relay but preserves a stream_id
    /// on the relay cell. Used for exit-side responses (CONNECTED,
    /// DATA backward, END) that must carry the client's original
    /// stream_id so the origin can route to the right Stream.
    async fn send_backward_relay_stream(
        &self,
        to_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        cmd: crate::circuit::RelayCommand,
        stream_id: u16,
        data: Vec<u8>,
    ) {
        use crate::circuit::{Cell, CellCommand, RelayCell, onion_encrypt_backward};
        let relay = match RelayCell::new(cmd, stream_id, data) {
            Ok(r) => r,
            Err(e) => { debug!("send_backward_relay_stream: build: {}", e); return; }
        };

        let mut mgr = self.circuits.write().await;
        let Some(rc) = mgr.relays.get_mut(&(to_peer, cid)) else {
            debug!("send_backward_relay_stream: no relay circuit");
            return;
        };

        let mut relay = relay;
        relay.stamp_digest(&mut rc.hop.backward_digest);
        let mut payload = relay.to_payload();
        onion_encrypt_backward(&mut rc.hop, &mut payload);
        let prev_peer = rc.prev_peer;
        let prev_cid  = rc.prev_circ_id;
        drop(mgr);

        let out = Cell { circ_id: prev_cid, command: CellCommand::Relay, payload };
        let _ = self.send_circuit_cell(&prev_peer, &out.to_bytes()).await;
    }

    // ── Exit-side stream handlers ─────────────────────────────────────

    /// Exit handler: client sent RELAY_BEGIN("host:port\0") on a new
    /// stream. We parse the target, open a TCP connection, register
    /// the stream in the relay circuit's mux, reply with RELAY_CONNECTED,
    /// and spawn a bidirectional pump task that bridges the TCP socket
    /// to the circuit.
    ///
    /// On failure (bad target, connection refused, etc.) we send back
    /// RELAY_END with an appropriate reason.
    async fn handle_exit_begin(
        self: Arc<Self>,
        from_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        data: &[u8],
    ) {
        // Parse null-terminated "host:port" target
        let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
        let target = match std::str::from_utf8(&data[..end]) {
            Ok(s) => s.to_string(),
            Err(_) => {
                self.send_exit_end(from_peer, cid, stream_id,
                    crate::stream::EndReason::Internal).await;
                return;
            }
        };

        // Policy: pre-resolve check for IP literals + port blocklist.
        if self.exit_policy.read().unwrap().check_pre_resolve(&target) ==
            crate::exit_policy::Decision::Reject
        {
            debug!("exit policy rejected: {}", target);
            self.send_exit_end(from_peer, cid, stream_id,
                crate::stream::EndReason::ExitPolicy).await;
            return;
        }

        // Try to connect
        let tcp = match tokio::time::timeout(
            Duration::from_secs(15),
            tokio::net::TcpStream::connect(&target),
        ).await {
            Ok(Ok(t))  => t,
            Ok(Err(e)) => {
                debug!("exit begin: connect {}: {}", target, e);
                self.send_exit_end(from_peer, cid, stream_id,
                    crate::stream::EndReason::Unreachable).await;
                return;
            }
            Err(_) => {
                self.send_exit_end(from_peer, cid, stream_id,
                    crate::stream::EndReason::Timeout).await;
                return;
            }
        };

        // Post-resolve check: DNS might have returned a private IP.
        if let Ok(peer) = tcp.peer_addr() {
            if self.exit_policy.read().unwrap().check_post_resolve(&peer) ==
                crate::exit_policy::Decision::Reject
            {
                debug!("exit policy rejected after resolve: {} -> {}",
                       target, peer);
                self.send_exit_end(from_peer, cid, stream_id,
                    crate::stream::EndReason::ExitPolicy).await;
                return;
            }
        }

        info!("exit: stream {} opened to {}", stream_id, target);

        // Register stream in the relay circuit's mux
        let streams = {
            let mgr = self.circuits.read().await;
            mgr.relays.get(&(from_peer, cid))
                .map(|rc| Arc::clone(&rc.exit_streams))
        };
        let Some(streams) = streams else {
            debug!("exit begin: relay circuit vanished");
            return;
        };
        let _rx = streams.accept_stream(stream_id, target).await;

        // Reply CONNECTED upstream
        self.send_exit_relay(
            from_peer, cid, crate::circuit::RelayCommand::Connected,
            stream_id, Vec::new(),
        ).await;

        // Split the TCP stream into read/write halves and spawn a pump.
        let (mut tcp_read, tcp_write) = tokio::io::split(tcp);
        let tcp_write = Arc::new(Mutex::new(tcp_write));

        // Store the write half on the node so handle_exit_data can reach it.
        self.exit_writers.write().await
            .insert((cid, stream_id), Arc::clone(&tcp_write));

        // Spawn reader task: TCP -> circuit (as DATA cells backward).
        let node = Arc::clone(&self);
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; crate::circuit::RELAY_DATA_MAX];
            loop {
                let n = match tcp_read.read(&mut buf).await {
                    Ok(0) => {
                        // EOF from target — close stream
                        node.send_exit_end(from_peer, cid, stream_id,
                            crate::stream::EndReason::Done).await;
                        break;
                    }
                    Ok(n) => n,
                    Err(_) => {
                        node.send_exit_end(from_peer, cid, stream_id,
                            crate::stream::EndReason::Unreachable).await;
                        break;
                    }
                };
                // Consume the relay circuit's backward-direction
                // window slot. If exhausted, the exit stalls on this
                // iteration until the client sends a circuit SENDME
                // (which we handle in handle_exit_sendme). We don't
                // block the TCP read — we just poll periodically until
                // a slot frees up. This means a slow client can
                // backpressure the exit's TCP reads, which is exactly
                // what flow control should do.
                loop {
                    let ok = {
                        let mut mgr = node.circuits.write().await;
                        mgr.relays.get_mut(&(from_peer, cid))
                            .map(|rc| rc.try_consume_circ_window())
                    };
                    match ok {
                        Some(Ok(())) => break,
                        Some(Err(_)) => {
                            // Window exhausted; wait briefly for a SENDME.
                            tokio::time::sleep(
                                std::time::Duration::from_millis(10)
                            ).await;
                        }
                        None => {
                            // Circuit went away underneath us.
                            return;
                        }
                    }
                }
                node.send_exit_relay(
                    from_peer, cid, crate::circuit::RelayCommand::Data,
                    stream_id, buf[..n].to_vec(),
                ).await;
            }
            // Clean up writer entry on exit
            node.exit_writers.write().await.remove(&(cid, stream_id));
        });
    }

    async fn handle_exit_data(
        &self,
        from_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        data: &[u8],
    ) {
        use tokio::io::AsyncWriteExt;
        let writer = self.exit_writers.read().await
            .get(&(cid, stream_id)).cloned();
        if let Some(w) = writer {
            let mut w = w.lock().await;
            if let Err(e) = w.write_all(data).await {
                debug!("exit data: write: {}", e);
            }
        }

        // Bump the relay circuit's delivered counter. When it
        // crosses CIRCUIT_SENDME_DELIVERED, emit a circuit-level
        // SENDME back toward the client so its outbound circuit
        // window gets refilled. Without this, the client's
        // `try_consume_circ_window` would eventually hit 0 and stall.
        let circ_sendme_due = {
            let mut mgr = self.circuits.write().await;
            mgr.relays.get_mut(&(from_peer, cid))
                .map(|rc| {
                    let due = rc.note_circ_delivered();
                    if due { rc.reset_circ_delivered(); }
                    due
                })
                .unwrap_or(false)
        };
        if circ_sendme_due {
            // stream_id = 0 → circuit-level SENDME
            self.send_backward_relay_stream(
                from_peer, cid,
                crate::circuit::RelayCommand::SendMe,
                0,              // stream_id = 0 for circuit-level
                Vec::new(),
            ).await;
        }
    }

    async fn handle_exit_end(
        &self,
        from_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        stream_id: u16,
    ) {
        // Drop the TCP write half — the reader task will see the
        // half-close and exit.
        self.exit_writers.write().await.remove(&(cid, stream_id));
        let streams = {
            let mgr = self.circuits.read().await;
            mgr.relays.get(&(from_peer, cid))
                .map(|rc| Arc::clone(&rc.exit_streams))
        };
        if let Some(m) = streams {
            m.remove(stream_id).await;
        }
    }

    async fn handle_exit_sendme(
        &self,
        from_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        stream_id: u16,
    ) {
        // stream_id = 0 is a circuit-level SENDME, refilling the
        // relay circuit's backward (exit→client) window. stream_id
        // != 0 refills the stream's own window.
        if stream_id == 0 {
            let mut mgr = self.circuits.write().await;
            if let Some(rc) = mgr.relays.get_mut(&(from_peer, cid)) {
                rc.on_circ_sendme();
            }
        } else {
            let streams = {
                let mgr = self.circuits.read().await;
                mgr.relays.get(&(from_peer, cid))
                    .map(|rc| Arc::clone(&rc.exit_streams))
            };
            if let Some(m) = streams {
                m.with_stream(stream_id, |s| s.on_sendme()).await;
            }
        }
    }

    /// Shorthand for sending a single relay cell backward from the
    /// exit with a specified stream_id.
    async fn send_exit_relay(
        &self,
        to_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        cmd: crate::circuit::RelayCommand,
        stream_id: u16,
        data: Vec<u8>,
    ) {
        self.send_backward_relay_stream(to_peer, cid, cmd, stream_id, data).await;
    }

    /// Send RELAY_END backward with the given reason byte.
    async fn send_exit_end(
        &self,
        to_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        reason: crate::stream::EndReason,
    ) {
        self.send_backward_relay_stream(
            to_peer, cid,
            crate::circuit::RelayCommand::End,
            stream_id,
            vec![reason as u8],
        ).await;
    }

    /// HS side: we received INTRODUCE2 on one of our intro circuits.
    /// Decrypt the payload using our static HS key, extract the RP
    /// info, cookie, and client ephemeral X. Build a 3-hop circuit to
    /// the RP, run the e2e handshake, and send RENDEZVOUS1 carrying
    /// (cookie, Y, AUTH) through the RP circuit.
    ///
    /// If we don't yet have a connection to the RP, we note the
    /// intent and log — a real deployment would consult the consensus
    /// for path selection and pre-connect; here we rely on the HS
    /// operator to have pre-connected to candidate RPs.
    /// HS side: we received INTRODUCE2 on one of our intro circuits.
    /// Decrypt the payload using our static HS key, extract the RP
    /// info, cookie, and client ephemeral X. Run the e2e handshake to
    /// obtain Y and AUTH, then enqueue an `HsRendezvousIntent` for the
    /// background drainer to act on (build RP circuit, send RENDEZVOUS1).
    ///
    /// We enqueue rather than acting inline to avoid an async-recursion
    /// cycle (`build_circuit` requires `Arc<Self>`). The drainer runs
    /// from `run()` with a fresh Arc captured at startup.
    async fn handle_introduce2(&self, _intro_cid: crate::circuit::CircuitId, data: &[u8]) {
        let intro = match crate::rendezvous::Introduce::decode(data) {
            Ok(i) => i,
            Err(e) => { debug!("introduce2 decode: {}", e); return; }
        };

        // HS static keys = the node's connection-level identity keys.
        let hs_b_sec = self.keypair.secret.clone();
        let hs_b_pub = self.keypair.public_bytes();

        let plain = match intro.open_at_hs(&hs_b_sec, &hs_b_pub) {
            Ok(p) => p,
            Err(e) => { debug!("introduce2 open (MAC/decrypt): {}", e); return; }
        };

        info!("HS: accepted INTRODUCE2, RP={}:{} cookie={}",
              plain.rp_host, plain.rp_port,
              hex::encode(&plain.cookie[..6]));

        let (e2e_keys, y_pub, auth) = crate::rendezvous::hs_finalize(
            &hs_b_sec, &hs_b_pub, &intro.client_ntor_x);

        let intent = HsRendezvousIntent {
            rp_node_id: plain.rp_node_id,
            rp_host:    plain.rp_host,
            rp_port:    plain.rp_port,
            cookie:     plain.cookie,
            server_y:   y_pub,
            auth,
            e2e_keys,
        };

        // Cap the queue so an adversarial intro relay can't flood us.
        let mut q = self.hs_pending_rendezvous.write().await;
        if q.len() >= 64 {
            debug!("HS: rendezvous queue full, dropping intent");
            return;
        }
        q.push_back(intent);
    }

    /// Background loop: drain the HS pending-rendezvous queue. For
    /// each queued intent, build a circuit to the RP and send
    /// RENDEZVOUS1. On success, install the e2e keys on the built
    /// circuit.
    ///
    /// This is the owner of `Arc<Self>` that `build_circuit` needs
    /// — which is why we decouple it from the cell-dispatch path.
    ///
    /// Runs every 100 ms while the queue has entries, otherwise
    /// sleeps 1 s. Each intent gets one attempt; failure logs and
    /// drops. For production, add a retry counter and exponential
    /// backoff; for now a failed RP just means the client's cookie
    /// goes stale and they retry with a different RP.
    async fn hs_rendezvous_drain_loop(self: Arc<Self>) {
        loop {
            let intent = {
                let mut q = self.hs_pending_rendezvous.write().await;
                q.pop_front()
            };
            let Some(intent) = intent else {
                time::sleep(Duration::from_secs(1)).await;
                continue;
            };

            let rp_connected = self.peers.read().await
                .contains_key(&intent.rp_node_id);
            if !rp_connected {
                // Try to open a connection to the RP. In production this
                // would go through a circuit; here we need a direct
                // control-plane link so we can originate a 1-hop circuit.
                let node = Arc::clone(&self);
                let host = intent.rp_host.clone();
                let port = intent.rp_port;
                if let Err(e) = node.connect(&host, port).await {
                    debug!("hs drain: connect RP {}:{}: {}", host, port, e);
                    time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                // Wait a beat for handshake to complete
                time::sleep(Duration::from_millis(500)).await;
                if !self.peers.read().await.contains_key(&intent.rp_node_id) {
                    debug!("hs drain: RP connection didn't register");
                    continue;
                }
            }

            // Build a 1-hop circuit to the RP. (3-hop path selection
            // via consensus is future work.) We need the RP's x25519
            // static public key to form the ntor handshake; look it
            // up in the peer table.
            let rp_static_pub: [u8; 32] = {
                let peers = self.peers.read().await;
                let Some(peer) = peers.get(&intent.rp_node_id) else {
                    debug!("hs drain: RP peer vanished");
                    continue;
                };
                match hex::decode(&peer.info.static_pub)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                {
                    Some(b) => b,
                    None => {
                        debug!("hs drain: RP static_pub invalid");
                        continue;
                    }
                }
            };
            let rp_link = crate::circuit::LinkSpec {
                host:       intent.rp_host.clone(),
                port:       intent.rp_port,
                node_id:    intent.rp_node_id,
                static_pub: rp_static_pub,
            };
            let node = Arc::clone(&self);
            let rp_cid = match node.build_circuit(vec![rp_link]).await {
                Ok(c) => c,
                Err(e) => {
                    debug!("hs drain: build RP circuit: {}", e);
                    continue;
                }
            };

            // Send RENDEZVOUS1 through the circuit
            let r1 = crate::rendezvous::Rendezvous1 {
                cookie:   intent.cookie,
                server_y: intent.server_y,
                auth:     intent.auth,
            };
            if let Err(e) = self.send_origin_relay(
                rp_cid,
                crate::circuit::RelayCommand::Rendezvous1,
                r1.encode(),
            ).await {
                debug!("hs drain: send RENDEZVOUS1: {}", e);
                continue;
            }

            // Install e2e keys — future app-level cells on this circuit
            // use these keys end-to-end with the client.
            self.circuits.write().await.e2e_keys.insert(rp_cid, intent.e2e_keys);
            info!("HS: rendezvous completed, e2e keys installed on circ {:?}", rp_cid);
        }
    }

    /// Open a multiplexed stream on an existing circuit to `target`
    /// (host:port). Sends RELAY_BEGIN through the circuit and returns:
    ///   * `stream_id` — for subsequent `stream_write` / `stream_close` calls
    ///   * `rx` — channel that yields data received on this stream.
    ///     An empty yield (`rx.recv() -> None`) signals the stream closed.
    ///   * `ready` — oneshot that completes when RELAY_CONNECTED arrives
    ///     from the exit and the stream transitions to Open. Callers
    ///     must await this before calling `stream_write`, or writes
    ///     will fail with `"send in state Connecting"`.
    pub async fn stream_open(
        &self,
        cid: crate::circuit::CircuitId,
        target: &str,
    ) -> Result<(u16, tokio::sync::mpsc::Receiver<Vec<u8>>, tokio::sync::oneshot::Receiver<()>)> {
        let streams = {
            let mgr = self.circuits.read().await;
            mgr.origins.get(&cid)
                .map(|c| Arc::clone(&c.streams))
                .ok_or_else(|| Error::Handshake("stream_open: no circuit".into()))?
        };

        let (id, rx, ready) = streams.open_stream(target.to_string()).await;

        // BEGIN payload is a nul-terminated address string in ASCII.
        let mut begin_data = target.as_bytes().to_vec();
        begin_data.push(0);

        // Construct the relay cell manually to set stream_id.
        use crate::circuit::{RelayCell, RelayCommand, Cell, CellCommand};
        let mut relay = RelayCell::new(RelayCommand::Begin, id, begin_data)?;

        let mut mgr = self.circuits.write().await;
        let hops_len = mgr.origins.get(&cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("stream_open: no circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("stream_open: circuit has no hops".into()));
        }
        let guard_peer = mgr.origins[&cid].peer;
        let target_hop = hops_len - 1;

        let oc      = mgr.origins.get_mut(&cid).unwrap();
        relay.stamp_digest(&mut oc.hops[target_hop].forward_digest);
        let mut payload = relay.to_payload();
        for i in (0..=target_hop).rev() {
            crate::circuit::onion_encrypt_forward(&mut oc.hops[i], &mut payload);
        }
        drop(mgr);

        let cell = Cell { circ_id: cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await?;

        Ok((id, rx, ready))
    }

    /// Send DATA on an open stream. Enforces the per-stream send
    /// window; returns an error if the window is exhausted (caller
    /// should wait for a SENDME to arrive).
    pub async fn stream_write(
        &self,
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        data: &[u8],
    ) -> Result<()> {
        use crate::circuit::{RELAY_DATA_MAX, RelayCommand};

        // Split into cell-sized chunks.
        for chunk in data.chunks(RELAY_DATA_MAX) {
            let streams = {
                let mgr = self.circuits.read().await;
                mgr.origins.get(&cid)
                    .map(|c| Arc::clone(&c.streams))
                    .ok_or_else(|| Error::Handshake("stream_write: no circuit".into()))?
            };

            // First consume a stream-level window slot. This fails
            // fast if the per-stream budget is exhausted.
            let ok = streams.with_stream(stream_id, |s| s.try_consume_window()).await;
            match ok {
                Some(Ok(())) => {}
                Some(Err(e)) => return Err(e),
                None => return Err(Error::Handshake("stream_write: unknown stream".into())),
            }

            // Then consume a circuit-level window slot. A depleted
            // circuit window means the circuit as a whole is
            // congested, not just this stream, so all sibling streams
            // are equally blocked. This prevents one greedy stream
            // from monopolizing the circuit's downstream capacity.
            {
                let mut mgr = self.circuits.write().await;
                let oc = mgr.origins.get_mut(&cid)
                    .ok_or_else(|| Error::Handshake("stream_write: circuit gone".into()))?;
                oc.try_consume_circ_window()?;
            }

            self.send_stream_relay(cid, stream_id, RelayCommand::Data, chunk.to_vec()).await?;
        }
        Ok(())
    }

    /// Close a stream with the given reason.
    pub async fn stream_close(
        &self,
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        reason: crate::stream::EndReason,
    ) -> Result<()> {
        use crate::circuit::RelayCommand;
        let reason_byte = reason as u8;
        self.send_stream_relay(cid, stream_id, RelayCommand::End, vec![reason_byte]).await?;

        let streams = {
            let mgr = self.circuits.read().await;
            mgr.origins.get(&cid).map(|c| Arc::clone(&c.streams))
        };
        if let Some(m) = streams {
            m.with_stream(stream_id, |s| s.close(reason)).await;
            m.remove(stream_id).await;
        }
        Ok(())
    }

    /// Internal: send a stream-scoped relay cell (carries stream_id).
    async fn send_stream_relay(
        &self,
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        cmd: crate::circuit::RelayCommand,
        data: Vec<u8>,
    ) -> Result<()> {
        use crate::circuit::{RelayCell, Cell, CellCommand, onion_encrypt_forward};

        let mut relay = RelayCell::new(cmd, stream_id, data)?;

        let mut mgr = self.circuits.write().await;
        let hops_len = mgr.origins.get(&cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("send_stream_relay: no circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("send_stream_relay: no hops".into()));
        }
        let guard_peer = mgr.origins[&cid].peer;
        let target_hop = hops_len - 1;

        let oc = mgr.origins.get_mut(&cid).unwrap();
        relay.stamp_digest(&mut oc.hops[target_hop].forward_digest);
        let mut payload = relay.to_payload();
        for i in (0..=target_hop).rev() {
            onion_encrypt_forward(&mut oc.hops[i], &mut payload);
        }
        drop(mgr);

        let cell = Cell { circ_id: cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await
    }

    /// Send an application-level relay cell along an origin circuit.
    /// Encrypts the cell through all hops and dispatches it over the
    /// connection to our guard peer.
    pub async fn send_origin_relay(
        &self,
        cid: crate::circuit::CircuitId,
        cmd: crate::circuit::RelayCommand,
        data: Vec<u8>,
    ) -> Result<()> {
        use crate::circuit::{RelayCell, Cell, CellCommand};
        let relay = RelayCell::new(cmd, 0, data)?;

        let mut mgr = self.circuits.write().await;
        let hops_len = mgr.origins.get(&cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("send_origin_relay: unknown circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("send_origin_relay: no hops".into()));
        }
        let guard_peer = mgr.origins[&cid].peer;
        let payload    = {
            let oc = mgr.origins.get_mut(&cid).unwrap();
            oc.encrypt_outbound(hops_len - 1, relay)?
        };
        drop(mgr);

        let cell = Cell { circ_id: cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await
    }

    /// Client side: we received RENDEZVOUS2 on our RP circuit. Match
    /// the cookie to the pending_rendezvous entry, verify the AUTH
    /// tag using the HS static key stashed at registration, and
    /// install the end-to-end keys for this circuit.
    ///
    /// This is the cryptographic moment at which the client becomes
    /// authenticated with the HS. A tampered or forged RENDEZVOUS2
    /// is rejected: the cookie is consumed (preventing retry) but no
    /// keys are installed, and the caller should tear down the circuit.
    async fn handle_rendezvous2(&self, rp_cid: crate::circuit::CircuitId, data: &[u8]) {
        let r2 = match crate::rendezvous::Rendezvous2::decode(data) {
            Ok(r) => r,
            Err(e) => { debug!("rendezvous2 decode: {}", e); return; }
        };

        // Find pending entry by rp_cid (RENDEZVOUS2 carries no cookie
        // itself — the RP used it for splicing and stripped it).
        let mut mgr = self.circuits.write().await;
        let cookie = mgr.pending_rendezvous.iter()
            .find(|(_, (cid, _, _, _))| *cid == rp_cid)
            .map(|(c, _)| *c);
        let Some(cookie) = cookie else {
            debug!("rendezvous2: no pending entry for cid {:?}", rp_cid);
            return;
        };

        // complete_rendezvous uses the HS static key stored at
        // register_pending_rendezvous time. On AUTH failure the cookie
        // is still consumed (see the implementation); no keys installed.
        match mgr.complete_rendezvous(&cookie, &r2.server_y, &r2.auth) {
            Ok(cid) => {
                info!("HS rendezvous completed on circ {:?} (e2e keys installed)", cid);
            }
            Err(e) => {
                debug!("rendezvous2: auth verification failed: {}", e);
                // Tear down the circuit — the RP may be adversarial.
                let guard = mgr.origins.get(&rp_cid).map(|c| c.peer);
                mgr.origins.remove(&rp_cid);
                mgr.e2e_keys.remove(&rp_cid);
                drop(mgr);
                if let Some(g) = guard {
                    use crate::circuit::{Cell, CellCommand};
                    if let Ok(dcell) = Cell::with_payload(rp_cid, CellCommand::Destroy, &[0]) {
                        let _ = self.send_circuit_cell(&g, &dcell.to_bytes()).await;
                    }
                }
            }
        }
    }

    // ── DHT ───────────────────────────────────────────────────────────

    async fn handle_dht_find(&self, msg: DhtFind, src: &Arc<PeerConn>) {
        let target: [u8; 32] = hex::decode(&msg.target)
            .ok().and_then(|b| b.try_into().ok()).unwrap_or([0u8; 32]);
        let nodes = self.routing.closest(&target, crate::dht::K)
            .into_iter().map(|p| DhtPeerInfo {
                node_id:    p.node_id_hex(),
                host:       p.host,
                port:       p.port,
                cert:       p.cert,
                static_pub: p.static_pub,
            }).collect();
        let _ = src.send_msg(&Message::DhtFound(DhtFound {
            req_id: msg.req_id,
            target: msg.target,
            nodes,
        })).await;
    }

    fn handle_dht_found(&self, msg: DhtFound) {
        for n in msg.nodes {
            if let Ok(b) = hex::decode(&n.node_id) {
                if let Ok(id) = b.try_into() {
                    self.routing.add_peer(PeerInfo {
                        node_id: id, host: n.host, port: n.port,
                        cert: n.cert, static_pub: n.static_pub,
                    });
                }
            }
        }
    }

    async fn handle_dht_fetch(&self, msg: crate::wire::DhtFetch, src: &Arc<PeerConn>) {
        let value = self.dht.get(&msg.key);
        let _ = src.send_msg(&Message::DhtValue(DhtValue {
            req_id: msg.req_id, key: msg.key, value,
        })).await;
    }

    // ── Hidden services ───────────────────────────────────────────────

    async fn handle_hs_lookup(&self, msg: HsLookup, src: &Arc<PeerConn>) {
        let descriptor = self.dht.get_hs(&msg.hs_id);
        let puzzle = if let Some(hs) = self.hs_mgr.get(&msg.hs_id).await {
            Some(hs.issue_puzzle())
        } else { None };
        let _ = src.send_msg(&Message::HsFound(HsFound {
            req_id: msg.req_id, hs_id: msg.hs_id, descriptor, puzzle,
        })).await;
    }

    // ── Board ─────────────────────────────────────────────────────────

    async fn handle_board_post(&self, msg: BoardPost, src: &Arc<PeerConn>) {
        if self.board.merge(&msg) {
            let peers = self.peers.read().await;
            for p in peers.values() {
                if p.info.node_id != src.info.node_id {
                    let _ = p.send_msg(&Message::BoardPost(msg.clone())).await;
                }
            }
        }
    }

    async fn handle_board_fetch(&self, msg: BoardFetch, src: &Arc<PeerConn>) {
        let posts = self.board.get(&msg.channel, msg.limit as usize);
        let _ = src.send_msg(&Message::BoardPosts(BoardPosts {
            req_id: msg.req_id, channel: msg.channel, posts,
        })).await;
    }

    // ── Public API ────────────────────────────────────────────────────

    pub async fn all_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().await.values().map(|p| p.info.clone()).collect()
    }

    pub async fn post_to_board(&self, channel: &str, text: &str) {
        let cluster = self.cert.read().unwrap().cluster_id();
        let post    = self.board.post(channel, text, Some(cluster));
        let peers   = self.peers.read().await;
        for p in peers.values() {
            let _ = p.send_msg(&Message::BoardPost(post.clone())).await;
        }
    }

    pub async fn register_hs(&self, name: &str) -> Arc<crate::hidden_service::HiddenService> {
        let cert = self.cert.read().unwrap().clone();
        self.hs_mgr.register(&cert, name).await
    }

    // ── Circuit API ───────────────────────────────────────────────────

    /// Build a multi-hop circuit through the given path. Each entry in
    /// `path` must correspond to a peer this node is already connected
    /// to (use [`PhiNode::connect`] first). The first entry is the
    /// guard; subsequent entries are reached via RELAY_EXTEND2.
    ///
    /// Returns the originating [`CircuitId`] once all hops are built.
    /// The caller can then send application-level relay cells through
    /// the circuit using APIs not yet exposed (stream layer).
    pub async fn build_circuit(
        self: Arc<Self>,
        path: Vec<crate::circuit::LinkSpec>,
    ) -> Result<crate::circuit::CircuitId> {
        use crate::circuit::{MAX_HOPS, CELL_SIZE};

        if path.is_empty() || path.len() > MAX_HOPS {
            return Err(Error::Handshake(format!(
                "build_circuit: path length {} out of range [1,{}]",
                path.len(), MAX_HOPS
            )));
        }
        // All hops must be connected peers (we pre-connect rather than
        // trying to connect during extend — see handle_circuit_cell).
        {
            let peers = self.peers.read().await;
            for (i, ls) in path.iter().enumerate() {
                if !peers.contains_key(&ls.node_id) {
                    return Err(Error::Handshake(format!(
                        "build_circuit: hop {} ({}) not connected",
                        i, hex::encode(&ls.node_id[..6])
                    )));
                }
            }
        }

        // 1. CREATE to guard. The `guard_b` arg is the guard's x25519
        //    static public key — NOT its node_id. The receiver's
        //    server_handshake validates that the B in the message
        //    matches its own static public key.
        let guard = &path[0];
        let (cid, create_bytes) = {
            let mut mgr = self.circuits.write().await;
            mgr.start_circuit(guard.node_id, &guard.node_id, &guard.static_pub)?
        };
        self.send_circuit_cell(&guard.node_id, &create_bytes).await?;

        // 2. Wait for CREATED — we poll the origin state until the first
        //    hop appears. In practice the dispatch task installs it.
        let timeout = Duration::from_secs(15);
        let start = std::time::Instant::now();
        loop {
            {
                let mgr = self.circuits.read().await;
                if let Some(oc) = mgr.origins.get(&cid) {
                    if oc.hops.len() >= 1 { break; }
                }
            }
            if start.elapsed() > timeout {
                return Err(Error::Handshake("circuit: CREATE timed out".into()));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // 3. Extend through remaining hops one at a time
        for (i, next) in path.iter().enumerate().skip(1) {
            let extend_bytes: [u8; CELL_SIZE] = {
                let mut mgr = self.circuits.write().await;
                mgr.extend_circuit(cid, next.clone())?
            };
            self.send_circuit_cell(&guard.node_id, &extend_bytes).await?;

            let need_hops = i + 1;
            let start = std::time::Instant::now();
            loop {
                {
                    let mgr = self.circuits.read().await;
                    if let Some(oc) = mgr.origins.get(&cid) {
                        if oc.hops.len() >= need_hops { break; }
                    }
                }
                if start.elapsed() > timeout {
                    return Err(Error::Handshake(format!(
                        "circuit: EXTEND to hop {} timed out", i
                    )));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        Ok(cid)
    }

    /// Report on existing circuits. Returns `(origin_count,
    /// relay_count)` — how many circuits this node originated vs.
    /// how many it participates in as a middle/exit hop.
    pub async fn circuit_status(&self) -> (usize, usize) {
        let mgr = self.circuits.read().await;
        (mgr.origins.len(), mgr.relays.len())
    }

    /// Tear down an origin circuit. Sends DESTROY upstream and removes
    /// local state.
    pub async fn destroy_circuit(&self, cid: crate::circuit::CircuitId) -> Result<()> {
        use crate::circuit::{Cell, CellCommand};

        let guard_peer = {
            let mgr = self.circuits.read().await;
            mgr.origins.get(&cid).map(|c| c.peer)
        };
        let Some(guard) = guard_peer else { return Ok(()); };

        let cell  = Cell::with_payload(cid, CellCommand::Destroy, &[0u8])?;
        let bytes = cell.to_bytes();
        let _ = self.send_circuit_cell(&guard, &bytes).await;

        let mut mgr = self.circuits.write().await;
        mgr.destroy(guard, cid);
        Ok(())
    }

    // ── Hidden service / rendezvous API ───────────────────────────────

    /// Send ESTABLISH_INTRO as a hidden service operator on an already
    /// built circuit. The circuit's terminal hop becomes an intro
    /// point for this HS. Returns the auth_key_pub the HS will publish
    /// in its descriptor for clients to reference.
    pub async fn establish_intro_on(
        &self,
        cid: crate::circuit::CircuitId,
        auth_key_pub: [u8; 32],
    ) -> Result<()> {
        use crate::circuit::{RelayCell, RelayCommand, Cell, CellCommand};
        use crate::rendezvous::EstablishIntro;

        let msg = EstablishIntro {
            auth_key_pub,
            // Empty sig for now: in production the HS signs the circuit
            // digest with its long-term HS identity key.
            sig: [0u8; 32],
        };
        let relay = RelayCell::new(
            RelayCommand::EstablishIntro, 0, msg.encode())?;

        let mut mgr = self.circuits.write().await;
        let hops_len = mgr.origins.get(&cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("establish_intro: unknown circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("establish_intro: circuit has no hops".into()));
        }

        let guard_peer = mgr.origins[&cid].peer;
        let payload    = {
            let oc = mgr.origins.get_mut(&cid).unwrap();
            oc.encrypt_outbound(hops_len - 1, relay)?
        };
        // Remember this circuit is now an intro for us
        mgr.register_intro_circuit(cid, auth_key_pub);
        drop(mgr);

        let cell = Cell { circ_id: cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await
    }

    /// Client: send ESTABLISH_RENDEZVOUS on an existing built circuit
    /// to an RP. The cookie is generated fresh; a StaticSecret is
    /// created for the e2e handshake. `hs_static_pub` comes from the
    /// HS descriptor and is stored so `handle_rendezvous2` can verify
    /// AUTH when the HS's reply arrives.
    pub async fn establish_rendezvous_on(
        &self,
        cid: crate::circuit::CircuitId,
        hs_static_pub: [u8; 32],
    ) -> Result<[u8; 20]> {
        use crate::circuit::{RelayCell, RelayCommand, Cell, CellCommand};
        use crate::rendezvous::{EstablishRendezvous, fresh_cookie};
        use x25519_dalek::StaticSecret;

        let cookie = fresh_cookie();

        let client_sk = StaticSecret::random_from_rng(OsRng);
        let client_x  = *PublicKey::from(&client_sk).as_bytes();

        let relay = RelayCell::new(
            RelayCommand::EstablishRendezvous, 0,
            EstablishRendezvous { cookie }.encode())?;

        let mut mgr = self.circuits.write().await;
        let hops_len   = mgr.origins.get(&cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("establish_rendezvous: unknown circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("establish_rendezvous: no hops".into()));
        }
        let guard_peer = mgr.origins[&cid].peer;
        let payload    = {
            let oc = mgr.origins.get_mut(&cid).unwrap();
            oc.encrypt_outbound(hops_len - 1, relay)?
        };
        mgr.register_pending_rendezvous(cookie, cid, client_sk, client_x, hs_static_pub);
        drop(mgr);

        let cell = Cell { circ_id: cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await?;
        Ok(cookie)
    }

    /// Client: send INTRODUCE1 to the HS via an intro circuit we've
    /// built. `intro_cid` is the circuit whose terminal hop is the
    /// intro point. The plaintext contains our RP selection.
    pub async fn send_introduce1(
        &self,
        intro_cid: crate::circuit::CircuitId,
        hs_static_pub: &[u8; 32],
        auth_key_pub:  &[u8; 32],
        rp_node_id:    [u8; 32],
        rp_host:       String,
        rp_port:       u16,
        cookie:        [u8; 20],
    ) -> Result<()> {
        use crate::circuit::{RelayCell, RelayCommand, Cell, CellCommand};
        use crate::rendezvous::{Introduce, IntroducePlaintext};

        let plaintext = IntroducePlaintext { rp_node_id, rp_host, rp_port, cookie };

        // CRITICAL: use the same client ephemeral stashed in
        // pending_rendezvous — the one we'll later use to verify
        // AUTH in handle_rendezvous2. Generating a fresh ephemeral
        // here would cause the HS's AUTH (computed over the X
        // embedded in INTRODUCE) to not match what the client
        // recomputes (from its stashed X).
        let client_sk = {
            let mgr = self.circuits.read().await;
            let entry = mgr.pending_rendezvous.get(&cookie)
                .ok_or_else(|| Error::Handshake(
                    "send_introduce1: no pending_rendezvous for this cookie \
                     — call establish_rendezvous_on first".into()))?;
            entry.1.clone()
        };

        let (intro, _client_sk) = Introduce::build_for_hs_with_ephemeral(
            hs_static_pub, auth_key_pub, &plaintext, client_sk);

        let relay = RelayCell::new(
            RelayCommand::Introduce1, 0, intro.encode())?;

        let mut mgr = self.circuits.write().await;
        let hops_len = mgr.origins.get(&intro_cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("introduce1: unknown circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("introduce1: no hops".into()));
        }
        let guard_peer = mgr.origins[&intro_cid].peer;
        let payload    = {
            let oc = mgr.origins.get_mut(&intro_cid).unwrap();
            oc.encrypt_outbound(hops_len - 1, relay)?
        };
        drop(mgr);

        let cell = Cell { circ_id: intro_cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await
    }

    /// Broadcast a hidden-service descriptor to all connected peers and store in DHT.
    /// Sign and publish an HS descriptor. The descriptor is signed
    /// under the given HS identity's epoch-blinded subkey before
    /// being cached locally and broadcast to peers via HsRegister.
    /// Peers verify the signature before caching (see HsRegister
    /// dispatch in `handle`), so an attacker can't forge descriptors
    /// for an hs_id they don't control.
    pub async fn broadcast_hs(
        &self,
        descriptor: crate::wire::HsDescriptor,
        identity:   &crate::hs_identity::HsIdentity,
    ) {
        // Stash the endpoint that was published so the periodic
        // republishing loop can reconstruct it next epoch without
        // the operator having to re-invoke hs_register.
        if let Some(hs) = self.hs_mgr.get(&descriptor.hs_id).await {
            let host = descriptor.intro_host.clone().unwrap_or_default();
            let port = descriptor.intro_port.unwrap_or(0);
            *hs.published_endpoint.write().await = Some((host, port));
        }

        let epoch = crate::hs_identity::current_epoch();
        let signed = crate::hs_identity::sign_descriptor(identity, descriptor, epoch);
        self.dht.put_hs(&signed);
        let peers = self.peers.read().await;
        for p in peers.values() {
            let _ = p.send_msg(&Message::HsRegister(crate::wire::HsRegister {
                descriptor: signed.clone(),
            })).await;
        }
    }

    /// Periodically re-sign and re-publish descriptors for every HS
    /// this node hosts. Descriptors are signed for the current epoch
    /// and clients accept signatures within ±1 epoch of their local
    /// clock, so a republish every ~12 hours keeps every HS
    /// reachable indefinitely. Without this loop, a hidden service
    /// stops being reachable ~48 hours after the daemon starts as
    /// the originally-signed descriptor falls outside the acceptance
    /// window.
    ///
    /// Runs forever. Spawned from `run()`. Never panics: all errors
    /// are logged and ignored.
    async fn hs_republish_loop(self: Arc<Self>) {
        // Half an epoch: ensures we always republish before the
        // previous descriptor falls outside clients' ±1 window.
        let interval = Duration::from_secs(
            crate::hs_identity::EPOCH_SECS / 2
        );
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = self.shutdown.notified() => break,
            }
            if self.is_shutting_down() { break; }
            self.republish_all_hs_once().await;
        }
        debug!("hs_republish_loop: shutting down");
    }

    /// Iterate every registered HS and re-sign + re-broadcast its
    /// descriptor (using the last-published endpoint). Public so
    /// tests can invoke a single republish pass directly instead of
    /// waiting 12 hours for the loop to fire.
    ///
    /// Skips services that have never been published (no endpoint
    /// stashed), since without an intro endpoint we'd publish a
    /// useless descriptor pointing nowhere.
    pub async fn republish_all_hs_once(&self) {
        let hs_ids = self.hs_mgr.list().await;
        for hs_id in hs_ids {
            let Some(hs) = self.hs_mgr.get(&hs_id).await else { continue };
            let endpoint = hs.published_endpoint.read().await.clone();
            let Some((host, port)) = endpoint else {
                debug!("hs republish: skip {} (never published)", hs_id);
                continue;
            };
            let descriptor = hs.descriptor(
                if host.is_empty() { None } else { Some(&host) },
                if port == 0       { None } else { Some(port)   },
            );
            debug!("hs republish: re-signing descriptor for {} (epoch {})",
                   hs_id, crate::hs_identity::current_epoch());
            self.broadcast_hs(descriptor, &hs.identity).await;
        }
    }

    pub async fn bootstrap(self: Arc<Self>, peers: Vec<(String, u16)>) {
        for (host, port) in peers {
            let node = Arc::clone(&self);
            let h    = host.clone();
            tokio::spawn(async move {
                info!("Bootstrap {}:{}", h, port);
                if let Err(e) = Arc::clone(&node).connect(&h, port).await {
                    warn!("Bootstrap {}:{}: {}", h, port, e);
                } else {
                    let my_id = node.node_id_hex();
                    let peers = node.peers.read().await;
                    for p in peers.values() {
                        let _ = p.send_msg(&Message::DhtFind(DhtFind {
                            req_id: hex::encode(rand_bytes(8)),
                            target: my_id.clone(),
                        })).await;
                    }
                }
            });
        }
    }

    // ── Background loops ──────────────────────────────────────────────

    async fn guard_refresh_loop(&self) {
        loop {
            time::sleep(Duration::from_secs(600)).await;
            let peers  = self.routing.all_peers();
            let guards = onion::select_guards(&peers, 3, &[])
                .into_iter().cloned().collect();
            *self.guards.write().await = guards;
            debug!("Guards refreshed");
        }
    }

    /// Verify and apply an incoming CertRotate announcement.
    ///
    /// Checks performed (in order, all must pass):
    /// 1. `old_node_id` matches an existing peer in our table.
    /// 2. `seq` strictly exceeds any previously-seen seq for that id.
    /// 3. `link_sig` matches the HMAC computed from the peer's
    ///    rotation_link_key — proves the announcer holds the session
    ///    key shared with the claimed old identity.
    /// 4. The new cert passes `PhiCert::verify()` (math is sound).
    /// 5. `new_node_id` matches the new cert's node_id.
    ///
    /// On success, updates the peer entry: key (HashMap index) moves
    /// from old_id to new_id, PeerInfo.node_id is updated, and the
    /// routing table is rebalanced. Session keys and the open TCP
    /// connection are preserved — rotation is purely a credential
    /// refresh, not a new handshake.
    async fn handle_cert_rotate(&self, msg: crate::wire::CertRotate, src: &Arc<PeerConn>) {
        // Parse hex IDs
        let old_id_vec = match hex::decode(&msg.old_node_id) {
            Ok(v) if v.len() == 32 => v,
            _ => { debug!("cert rotate: bad old_node_id hex"); return; }
        };
        let new_id_vec = match hex::decode(&msg.new_node_id) {
            Ok(v) if v.len() == 32 => v,
            _ => { debug!("cert rotate: bad new_node_id hex"); return; }
        };
        let mut old_id = [0u8; 32]; old_id.copy_from_slice(&old_id_vec);
        let mut new_id = [0u8; 32]; new_id.copy_from_slice(&new_id_vec);

        // Defensive: the sender must actually be the one rotating.
        // Otherwise peer A could broadcast a rotation for peer B.
        if src.info.node_id != old_id {
            debug!("cert rotate: src {} claims to rotate {}",
                   hex::encode(&src.info.node_id[..6]),
                   hex::encode(&old_id[..6]));
            return;
        }

        // (1) Peer must exist in our table under old_id.
        let peer_arc = match self.peers.read().await.get(&old_id) {
            Some(p) => Arc::clone(p),
            None    => { debug!("cert rotate: unknown old peer"); return; }
        };

        // (2) Replay / stale check.
        {
            let mut seen = self.seen_rotation_seqs.write().await;
            let prev = seen.get(&old_id).copied().unwrap_or(0);
            if msg.seq <= prev {
                debug!("cert rotate: stale seq {} ≤ {} for {}",
                       msg.seq, prev, hex::encode(&old_id[..6]));
                return;
            }
            // Speculatively mark seen so a concurrent replay of the same
            // announcement is rejected even before (3) and (4) run.
            seen.insert(old_id, msg.seq);
        }

        // (3)-(5) Pure-function verification chain: HMAC, cert math,
        //         node_id binding.
        let link_key = peer_arc.session.rotation_link_key();
        if let Err(e) = verify_rotation(&link_key, &msg) {
            debug!("cert rotate: verification failed: {}", e);
            return;
        }
        // We need the WireCert for the peer entry update below.
        let wire_cert: crate::cert::WireCert = match serde_json::from_str(&msg.new_cert_json) {
            Ok(w) => w,
            Err(e) => { debug!("cert rotate: json re-parse: {}", e); return; }
        };

        // All checks passed — re-key the peer entry.
        {
            let mut peers = self.peers.write().await;
            let peer = match peers.remove(&old_id) {
                Some(p) => p,
                None    => {
                    debug!("cert rotate: peer vanished during rotation");
                    return;
                }
            };
            // Update the shared PeerInfo's node_id. peer.info is a value;
            // the stored Arc<PeerConn> already captures it. We can't
            // mutate through Arc safely without interior mutability, so
            // we rebuild the PeerConn Arc with the new info. Keep the
            // original session (it's wrapped in Arc already).
            let new_info = crate::dht::PeerInfo {
                node_id:    new_id,
                host:       peer.info.host.clone(),
                port:       peer.info.port,
                cert:       wire_cert.clone(),
                static_pub: peer.info.static_pub.clone(),
            };
            let updated = Arc::new(PeerConn {
                info:    new_info.clone(),
                sender:  peer.sender.clone(),
                session: Arc::clone(&peer.session),
            });
            peers.insert(new_id, updated);
            drop(peers);

            // Routing table: drop old, add new.
            self.routing.remove_peer(&old_id);
            self.routing.add_peer(new_info);
        }

        // Also migrate the guard manager entry if present.
        if self.guard_mgr.is_guard(&old_id) {
            // Re-add under new id; list() retains old until prune.
            let entry_host = src.info.host.clone();
            let entry_port = src.info.port;
            self.guard_mgr.add_candidate(&new_id, &entry_host, entry_port);
            self.guard_mgr.mark_success(&new_id);
            self.guard_mgr.save_best_effort();
        }

        info!("Peer rotated: {} → {}",
              hex::encode(&old_id[..6]),
              hex::encode(&new_id[..6]));

        // Suppress unused lint on vecs we already copied.
        let _ = (old_id_vec, new_id_vec);
    }

    async fn rotation_loop(self: Arc<Self>) {
        loop {
            time::sleep(ROTATE_INTERVAL).await;
            info!("Rotating cert…");
            let old_cert = self.cert.read().unwrap().clone();
            let new_cert = match old_cert.rotate() {
                Ok(c)  => c,
                Err(e) => { warn!("Cert rotation: {}", e); continue; }
            };

            let old_id = old_cert.node_id();
            let new_id = new_cert.node_id();
            let new_wire = new_cert.to_wire();
            let new_json = match serde_json::to_string(&new_wire) {
                Ok(s) => s,
                Err(e) => { warn!("rotate: serialize: {}", e); continue; }
            };

            let seq = self.rotation_seq.fetch_add(1, Ordering::SeqCst) + 1;
            let ts  = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0);

            // Install the new cert locally first so self.node_id() changes.
            *self.cert.write().unwrap() = new_cert;

            // Broadcast to each connected peer, signed per-session.
            let peers = self.peers.read().await;
            for (pid, peer) in peers.iter() {
                let link_key = peer.session.rotation_link_key();
                let sig      = compute_rotation_sig(
                    &link_key, &old_id, &new_id, &new_json, seq, ts);
                let msg = crate::wire::CertRotate {
                    old_node_id:   hex::encode(old_id),
                    new_node_id:   hex::encode(new_id),
                    new_cert_json: new_json.clone(),
                    seq,
                    ts,
                    link_sig:      hex::encode(sig),
                };
                if let Err(e) = peer.send_msg(&Message::CertRotate(msg)).await {
                    debug!("rotate: peer {}: {}", hex::encode(&pid[..6]), e);
                }
            }
        }
    }
}

/// Compute the HMAC-SHA256 tag binding a CertRotate announcement to
/// the (old, new) identity transition. Both sides of a peer session
/// derive the same `link_key` via `Session::rotation_link_key`, so
/// the receiver can recompute this tag and compare byte-for-byte.
/// Returns exactly 32 bytes; no truncation.
fn compute_rotation_sig(
    link_key: &[u8; 32],
    old_node_id: &[u8; 32],
    new_node_id: &[u8; 32],
    new_cert_json: &str,
    seq: u64,
    ts: u64,
) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(link_key)
        .expect("hmac key");
    mac.update(b"phinet-cert-rotate-v1:");
    mac.update(old_node_id);
    mac.update(new_node_id);
    mac.update(new_cert_json.as_bytes());
    mac.update(&seq.to_be_bytes());
    mac.update(&ts.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Pure-function rotation verification. Returns the parsed new cert
/// on success or an error describing which check failed. Used by
/// `handle_cert_rotate` and directly by unit tests.
///
/// Checks performed (all must pass):
/// 1. HMAC `link_sig` matches `compute_rotation_sig` under `link_key`.
/// 2. New cert JSON parses and `PhiCert::verify()` returns true.
/// 3. Derived node_id matches claimed `new_node_id`.
pub(crate) fn verify_rotation(
    link_key: &[u8; 32],
    msg: &crate::wire::CertRotate,
) -> Result<crate::cert::PhiCert> {
    // Parse IDs
    let old_id_vec = hex::decode(&msg.old_node_id)
        .map_err(|_| Error::Crypto("cert rotate: bad old_node_id hex".into()))?;
    if old_id_vec.len() != 32 {
        return Err(Error::Crypto("cert rotate: old_node_id not 32 bytes".into()));
    }
    let mut old_id = [0u8; 32]; old_id.copy_from_slice(&old_id_vec);

    let new_id_vec = hex::decode(&msg.new_node_id)
        .map_err(|_| Error::Crypto("cert rotate: bad new_node_id hex".into()))?;
    if new_id_vec.len() != 32 {
        return Err(Error::Crypto("cert rotate: new_node_id not 32 bytes".into()));
    }
    let mut new_id = [0u8; 32]; new_id.copy_from_slice(&new_id_vec);

    // HMAC
    let sig_vec = hex::decode(&msg.link_sig)
        .map_err(|_| Error::Crypto("cert rotate: bad sig hex".into()))?;
    if sig_vec.len() != 32 {
        return Err(Error::Crypto("cert rotate: sig not 32 bytes".into()));
    }
    let mut sig = [0u8; 32]; sig.copy_from_slice(&sig_vec);

    let expect = compute_rotation_sig(
        link_key, &old_id, &new_id, &msg.new_cert_json, msg.seq, msg.ts);
    if !ct_eq_32(&sig, &expect) {
        return Err(Error::AuthFailed);
    }

    // Cert JSON + math
    let wire_cert: crate::cert::WireCert = serde_json::from_str(&msg.new_cert_json)
        .map_err(|e| Error::Crypto(format!("cert rotate: json: {e}")))?;
    let new_cert = crate::cert::PhiCert::from_wire(&wire_cert)?;
    if !new_cert.verify() {
        return Err(Error::Crypto("cert rotate: math failed".into()));
    }

    // Binding: new_id must be the derived node_id of the new cert
    let derived = new_cert.node_id();
    if derived != new_id {
        return Err(Error::Crypto("cert rotate: node_id binding mismatch".into()));
    }

    Ok(new_cert)
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    OsRng.fill_bytes(&mut b);
    u32::from_le_bytes(b)
}

use crate::timing::ct_eq_32;

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod rotation_tests {
    use super::*;
    use crate::cert::{PhiCert, CertBits};
    use crate::wire::CertRotate;

    /// Build a small valid cert for testing. Uses smallest available
    /// bit size to keep test runtime reasonable.
    fn small_cert() -> PhiCert {
        PhiCert::generate(CertBits::B256).expect("gen cert")
    }

    fn make_rotation(
        old_cert: &PhiCert,
        new_cert: &PhiCert,
        link_key: &[u8; 32],
        seq: u64,
        ts: u64,
    ) -> CertRotate {
        let old_id = old_cert.node_id();
        let new_id = new_cert.node_id();
        let wire   = new_cert.to_wire();
        let json   = serde_json::to_string(&wire).unwrap();
        let sig    = compute_rotation_sig(link_key, &old_id, &new_id, &json, seq, ts);
        CertRotate {
            old_node_id:   hex::encode(old_id),
            new_node_id:   hex::encode(new_id),
            new_cert_json: json,
            seq,
            ts,
            link_sig:      hex::encode(sig),
        }
    }

    #[test]
    fn valid_rotation_accepted() {
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let key      = [0x42u8; 32];
        let msg      = make_rotation(&old_cert, &new_cert, &key, 1, 1700000000);

        let verified = verify_rotation(&key, &msg).expect("should verify");
        assert_eq!(verified.node_id(), new_cert.node_id());
    }

    #[test]
    fn tampered_hmac_rejected() {
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let key      = [0x42u8; 32];
        let mut msg  = make_rotation(&old_cert, &new_cert, &key, 1, 1700000000);

        // Flip one bit in the hex sig
        let mut bytes = hex::decode(&msg.link_sig).unwrap();
        bytes[17] ^= 1;
        msg.link_sig = hex::encode(bytes);

        assert!(matches!(verify_rotation(&key, &msg), Err(Error::AuthFailed)));
    }

    #[test]
    fn wrong_link_key_rejected() {
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let key      = [0x42u8; 32];
        let msg      = make_rotation(&old_cert, &new_cert, &key, 1, 1700000000);

        // Different key — an attacker who doesn't share our session
        let wrong_key = [0x43u8; 32];
        assert!(matches!(verify_rotation(&wrong_key, &msg), Err(Error::AuthFailed)));
    }

    #[test]
    fn node_id_binding_enforced() {
        // Attacker signs a rotation pointing to cert X but claims
        // new_node_id is from cert Y. Verifier must catch the mismatch.
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let decoy    = small_cert();
        let key      = [0x42u8; 32];

        let old_id   = old_cert.node_id();
        let fake_id  = decoy.node_id();     // doesn't match the embedded cert
        let real_id  = new_cert.node_id();
        assert_ne!(fake_id, real_id);

        let wire = new_cert.to_wire();
        let json = serde_json::to_string(&wire).unwrap();
        let sig  = compute_rotation_sig(&key, &old_id, &fake_id, &json, 1, 0);
        let msg  = CertRotate {
            old_node_id:   hex::encode(old_id),
            new_node_id:   hex::encode(fake_id),    // LIE
            new_cert_json: json,
            seq:           1,
            ts:            0,
            link_sig:      hex::encode(sig),
        };
        // HMAC passes (we signed the lie), but binding check fails.
        let err = verify_rotation(&key, &msg);
        assert!(err.is_err());
        let err_str = format!("{:?}", err.unwrap_err());
        assert!(err_str.contains("binding") || err_str.contains("node_id"),
                "expected binding error, got: {}", err_str);
    }

    #[test]
    fn corrupt_cert_json_rejected() {
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let key      = [0x42u8; 32];
        let mut msg  = make_rotation(&old_cert, &new_cert, &key, 1, 0);

        // Mangle the JSON — HMAC will fail first since the sig was
        // computed over the original text.
        msg.new_cert_json = "{not valid json".to_string();
        // The HMAC was computed over the *original* json, so mangling
        // the field invalidates it. verify_rotation hits HMAC check first.
        assert!(verify_rotation(&key, &msg).is_err());
    }

    #[test]
    fn sig_binds_to_seq_and_ts() {
        // If attacker replays a valid rotation but changes seq/ts,
        // the sig should no longer verify.
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let key      = [0x42u8; 32];
        let mut msg  = make_rotation(&old_cert, &new_cert, &key, 5, 1700000000);

        msg.seq = 6; // attacker tries to replay with higher seq
        assert!(matches!(verify_rotation(&key, &msg), Err(Error::AuthFailed)));

        let mut msg2 = make_rotation(&old_cert, &new_cert, &key, 5, 1700000000);
        msg2.ts = 1700001000;
        assert!(matches!(verify_rotation(&key, &msg2), Err(Error::AuthFailed)));
    }

    #[test]
    fn compute_rotation_sig_is_deterministic() {
        let key    = [0x11u8; 32];
        let old_id = [0xAAu8; 32];
        let new_id = [0xBBu8; 32];
        let json   = r#"{"fake":"cert"}"#;

        let s1 = compute_rotation_sig(&key, &old_id, &new_id, json, 42, 1000);
        let s2 = compute_rotation_sig(&key, &old_id, &new_id, json, 42, 1000);
        assert_eq!(s1, s2);

        // Changing any field produces a different sig
        let s_diff_key = compute_rotation_sig(&[0x12u8; 32], &old_id, &new_id, json, 42, 1000);
        assert_ne!(s1, s_diff_key);
        let s_diff_seq = compute_rotation_sig(&key, &old_id, &new_id, json, 43, 1000);
        assert_ne!(s1, s_diff_seq);
    }
}
