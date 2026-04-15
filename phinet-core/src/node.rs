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
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    io::{BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    sync::{mpsc, RwLock as ARwLock},
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

    pub high_security: bool,
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
            board:   MessageBoard::new(),
            hs_mgr:  HsManager::new(store.clone()),
            store,
            peers:         ARwLock::new(HashMap::new()),
            guards:        ARwLock::new(Vec::new()),
            high_security: false,
        })
    }

    pub fn node_id(&self) -> [u8; 32]  { self.cert.read().unwrap().node_id() }
    pub fn node_id_hex(&self) -> String { hex::encode(self.node_id()) }

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
            tokio::spawn(async move {
                loop {
                    time::sleep(Duration::from_secs(300)).await;
                    n.dht.evict_expired();
                }
            });
        }

        loop {
            let (stream, addr) = listener.accept().await?;
            let node = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = node.handle_incoming(stream, addr).await {
                    debug!("incoming {}: {}", addr, e);
                }
            });
        }
    }

    // ── Handshake (responder) ─────────────────────────────────────────

    async fn handle_incoming(self: Arc<Self>, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        let (r, w)  = stream.into_split();
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
        let stream  = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let (r, w)  = stream.into_split();
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

    async fn register_peer(
        self: Arc<Self>,
        info: PeerInfo,
        session: Arc<Session>,
        reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
        writer: BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    ) -> Result<()> {
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
                    Ok(msg)            => node.dispatch(msg, &peer).await,
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

    async fn dispatch(&self, msg: Message, src: &Arc<PeerConn>) {
        match msg {
            Message::Onion(o)       => self.handle_onion(o).await,
            Message::DhtFind(f)     => self.handle_dht_find(f, src).await,
            Message::DhtFound(f)    => self.handle_dht_found(f),
            Message::DhtStore(s)    => self.dht.put(s.key, s.value),
            Message::DhtFetch(f)    => self.handle_dht_fetch(f, src).await,
            Message::HsRegister(r)  => self.dht.put_hs(&r.descriptor),
            Message::HsLookup(l)    => self.handle_hs_lookup(l, src).await,
            Message::BoardPost(p)   => self.handle_board_post(p, src).await,
            Message::BoardFetch(f)  => self.handle_board_fetch(f, src).await,
            Message::Padding(_)     => {} // cover traffic, discard
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

    /// Broadcast a hidden-service descriptor to all connected peers and store in DHT.
    pub async fn broadcast_hs(&self, descriptor: crate::wire::HsDescriptor) {
        self.dht.put_hs(&descriptor);
        let peers = self.peers.read().await;
        for p in peers.values() {
            let _ = p.send_msg(&Message::HsRegister(crate::wire::HsRegister {
                descriptor: descriptor.clone(),
            })).await;
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

    async fn rotation_loop(&self) {
        loop {
            time::sleep(ROTATE_INTERVAL).await;
            info!("Rotating cert…");
            let old = self.cert.read().unwrap().clone();
            match old.rotate() {
                Ok(new_cert) => { *self.cert.write().unwrap() = new_cert; }
                Err(e)       => warn!("Cert rotation: {}", e),
            }
        }
    }
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}
