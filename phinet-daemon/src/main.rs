// phinet-daemon/src/main.rs
//! ΦNET Daemon — network node + JSON control socket on 127.0.0.1:7799

use anyhow::{Context, Result};
use phinet_core::{
    cert::{CertBits, PhiCert, WireCert},
    node::PhiNode,
    store::{identity_path, sites_dir, SiteStore},
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time,
};
use tracing::{info, warn};

// ── Identity ──────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct SavedIdentity {
    cert: WireCert,
}

fn load_or_create(bits: CertBits, reset: bool) -> Result<PhiCert> {
    let path = identity_path();
    std::fs::create_dir_all(path.parent().unwrap())?;

    if !reset && path.exists() {
        if let Ok(json) = std::fs::read_to_string(&path) {
            if let Ok(saved) = serde_json::from_str::<SavedIdentity>(&json) {
                if let Ok(cert) = PhiCert::from_wire(&saved.cert) {
                    if cert.verify() {
                        info!("Loaded identity from {}", path.display());
                        return Ok(cert);
                    }
                }
            }
        }
        warn!("Saved identity invalid — regenerating");
    }

    info!("Generating {}-bit ΦNET identity…", bits.bits());
    let cert  = PhiCert::generate(bits).context("cert generation failed")?;
    let saved = serde_json::to_string_pretty(&SavedIdentity { cert: cert.to_wire() })?;
    std::fs::write(&path, saved)?;

    // Restrict permissions so only the owner can read/write. This is
    // defense in depth: even though the file currently only holds
    // public cert material, if we later add private-key storage here
    // the file permissions already protect it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path,
            std::fs::Permissions::from_mode(0o600));
    }

    info!("Identity saved to {}", path.display());
    Ok(cert)
}

// ── Control socket ────────────────────────────────────────────────────

#[derive(Deserialize)]
#[allow(dead_code)]
struct Req {
    cmd:      String,
    hs_id:    Option<String>,
    path:     Option<String>,
    method:   Option<String>,
    name:     Option<String>,
    channel:  Option<String>,
    text:     Option<String>,
}

#[derive(Serialize)]
struct Resp {
    ok:    bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(flatten)]
    data:  serde_json::Value,
}

impl Resp {
    fn ok(data: serde_json::Value) -> Self { Self { ok: true,  error: None,               data } }
    fn err(msg: &str)              -> Self { Self { ok: false, error: Some(msg.to_string()), data: serde_json::Value::Null } }
}

async fn run_ctl(node: Arc<PhiNode>, port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let srv  = TcpListener::bind(&addr).await?;
    info!("Control socket on {}", addr);
    loop {
        let (conn, _) = srv.accept().await?;
        let n = Arc::clone(&node);
        tokio::spawn(async move {
            if let Err(e) = handle_ctl(conn, n).await { tracing::debug!("ctl: {}", e); }
        });
    }
}

/// Serve the cached consensus over plain HTTP/1.1.
///
/// **Bind address: 127.0.0.1**. The endpoint is intended to be
/// fronted by a TLS-terminating reverse proxy (nginx/Caddy/Apache)
/// that handles the HTTPS cert and forwards to this. We don't bind
/// 0.0.0.0 because that would publish raw HTTP on the public
/// internet — operationally legitimate but easy to misconfigure.
/// If you want public exposure, set up the reverse proxy. If you
/// want to bypass it, change the bind address yourself; the model
/// is documented in `phinet-core/src/consensus_fetch.rs`.
///
/// Endpoints:
///   - `GET /consensus.json` → JSON-serialized cached consensus
///   - `GET /consensus.hash` → hex SHA-256 of canonical consensus bytes
///                              (cheap diff-check for clients)
///   - other paths → 404
///
/// Returns 503 if no consensus is cached yet (authority hasn't run
/// merge-votes). Clients should retry later.
async fn serve_consensus_http(node: Arc<PhiNode>, port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let srv  = TcpListener::bind(&addr).await
        .with_context(|| format!("bind consensus HTTP on {}", addr))?;
    info!("Consensus HTTP on {}", addr);

    loop {
        let (conn, _) = srv.accept().await?;
        let n = Arc::clone(&node);
        tokio::spawn(async move {
            if let Err(e) = handle_consensus_http(conn, n).await {
                tracing::debug!("consensus http: {}", e);
            }
        });
    }
}

async fn handle_consensus_http(stream: TcpStream, node: Arc<PhiNode>) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    // Parse request line: METHOD PATH HTTP/1.1
    let mut req_line = String::new();
    reader.read_line(&mut req_line).await?;
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        let _ = wr.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
        return Ok(());
    }
    let method = parts[0];
    let path   = parts[1];

    // Drain headers (we don't care about them but must consume to
    // avoid a half-closed read leaving bytes in the socket).
    loop {
        let mut h = String::new();
        let n = reader.read_line(&mut h).await?;
        if n == 0 { break; }
        if h.trim_end_matches(&['\r', '\n'][..]).is_empty() { break; }
    }

    if method != "GET" && method != "HEAD" {
        let _ = wr.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\
                              Allow: GET, HEAD\r\n\
                              Content-Length: 0\r\n\r\n").await;
        return Ok(());
    }

    let cached = node.cached_consensus.read().await;
    let consensus = match cached.as_ref() {
        Some(c) => c.clone(),
        None => {
            let _ = wr.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\n\
                  Content-Type: text/plain\r\n\
                  Content-Length: 31\r\n\r\n\
                  no consensus cached on this host"
            ).await;
            return Ok(());
        }
    };
    drop(cached);

    match path {
        "/consensus.json" => {
            let body = serde_json::to_vec_pretty(&consensus)?;
            let head = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: max-age=300\r\n\
                 Connection: close\r\n\r\n",
                body.len());
            wr.write_all(head.as_bytes()).await?;
            if method == "GET" {
                wr.write_all(&body).await?;
            }
        }
        "/consensus.hash" => {
            let hash = phinet_core::directory::consensus_hash(&consensus);
            let body = format!("{}\n", hex::encode(hash));
            let head = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len());
            wr.write_all(head.as_bytes()).await?;
            if method == "GET" {
                wr.write_all(body.as_bytes()).await?;
            }
        }
        _ => {
            let _ = wr.write_all(
                b"HTTP/1.1 404 Not Found\r\n\
                  Content-Type: text/plain\r\n\
                  Content-Length: 9\r\n\r\n\
                  not found"
            ).await;
        }
    }
    let _ = wr.shutdown().await;
    Ok(())
}

async fn handle_ctl(stream: TcpStream, node: Arc<PhiNode>) -> Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    while let Some(line) = lines.next_line().await? {
        let resp = match serde_json::from_str::<Req>(&line) {
            Err(e)  => Resp::err(&format!("parse: {}", e)),
            Ok(req) => dispatch(&req, &node).await,
        };
        let mut out = serde_json::to_string(&resp)?;
        out.push('\n');
        wr.write_all(out.as_bytes()).await?;
    }
    Ok(())
}

async fn dispatch(req: &Req, node: &Arc<PhiNode>) -> Resp {
    match req.cmd.as_str() {
        "ping" => Resp::ok(serde_json::json!({ "version": 2 })),

        "whoami" => {
            let cert = node.cert.read().unwrap().clone();
            Resp::ok(serde_json::json!({
                "node_id":   cert.node_id_hex(),
                "cert_bits": cert.bits.bits(),
                "dr":        cert.dr,
                "mu":        cert.mu,
                "sg":        cert.sg,
                "cluster_id": cert.cluster_id_hex(),
                "peers":     node.routing.peer_count(),
                "dht_keys":  node.dht.keys().len(),
                "listen":    format!("{}:{}", node.host, node.port),
            }))
        }

        "peers" => {
            let peers = node.all_peers().await;
            Resp::ok(serde_json::json!({
                "count": peers.len(),
                "peers": peers.iter().map(|p| serde_json::json!({
                    "node_id": p.node_id_hex(),
                    "host":    p.host,
                    "port":    p.port,
                })).collect::<Vec<_>>(),
            }))
        }

        "hs_fetch" => {
            let hs_id = req.hs_id.as_deref().unwrap_or("");
            let path  = req.path.as_deref().unwrap_or("/");
            match node.store.get_file(hs_id, path).await {
                Some((status, ct, body)) => Resp::ok(serde_json::json!({
                    "status":   status,
                    "headers":  { "Content-Type": ct },
                    "body_b64": hex::encode(&body),
                })),
                None => {
                    // Check DHT for network descriptor
                    if let Some(desc) = node.dht.get_hs(hs_id) {
                        Resp::ok(serde_json::json!({
                            "status":   503,
                            "headers":  { "Content-Type": "text/html" },
                            "body_b64": hex::encode(
                                format!("<h1>Service in DHT but intro not yet reachable</h1><p>{:?}:{:?}</p>",
                                        desc.intro_host, desc.intro_port).as_bytes()
                            ),
                        }))
                    } else {
                        Resp::ok(serde_json::json!({
                            "status":   404,
                            "headers":  { "Content-Type": "text/html" },
                            "body_b64": hex::encode(b"<h1>Not found</h1>"),
                        }))
                    }
                }
            }
        }

        "hs_register" => {
            let name = req.name.as_deref().unwrap_or("").to_string();
            let hs   = node.register_hs(&name).await;
            let desc = hs.descriptor(Some(&detect_ip()), Some(node.port + 1));
            node.broadcast_hs(desc, &hs.identity).await;
            Resp::ok(serde_json::json!({
                "hs_id":     hs.hs_id,
                "name":      hs.name,
                "intro_pub": hex::encode(hs.intro_pub.as_bytes()),
            }))
        }

        "board_post" => {
            let ch   = req.channel.as_deref().unwrap_or("general");
            let text = req.text.as_deref().unwrap_or("");
            node.post_to_board(ch, text).await;
            Resp::ok(serde_json::json!({ "posted": true }))
        }

        "board_read" => {
            let ch    = req.channel.as_deref().unwrap_or("general");
            let posts = node.board.get(ch, 50);
            Resp::ok(serde_json::json!({ "posts": posts }))
        }

        "status" => {
            let svcs = node.store.list_services().await;
            Resp::ok(serde_json::json!({
                "local_services": svcs.len(),
                "peers":          node.routing.peer_count(),
                "dht_keys":       node.dht.keys().len(),
            }))
        }

        "connect" => {
            // Connect to a bootstrap peer: {"cmd":"connect","host":"1.2.3.4","port":7700}
            let host = req.name.as_deref().unwrap_or("").to_string();
            let port = req.path.as_deref()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(7700);
            if host.is_empty() {
                Resp::err("missing host (use 'name' field)")
            } else {
                let node = Arc::clone(node);
                tokio::spawn(async move {
                    node.bootstrap(vec![(host, port)]).await;
                });
                Resp::ok(serde_json::json!({ "connecting": true }))
            }
        }

        "circuit_status" => {
            let (origins, relays) = node.circuit_status().await;
            Resp::ok(serde_json::json!({
                "origins": origins,
                "relays":  relays,
            }))
        }

        "build_circuit" => {
            // Path is a comma-separated list of "node_id_hex@host:port"
            // Example: {"cmd":"build_circuit","path":"ab..@1.2.3.4:7700,cd..@5.6.7.8:7700"}
            let path_str = req.text.as_deref().unwrap_or("").trim();
            if path_str.is_empty() {
                return Resp::err("missing 'text' field with comma-separated path");
            }

            let mut path = Vec::new();
            for entry in path_str.split(',') {
                let entry = entry.trim();
                let Some((id_hex, addr)) = entry.split_once('@') else {
                    return Resp::err(&format!("malformed hop: {entry} (want id@host:port)"));
                };
                let Ok(id_vec) = hex::decode(id_hex) else {
                    return Resp::err(&format!("bad hex in node_id: {id_hex}"));
                };
                if id_vec.len() != 32 {
                    return Resp::err(&format!("node_id must be 32 bytes, got {}", id_vec.len()));
                }
                let Some((host, port_str)) = addr.rsplit_once(':') else {
                    return Resp::err(&format!("malformed addr: {addr}"));
                };
                let Ok(port) = port_str.parse::<u16>() else {
                    return Resp::err(&format!("bad port: {port_str}"));
                };
                let mut id = [0u8; 32];
                id.copy_from_slice(&id_vec);

                // Look up the peer's x25519 static public key from the
                // node's peer table. Without it, the ntor handshake
                // can't be addressed to this hop, so the circuit-build
                // would time out. The hop must already be a connected
                // peer for this to work.
                let static_pub: [u8; 32] = {
                    let peers = node.peers_snapshot().await;
                    let Some(peer) = peers.iter().find(|p| p.node_id == id) else {
                        return Resp::err(&format!(
                            "hop {} not a connected peer — phi peer connect first",
                            hex::encode(&id[..6])
                        ));
                    };
                    match hex::decode(&peer.static_pub)
                        .ok()
                        .and_then(|v| v.try_into().ok())
                    {
                        Some(b) => b,
                        None => return Resp::err(
                            "peer's static_pub is corrupted in peer table"),
                    }
                };

                path.push(phinet_core::circuit::LinkSpec {
                    host:       host.to_string(),
                    port,
                    node_id:    id,
                    static_pub,
                });
            }

            let node = Arc::clone(node);
            match node.build_circuit(path).await {
                Ok(cid) => Resp::ok(serde_json::json!({
                    "circ_id": cid.0,
                    "hops":    path_str.split(',').count(),
                })),
                Err(e) => Resp::err(&format!("build_circuit: {e}")),
            }
        }

        "auto_circuit" => {
            // Build a circuit using consensus-weighted path selection.
            //
            // Request: {"cmd":"auto_circuit"}
            //   Optionally provide "consensus_path" pointing at a JSON
            //   ConsensusDocument file. Otherwise we construct an
            //   ad-hoc consensus from currently-connected peers (fine
            //   for a small private network, not what production
            //   would use).
            //
            // The selector picks 3 hops weighted by bandwidth, with
            // /16 subnet diversity, GUARD/EXIT flag constraints, and
            // self-exclusion. Returns the constructed circuit ID.
            use phinet_core::directory::{ConsensusDocument, PeerEntry, PeerFlags};
            use phinet_core::path_select::{select_path, PathError};

            let consensus = if let Some(path) = req.text.as_deref() {
                // Operator passed a consensus file path.
                match std::fs::read_to_string(path)
                    .ok()
                    .and_then(|s| serde_json::from_str::<ConsensusDocument>(&s).ok())
                {
                    Some(c) => c,
                    None => return Resp::err(
                        &format!("could not load/parse consensus from {path}")),
                }
            } else {
                // Construct an ad-hoc consensus from connected peers.
                // Every peer gets STABLE+FAST+GUARD+EXIT+RUNNING+VALID
                // because in a small private network every peer is
                // expected to do everything. Bandwidth is set to 1000
                // for all peers (uniform random selection).
                let peers = node.peers_snapshot().await;
                if peers.len() < 3 {
                    return Resp::err(&format!(
                        "auto_circuit: need ≥3 connected peers, have {}",
                        peers.len()));
                }
                let entries: Vec<PeerEntry> = peers.iter().map(|p| {
                    PeerEntry {
                        node_id_hex:    hex::encode(p.node_id),
                        host:           p.host.clone(),
                        port:           p.port,
                        static_pub_hex: p.static_pub.clone(),
                        flags: (PeerFlags::STABLE | PeerFlags::FAST
                                | PeerFlags::GUARD | PeerFlags::EXIT
                                | PeerFlags::RUNNING | PeerFlags::VALID).bits(),
                        bandwidth_kbs: 1000,
                        exit_policy_summary: String::new(),
                    }
                }).collect();
                ConsensusDocument {
                    network_id: "phinet-local".to_string(),
                    valid_after: 0,
                    valid_until: u64::MAX,
                    peers: entries,
                    signatures: Vec::new(),
                }
            };

            // Exclude our own node_id so we don't pick ourselves.
            let self_id = hex::encode(node.node_id());
            // OsRng is Send (unlike thread_rng which has thread-local
            // state) so the future containing it can cross threads.
            let mut rng = rand::rngs::OsRng;
            let path = match select_path(&mut rng, &consensus, &[self_id], None) {
                Ok(p) => p,
                Err(PathError::InsufficientRelays(s)) => {
                    return Resp::err(&format!("path selection: {s}"));
                }
            };

            let specs = match path.to_link_specs() {
                Ok(s) => s,
                Err(e) => return Resp::err(&format!("link spec conversion: {e}")),
            };
            let hop_summary: Vec<String> = path.hops.iter()
                .map(|h| format!("{}…@{}:{}", &h.node_id_hex[..8], h.host, h.port))
                .collect();

            let node = Arc::clone(node);
            match node.build_circuit(specs).await {
                Ok(cid) => Resp::ok(serde_json::json!({
                    "circ_id": cid.0,
                    "hops":    hop_summary,
                    "method":  "auto_select",
                })),
                Err(e) => Resp::err(&format!("auto_circuit build: {e}")),
            }
        }

        "bw_measure" => {
            // Measure throughput through a target relay by building
            // a 2-hop circuit (target → helper) and timing how fast
            // bytes flow back. Used by the bandwidth scanner.
            //
            // Request:
            //   {"cmd":"bw_measure",
            //    "hs_id":"<target relay node_id_hex>",
            //    "text":"<helper relay node_id_hex>",   // optional
            //    "method":"<bytes>" }                   // optional, default 1MB
            //
            // The "method" field carries the payload byte count
            // (sloppy but the Req struct is fixed and we don't have
            // a free numeric field).
            //
            // Returns: { bw_kbs, rtt_ms, bytes_received, success }
            //
            // Caveat: this needs at least one helper relay connected
            // to the target. In a small network this is the case
            // because everyone connects to everyone; in production
            // the scanner would specify the helper explicitly.
            use phinet_core::circuit::LinkSpec;

            let target_hex = match req.hs_id.as_deref() {
                Some(s) => s,
                None    => return Resp::err("bw_measure: missing hs_id (target node_id)"),
            };
            let target_id = match hex::decode(target_hex) {
                Ok(v) if v.len() == 32 => {
                    let mut a = [0u8; 32]; a.copy_from_slice(&v); a
                }
                _ => return Resp::err("bw_measure: bad target node_id_hex"),
            };

            let payload_bytes: usize = req.method.as_deref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1024 * 1024);

            let peers = node.peers_snapshot().await;
            let target_peer = peers.iter().find(|p| p.node_id == target_id);
            let target_peer = match target_peer {
                Some(p) => p,
                None    => return Resp::err(&format!(
                    "bw_measure: target {} is not in peer table — connect to it first",
                    &target_hex[..16])),
            };

            // Pick a helper: either explicit from req.text, or the
            // first peer that isn't us and isn't the target.
            let self_id = node.node_id();
            let helper_peer = if let Some(htxt) = req.text.as_deref() {
                let h = match hex::decode(htxt) {
                    Ok(v) if v.len() == 32 => {
                        let mut a = [0u8; 32]; a.copy_from_slice(&v); a
                    }
                    _ => return Resp::err("bw_measure: bad helper node_id_hex"),
                };
                peers.iter().find(|p| p.node_id == h)
            } else {
                peers.iter().find(|p|
                    p.node_id != self_id && p.node_id != target_id)
            };
            let helper_peer = match helper_peer {
                Some(p) => p,
                None    => return Resp::err(
                    "bw_measure: no helper available (need ≥2 connected peers)"),
            };

            let target_pub = match hex::decode(&target_peer.static_pub) {
                Ok(v) if v.len() == 32 => {
                    let mut a = [0u8; 32]; a.copy_from_slice(&v); a
                }
                _ => return Resp::err("bw_measure: target static_pub bad hex"),
            };
            let helper_pub = match hex::decode(&helper_peer.static_pub) {
                Ok(v) if v.len() == 32 => {
                    let mut a = [0u8; 32]; a.copy_from_slice(&v); a
                }
                _ => return Resp::err("bw_measure: helper static_pub bad hex"),
            };

            let specs = vec![
                LinkSpec {
                    host:       target_peer.host.clone(),
                    port:       target_peer.port,
                    node_id:    target_id,
                    static_pub: target_pub,
                },
                LinkSpec {
                    host:       helper_peer.host.clone(),
                    port:       helper_peer.port,
                    node_id:    helper_peer.node_id,
                    static_pub: helper_pub,
                },
            ];

            let t_build_start = std::time::Instant::now();
            let cid = match Arc::clone(node).build_circuit(specs).await {
                Ok(c) => c,
                Err(e) => return Resp::err(&format!("bw_measure: circuit build: {e}")),
            };
            let build_ms = t_build_start.elapsed().as_millis() as u32;

            // Open a bw-test:<N> stream to the helper (last hop).
            // The helper's BEGIN handler intercepts the sentinel
            // target and emits N pseudorandom bytes locally — no
            // network egress, no exit-policy involvement. We time
            // first-byte and total arrival to compute throughput.
            let target_str = format!("bw-test:{}", payload_bytes);
            let (stream_id, mut rx, ready) =
                match node.stream_open(cid, &target_str).await {
                    Ok(t) => t,
                    Err(e) => {
                        let _ = node.destroy_circuit(cid).await;
                        return Resp::err(&format!("bw_measure: stream_open: {e}"));
                    }
                };

            // Wait for CONNECTED to fire so the timer doesn't include
            // RELAY_BEGIN dispatch latency. Bound the wait.
            if let Err(_) = tokio::time::timeout(
                std::time::Duration::from_secs(15), ready
            ).await {
                let _ = node.stream_close(cid, stream_id,
                    phinet_core::stream::EndReason::Internal).await;
                let _ = node.destroy_circuit(cid).await;
                return Resp::err("bw_measure: stream did not reach Open within 15s");
            }

            let t_first_byte: Option<std::time::Instant>;
            let mut received: usize = 0;
            let t_recv_start = std::time::Instant::now();

            // First byte: wait up to 30s
            let first_chunk = tokio::time::timeout(
                std::time::Duration::from_secs(30), rx.recv()
            ).await;
            t_first_byte = Some(std::time::Instant::now());
            match first_chunk {
                Ok(Some(buf)) => received += buf.len(),
                Ok(None) => {
                    let _ = node.destroy_circuit(cid).await;
                    return Resp::err("bw_measure: stream closed before any data");
                }
                Err(_) => {
                    let _ = node.destroy_circuit(cid).await;
                    return Resp::err("bw_measure: no data within 30s of stream open");
                }
            }

            // Drain remaining chunks until EOF or full payload.
            while received < payload_bytes {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(60), rx.recv()
                ).await {
                    Ok(Some(buf)) => received += buf.len(),
                    Ok(None) => break, // helper closed stream
                    Err(_)   => break, // timeout — accept what we got
                }
            }

            let t_done = std::time::Instant::now();
            let transfer_ms = t_first_byte
                .map(|t| t_done.duration_since(t).as_millis().max(1) as u64)
                .unwrap_or(1);
            let total_ms = t_recv_start.elapsed().as_millis().max(1) as u64;

            // bw_kbs = bytes / (transfer_secs) / 1024 (kibibytes).
            // We use the post-first-byte window so circuit-build and
            // queue-warmup don't depress the number; it's the
            // steady-state throughput.
            let bw_kbs = ((received as u64) * 1000 / transfer_ms / 1024) as u32;

            // rtt_ms reports the time to first byte after stream
            // open: this is the round-trip across the 2 hops, a
            // useful auxiliary signal for "is this relay overloaded?"
            let rtt_ms = t_first_byte
                .map(|t| t.duration_since(t_recv_start).as_millis() as u32)
                .unwrap_or(0);

            // Tear down stream and circuit
            let _ = node.stream_close(cid, stream_id,
                phinet_core::stream::EndReason::Done).await;
            let _ = node.destroy_circuit(cid).await;

            Resp::ok(serde_json::json!({
                "bw_kbs":         bw_kbs,
                "rtt_ms":         rtt_ms,
                "bytes_received": received,
                "bytes_requested": payload_bytes,
                "transfer_ms":    transfer_ms,
                "total_ms":       total_ms,
                "build_ms":       build_ms,
                "success":        received > 0,
                "circuit_method": "2hop_target_then_helper_bw_test",
            }))
        }

        "consensus_load" => {
            // Load a consensus document from disk and install it
            // into cached_consensus after verification.
            //
            // Request: {"cmd":"consensus_load","text":"/path/to/consensus.json"}
            let path = match req.text.as_deref() {
                Some(p) => p,
                None    => return Resp::err("consensus_load: missing text (path)"),
            };
            let bytes = match std::fs::read_to_string(path) {
                Ok(b) => b,
                Err(e) => return Resp::err(&format!("read {}: {}", path, e)),
            };
            let consensus: phinet_core::directory::ConsensusDocument =
                match serde_json::from_str(&bytes) {
                    Ok(c) => c,
                    Err(e) => return Resp::err(&format!("parse: {}", e)),
                };
            match phinet_core::consensus_fetch::install_consensus(node, consensus).await {
                Ok(updated) => Resp::ok(serde_json::json!({"updated": updated})),
                Err(e)      => Resp::err(&e),
            }
        }

        other => Resp::err(&format!("unknown command: {}", other)),
    }
}

// ── Main ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut port          = 7700u16;
    let mut host          = "0.0.0.0".to_string();
    let mut bootstrap     = Vec::<(String, u16)>::new();
    let mut cert_bits     = CertBits::B256;
    let mut ctl_port       = 7799u16;
    let mut consensus_port: Option<u16> = None;
    let mut reset         = false;
    let mut _high_sec      = false;
    let mut verbose       = false;
    let mut client_only   = false;
    let mut trusted_auths = Vec::<[u8; 32]>::new();
    let mut consensus_url: Option<String> = None;
    let mut consensus_path: Option<String> = None;
    let mut i             = 1usize;

    while i < args.len() {
        match args[i].as_str() {
            "--port"            => { port     = args.get(i+1).and_then(|s| s.parse().ok()).unwrap_or(7700); i += 1; }
            "--host"            => { host     = args.get(i+1).cloned().unwrap_or_else(|| "0.0.0.0".into()); i += 1; }
            "--ctl-port"        => { ctl_port = args.get(i+1).and_then(|s| s.parse().ok()).unwrap_or(7799); i += 1; }
            "--consensus-port"  => { consensus_port = args.get(i+1).and_then(|s| s.parse().ok()); i += 1; }
            "--cert-bits"       => {
                cert_bits = match args.get(i+1).map(|s| s.as_str()) {
                    Some("512")  => CertBits::B512,
                    Some("1024") => CertBits::B1024,
                    Some("2048") => CertBits::B2048,
                    _            => CertBits::B256,
                };
                i += 1;
            }
            "--bootstrap"       => {
                if let Some(s) = args.get(i+1) {
                    if let Some((h, p)) = s.rsplit_once(':') {
                        if let Ok(p) = p.parse::<u16>() {
                            let h = h.to_string();
                            // Skip obviously wrong values
                            if !h.is_empty() && h != "0.0.0.0" {
                                bootstrap.push((h, p));
                            } else {
                                eprintln!("Warning: ignoring --bootstrap {} (use a real remote IP, e.g. 1.2.3.4:7700)", s);
                            }
                        }
                    } else {
                        // No port specified — try with default port 7700
                        let h = s.trim().to_string();
                        if !h.is_empty() && h != "0.0.0.0" {
                            bootstrap.push((h, 7700));
                        } else {
                            eprintln!("Usage: --bootstrap <host>:<port>  e.g. --bootstrap 1.2.3.4:7700");
                        }
                    }
                } else {
                    eprintln!("Usage: --bootstrap <host>:<port>  e.g. --bootstrap 1.2.3.4:7700");
                }
                i += 1;
            }
            "--reset-identity"  => reset    = true,
            "--high-security"   => _high_sec = true,
            "--verbose" | "-v"  => verbose  = true,

            // Client-only mode: don't bind a listener. Outbound
            // circuits and HS fetch still work; this node just
            // doesn't accept inbound connections.
            "--client-only"     => client_only = true,

            // Add a trusted directory authority by hex-encoded
            // Ed25519 public key (32 bytes = 64 hex chars). Repeat
            // the flag to add multiple. Without these, consensus
            // verification will reject every consensus.
            "--trusted-authority" => {
                if let Some(s) = args.get(i+1) {
                    match hex::decode(s.trim()) {
                        Ok(v) if v.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            trusted_auths.push(arr);
                        }
                        _ => eprintln!("Warning: --trusted-authority {} is not 32-byte hex; ignored", s),
                    }
                } else {
                    eprintln!("Usage: --trusted-authority <64-hex-char Ed25519 pubkey>");
                }
                i += 1;
            }

            // URL of an HTTPS-served consensus document. The daemon
            // periodically fetches this, verifies the signatures
            // against --trusted-authority, and uses it for path
            // selection. Mutually exclusive with --consensus-path.
            "--consensus-url" => {
                if let Some(s) = args.get(i+1) {
                    consensus_url = Some(s.clone());
                } else {
                    eprintln!("Usage: --consensus-url <https://auth.example.com/consensus.json>");
                }
                i += 1;
            }

            // Local file path to a consensus document. Useful for
            // testnets where the operator places the consensus on
            // disk rather than serving it over HTTPS. Mutually
            // exclusive with --consensus-url.
            "--consensus-path" => {
                if let Some(s) = args.get(i+1) {
                    consensus_path = Some(s.clone());
                } else {
                    eprintln!("Usage: --consensus-path </path/to/consensus.json>");
                }
                i += 1;
            }

            _                   => {}
        }
        i += 1;
    }

    tracing_subscriber::fmt()
        .with_env_filter(if verbose { "debug" } else { "info" })
        .init();

    let cert  = load_or_create(cert_bits, reset)?;
    let store = Arc::new(SiteStore::new());
    let node  = PhiNode::new(&host, port, cert, store);

    // Apply --client-only flag.
    if client_only {
        node.client_only.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    // Populate trusted directory authorities. Without at least one,
    // consensus verification rejects every consensus, which means
    // path selection has no consensus to consult.
    if !trusted_auths.is_empty() {
        let mut guard = node.trusted_authorities.write().await;
        *guard = trusted_auths.clone();
        info!("Trusted authorities: {}", trusted_auths.len());
    } else if client_only {
        warn!("--client-only without --trusted-authority; consensus verification will fail");
    }

    // Mutual exclusion between consensus-url and consensus-path.
    if consensus_url.is_some() && consensus_path.is_some() {
        anyhow::bail!("--consensus-url and --consensus-path are mutually exclusive");
    }

    // Background loop: periodically refresh the consensus.
    if let Some(url) = consensus_url.clone() {
        let n = Arc::clone(&node);
        tokio::spawn(async move {
            phinet_core::consensus_fetch::refresh_loop_url(n, url).await;
        });
    } else if let Some(path) = consensus_path.clone() {
        let n = Arc::clone(&node);
        tokio::spawn(async move {
            phinet_core::consensus_fetch::refresh_loop_path(n, path).await;
        });
    }

    // high_security cannot be set after Arc creation — use a wrapper or re-init
    // For now, high_security is false by default (can be toggled via ctl later)

    print_banner(&node, ctl_port);

    // Control socket
    let ctl_node = Arc::clone(&node);
    tokio::spawn(async move {
        if let Err(e) = run_ctl(ctl_node, ctl_port).await {
            warn!("Control: {}", e);
        }
    });

    // Consensus HTTP endpoint (default ctl_port + 1 = 7800).
    // Serves the cached_consensus as JSON to anyone who GETs
    // /consensus.json. This is the *publish* side — clients fetching
    // from a URL hit either this directly or (recommended) hit a
    // TLS-terminating reverse proxy that forwards here.
    //
    // Skip in client-only mode: a client doesn't publish a consensus.
    if !client_only {
        let cons_node = Arc::clone(&node);
        let cons_port = consensus_port.unwrap_or_else(|| ctl_port.wrapping_add(1));
        tokio::spawn(async move {
            if let Err(e) = serve_consensus_http(cons_node, cons_port).await {
                warn!("Consensus serve: {}", e);
            }
        });
    }

    // Bootstrap
    if !bootstrap.is_empty() {
        let bn = Arc::clone(&node);
        let bp = bootstrap.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_millis(500)).await;
            bn.bootstrap(bp).await;
        });
    }

    // Wire SIGINT/SIGTERM to a graceful shutdown. Without this the
    // daemon can only be stopped with SIGKILL, which drops in-flight
    // state (replay-cache writes, guard persistence, board flushes).
    // With this wiring, Ctrl-C / systemd stop triggers the same
    // idempotent shutdown path that integration tests use, giving
    // background loops a chance to finish cleanly.
    {
        let sn = Arc::clone(&node);
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                // Set up both handlers; race them against each other
                // so whichever fires first triggers shutdown.
                let mut sigint  = match signal(SignalKind::interrupt()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("signal handler setup failed: {e}");
                        return;
                    }
                };
                let mut sigterm = match signal(SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("signal handler setup failed: {e}");
                        return;
                    }
                };
                tokio::select! {
                    _ = sigint.recv()  => tracing::info!("SIGINT received"),
                    _ = sigterm.recv() => tracing::info!("SIGTERM received"),
                }
            }
            #[cfg(not(unix))]
            {
                // Windows: just ctrl_c. SIGTERM isn't a Windows concept.
                if let Err(e) = tokio::signal::ctrl_c().await {
                    tracing::warn!("ctrl_c handler: {e}");
                    return;
                }
                tracing::info!("ctrl_c received");
            }
            tracing::info!("shutting down gracefully…");
            sn.shutdown();
        });
    }

    node.run().await?;
    tracing::info!("daemon exited cleanly");
    Ok(())
}

fn print_banner(node: &Arc<PhiNode>, ctl_port: u16) {
    let cert = node.cert.read().unwrap();
    println!(r"
  ┌────────────────────────────────────────────────┐
  │              ΦNET Daemon v2                    │
  └────────────────────────────────────────────────┘

  Node ID:  {}…
  Cert:     {}-bit  dr={}  mu={}  sg={}
  Listen:   {}:{}
  Control:  127.0.0.1:{}
  Sites:    {}
",
        &cert.node_id_hex()[..16],
        cert.bits.bits(), cert.dr, cert.mu, cert.sg,
        node.host, node.port,
        ctl_port,
        sites_dir().display(),
    );
}

fn detect_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0").ok()
        .and_then(|s| { s.connect("8.8.8.8:80").ok()?; s.local_addr().ok() })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}
