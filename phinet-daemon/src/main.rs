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
            node.broadcast_hs(desc).await;
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
    let mut ctl_port      = 7799u16;
    let mut reset         = false;
    let mut _high_sec      = false;
    let mut verbose       = false;
    let mut i             = 1usize;

    while i < args.len() {
        match args[i].as_str() {
            "--port"            => { port     = args.get(i+1).and_then(|s| s.parse().ok()).unwrap_or(7700); i += 1; }
            "--host"            => { host     = args.get(i+1).cloned().unwrap_or_else(|| "0.0.0.0".into()); i += 1; }
            "--ctl-port"        => { ctl_port = args.get(i+1).and_then(|s| s.parse().ok()).unwrap_or(7799); i += 1; }
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

    // Bootstrap
    if !bootstrap.is_empty() {
        let bn = Arc::clone(&node);
        let bp = bootstrap.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_millis(500)).await;
            bn.bootstrap(bp).await;
        });
    }

    node.run().await?;
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
