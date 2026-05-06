// phinet-bwscanner/src/main.rs
//!
//! # phinet-bwscanner
//!
//! CLI driver around the bandwidth-scanner library. Reads a
//! consensus, runs measurements, writes a signed authority vote.
//!
//! Operators run this on a schedule (cron, systemd-timer) every
//! ~hour. The output votes are then exchanged with other authorities
//! out-of-band and merged into the next consensus.
//!
//! ## Usage
//!
//! ```bash
//! # Generate a fresh authority identity
//! phinet-bwscanner gen-identity --out ~/.phinet/auth.json
//!
//! # Run a scan against a consensus, writing a signed vote
//! phinet-bwscanner scan \
//!     --identity ~/.phinet/auth.json \
//!     --consensus /var/phinet/consensus.json \
//!     --output /var/phinet/votes/vote-$(date +%s).json \
//!     --network-id phinet-mainnet \
//!     --daemon-control 127.0.0.1:7799
//! ```
//!
//! In current form the scanner uses a **simulation transport** — it
//! doesn't drive real ΦNET circuit-build measurements. Wiring it
//! up to the daemon's control port for real measurements is one
//! integration step away (the trait is stable; just need a
//! `DaemonMeasurementTransport` implementation that talks to the
//! daemon over JSON-RPC). The scanner pipeline itself, vote
//! signing, and median aggregation are all production-ready.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use phinet_bwscanner::{
    BoxFuture, MeasurementTransport, RelayMeasurement, ScanConfig, Scanner,
};
use phinet_core::{
    directory::{ConsensusDocument, DirectoryAuthority, PeerEntry},
    hs_identity::HsIdentity,
};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "phinet-bwscanner",
          about = "Bandwidth scanner producing signed authority votes")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new directory-authority identity (long-term Ed25519).
    /// The resulting file is the root of trust for any consensus this
    /// authority signs. Keep it offline-secure.
    GenIdentity {
        #[arg(long)]
        out: PathBuf,
    },

    /// Run one full scan pass and write a signed vote.
    Scan {
        /// Path to the authority identity file (from gen-identity).
        #[arg(long)]
        identity: PathBuf,

        /// Path to the consensus document to scan against.
        #[arg(long)]
        consensus: PathBuf,

        /// Where to write the signed vote (JSON).
        #[arg(long)]
        output: PathBuf,

        /// Network identifier — must match the one in the consensus.
        #[arg(long, default_value = "phinet-mainnet")]
        network_id: String,

        /// Number of measurement passes per relay (median is reported).
        #[arg(long, default_value = "3")]
        passes: u32,

        /// Per-relay measurement timeout in seconds.
        #[arg(long, default_value = "60")]
        timeout_secs: u64,

        /// Use the simulation transport — generates random plausible
        /// bandwidth values instead of doing real measurements.
        /// Useful for testing the scanner pipeline end-to-end without
        /// a live network.
        #[arg(long)]
        simulate: bool,

        /// Control-port address of the phinet-daemon to use for
        /// real measurements. Ignored when --simulate is set.
        /// The daemon must already be connected to every relay
        /// being measured.
        #[arg(long, default_value = "127.0.0.1:7799")]
        daemon_control: String,
    },

    /// Print the public key of an authority identity. Operators
    /// publish this so clients can add it to their trusted-authority
    /// set.
    PubKey {
        #[arg(long)]
        identity: PathBuf,
    },

    /// Merge a set of votes from peer authorities into a signed
    /// consensus document. Each authority runs this independently
    /// after collecting votes; they should all produce byte-identical
    /// pre-signature canonical bytes (deterministic merge), so the
    /// signatures attached afterwards are interoperable.
    ///
    /// Usage:
    ///   phinet-bwscanner merge-votes \
    ///     --identity ~/.phinet/auth.json \
    ///     --network-id phinet-mainnet \
    ///     --output /var/phinet/consensus.json \
    ///     /var/phinet/votes/auth1.json \
    ///     /var/phinet/votes/auth2.json \
    ///     /var/phinet/votes/auth3.json
    ///
    /// The output document carries this authority's signature.
    /// Other authorities run the same command on their machines
    /// and the operator collects all the signed copies — any one
    /// of them that has ≥threshold valid sigs is publishable.
    MergeVotes {
        /// Path to this authority's identity file.
        #[arg(long)]
        identity: PathBuf,
        /// Network ID — must match what's in every vote.
        #[arg(long, default_value = "phinet-mainnet")]
        network_id: String,
        /// Path to write the signed consensus.
        #[arg(long)]
        output: PathBuf,
        /// Skip per-vote signature verification. Useful only for
        /// debugging — never use in production.
        #[arg(long)]
        skip_verify: bool,
        /// Vote JSON files (one per authority).
        votes: Vec<PathBuf>,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("phinet_bwscanner=info"))
        )
        .init();

    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    match cli.cmd {
        Cmd::GenIdentity { out } => {
            let id = HsIdentity::generate();
            id.save(&out).with_context(|| format!("save identity to {}", out.display()))?;
            println!("Generated authority identity at {}", out.display());
            println!("Public key: {}", hex::encode(id.public_key()));
            println!("\nDistribute this public key to clients and other authorities.");
        }

        Cmd::PubKey { identity } => {
            let id = HsIdentity::load(&identity)
                .with_context(|| format!("load identity from {}", identity.display()))?;
            println!("{}", hex::encode(id.public_key()));
        }

        Cmd::Scan { identity, consensus, output, network_id, passes, timeout_secs, simulate, daemon_control } => {
            rt.block_on(async {
                run_scan(RunScanArgs {
                    identity,
                    consensus,
                    output,
                    network_id,
                    passes,
                    timeout_secs,
                    simulate,
                    daemon_control,
                }).await
            })?;
        }

        Cmd::MergeVotes { identity, network_id, output, skip_verify, votes } => {
            run_merge(MergeArgs {
                identity, network_id, output, skip_verify, votes,
            })?;
        }
    }

    Ok(())
}

struct MergeArgs {
    identity:    PathBuf,
    network_id:  String,
    output:      PathBuf,
    skip_verify: bool,
    votes:       Vec<PathBuf>,
}

fn run_merge(args: MergeArgs) -> Result<()> {
    use phinet_core::directory::{
        build_consensus, verify_vote, AuthorityVote, DirectoryAuthority,
    };

    if args.votes.is_empty() {
        anyhow::bail!("merge-votes: provide at least one vote file");
    }

    let id = HsIdentity::load(&args.identity)
        .with_context(|| format!("load identity from {}", args.identity.display()))?;
    let auth = DirectoryAuthority::new(id, &args.network_id);

    let mut votes: Vec<AuthorityVote> = Vec::with_capacity(args.votes.len());
    for path in &args.votes {
        let bytes = std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        let vote: AuthorityVote = serde_json::from_str(&bytes)
            .with_context(|| format!("parse {}", path.display()))?;

        if !args.skip_verify {
            verify_vote(&vote)
                .map_err(|e| anyhow::anyhow!("vote {} self-verify failed: {:?}",
                    path.display(), e))?;
        }
        if vote.network_id != args.network_id {
            anyhow::bail!("vote {} has network_id={} but expected {}",
                path.display(), vote.network_id, args.network_id);
        }
        votes.push(vote);
    }

    tracing::info!("merging {} votes for network {}", votes.len(), args.network_id);

    let mut consensus = build_consensus(&args.network_id, &votes);
    auth.sign_consensus(&mut consensus);

    tracing::info!("consensus has {} peers, {} signatures",
        consensus.peers.len(), consensus.signatures.len());

    let json = serde_json::to_string_pretty(&consensus)
        .context("serialize consensus")?;
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&args.output, json)
        .with_context(|| format!("write {}", args.output.display()))?;

    tracing::info!("wrote signed consensus to {}", args.output.display());
    println!("{}", hex::encode(phinet_core::directory::consensus_hash(&consensus)));
    Ok(())
}

struct RunScanArgs {
    identity: PathBuf,
    consensus: PathBuf,
    output: PathBuf,
    network_id: String,
    passes: u32,
    timeout_secs: u64,
    simulate: bool,
    daemon_control: String,
}

async fn run_scan(args: RunScanArgs) -> Result<()> {
    let id = HsIdentity::load(&args.identity)
        .with_context(|| format!("load identity from {}", args.identity.display()))?;
    let auth = DirectoryAuthority::new(id, &args.network_id);

    let cons_bytes = std::fs::read_to_string(&args.consensus)
        .with_context(|| format!("read consensus from {}", args.consensus.display()))?;
    let consensus: ConsensusDocument = serde_json::from_str(&cons_bytes)
        .context("parse consensus JSON")?;

    if consensus.network_id != args.network_id {
        anyhow::bail!(
            "consensus network_id ({}) doesn't match --network-id ({})",
            consensus.network_id, args.network_id);
    }

    tracing::info!("scanning {} relays in network {}",
        consensus.peers.len(), consensus.network_id);

    let config = ScanConfig {
        passes: args.passes,
        per_relay_timeout: Duration::from_secs(args.timeout_secs),
        ..Default::default()
    };

    let transport: Box<dyn MeasurementTransport> = if args.simulate {
        tracing::warn!("using simulation transport — output is NOT real measurements");
        Box::new(SimulationTransport)
    } else {
        // Real-network mode: talk to a running phinet-daemon's
        // control port. The daemon must already be connected to
        // the relays we're measuring (see "scanner daemon"
        // discussion in OPERATING.md).
        let addr: std::net::SocketAddr = args.daemon_control.parse()
            .with_context(|| format!(
                "parse --daemon-control {}", args.daemon_control))?;
        tracing::info!("using daemon measurement transport at {}", addr);
        Box::new(DaemonMeasurementTransport::new(addr))
    };

    let scanner = Scanner::new(transport, config);
    let vote = scanner.run(&consensus.peers, &auth).await;

    // Verify before writing — defensive check that our own
    // signing produced a valid vote. If this fails, the
    // identity-load path is broken.
    phinet_core::directory::verify_vote(&vote)
        .context("our own vote failed self-verification")?;

    let json = serde_json::to_string_pretty(&vote).context("serialize vote")?;
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&args.output, json)
        .with_context(|| format!("write vote to {}", args.output.display()))?;

    tracing::info!("wrote signed vote to {}", args.output.display());
    let running = vote.peers.iter()
        .filter(|p| p.flags & phinet_core::directory::PeerFlags::RUNNING.bits() != 0)
        .count();
    tracing::info!("  {}/{} relays measured as RUNNING",
        running, vote.peers.len());

    Ok(())
}

/// Simulation transport: produces deterministic-but-plausible
/// bandwidth values based on the relay's node_id. Used for
/// pipeline testing without a live network.
///
/// Each relay's bandwidth is hash(node_id) % 5000 + 100 kBs, so
/// values range from 100 kBs to 5100 kBs. Stable across runs for
/// a given relay so consensus tests are reproducible.
struct SimulationTransport;

impl MeasurementTransport for SimulationTransport {
    fn measure<'a>(
        &'a self,
        relay: &'a PeerEntry,
        _config: &'a ScanConfig,
    ) -> BoxFuture<'a, RelayMeasurement> {
        Box::pin(async move {
            // Tiny artificial delay so timeouts can be tested if
            // someone really wants to. In real scans the per-relay
            // measurement takes seconds; we don't need to simulate
            // that exactly.
            tokio::time::sleep(Duration::from_millis(5)).await;

            // Hash the node_id to derive a stable bandwidth value
            let mut h: u64 = 0xcbf29ce484222325;
            for b in relay.node_id_hex.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            let bw_kbs = ((h % 5000) + 100) as u32;

            RelayMeasurement {
                node_id_hex: relay.node_id_hex.clone(),
                bw_kbs,
                rtt_ms: 50 + ((h % 100) as u32),
                success: true,
                error: None,
            }
        })
    }
}

/// Real-network measurement transport. Connects to a running
/// `phinet-daemon`'s control port (default 127.0.0.1:7799) and
/// invokes `bw_measure` for each relay, returning the daemon's
/// observed throughput.
///
/// The daemon must:
///   - Be already connected to the target relay (the bw_measure
///     command requires the target in its peer table)
///   - Have ≥1 other peer that can serve as a 2-hop helper
///
/// In a deployment, the authority operates a "scanner daemon" that
/// connects to every relay in the consensus and runs measurements.
/// This crate's responsibility ends at the control-port boundary;
/// the scanner daemon's bootstrap connectivity is operator concern.
struct DaemonMeasurementTransport {
    control_addr: std::net::SocketAddr,
}

impl DaemonMeasurementTransport {
    fn new(control_addr: std::net::SocketAddr) -> Self {
        Self { control_addr }
    }
}

impl MeasurementTransport for DaemonMeasurementTransport {
    fn measure<'a>(
        &'a self,
        relay: &'a phinet_core::directory::PeerEntry,
        config: &'a ScanConfig,
    ) -> BoxFuture<'a, RelayMeasurement> {
        Box::pin(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            use tokio::net::TcpStream;

            // Build the JSON-RPC request the daemon's handle_ctl expects.
            let req = serde_json::json!({
                "cmd":    "bw_measure",
                "hs_id":  relay.node_id_hex,
                "method": config.payload_bytes.to_string(),
            });
            let req_str = match serde_json::to_string(&req) {
                Ok(s) => s,
                Err(e) => return failed(&relay.node_id_hex,
                    format!("serialize req: {e}")),
            };

            // Connect, send, read line.
            let stream = match TcpStream::connect(self.control_addr).await {
                Ok(s) => s,
                Err(e) => return failed(&relay.node_id_hex,
                    format!("connect daemon ctl {}: {e}", self.control_addr)),
            };

            let (r, mut w) = stream.into_split();
            let mut reader = BufReader::new(r);

            if let Err(e) = w.write_all(format!("{}\n", req_str).as_bytes()).await {
                return failed(&relay.node_id_hex, format!("write: {e}"));
            }
            // Best effort flush + half-close
            let _ = w.shutdown().await;

            let mut line = String::new();
            if let Err(e) = reader.read_line(&mut line).await {
                return failed(&relay.node_id_hex, format!("read: {e}"));
            }

            let resp: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => return failed(&relay.node_id_hex,
                    format!("parse resp: {e}")),
            };

            if resp["ok"].as_bool() != Some(true) {
                let err = resp["error"].as_str().unwrap_or("unknown");
                return failed(&relay.node_id_hex, format!("daemon: {err}"));
            }

            let bw_kbs = resp["bw_kbs"].as_u64().unwrap_or(0) as u32;
            let rtt_ms = resp["rtt_ms"].as_u64().unwrap_or(0) as u32;

            RelayMeasurement {
                node_id_hex: relay.node_id_hex.clone(),
                bw_kbs,
                rtt_ms,
                success: bw_kbs > 0,
                error: if bw_kbs == 0 {
                    Some("daemon reported 0 kbs".into())
                } else { None },
            }
        })
    }
}

fn failed(node_id_hex: &str, why: String) -> RelayMeasurement {
    RelayMeasurement {
        node_id_hex: node_id_hex.into(),
        bw_kbs: 0, rtt_ms: 0, success: false,
        error: Some(why),
    }
}
