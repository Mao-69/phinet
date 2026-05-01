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
    },

    /// Print the public key of an authority identity. Operators
    /// publish this so clients can add it to their trusted-authority
    /// set.
    PubKey {
        #[arg(long)]
        identity: PathBuf,
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

        Cmd::Scan { identity, consensus, output, network_id, passes, timeout_secs, simulate } => {
            rt.block_on(async {
                run_scan(RunScanArgs {
                    identity,
                    consensus,
                    output,
                    network_id,
                    passes,
                    timeout_secs,
                    simulate,
                }).await
            })?;
        }
    }

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
        // Real measurement transport would go here. For now, we
        // refuse to produce a real-looking vote without real data.
        anyhow::bail!(
            "real measurement transport not yet wired up. \
             Run with --simulate to use synthetic values, or implement \
             a DaemonMeasurementTransport that talks to phinet-daemon's \
             control port (the MeasurementTransport trait makes this a \
             ~150-line addition).");
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
