// phinet-bwscanner/src/lib.rs
//!
//! # Bandwidth scanner
//!
//! Measures the throughput of every relay in the consensus and
//! produces a signed [`AuthorityVote`] containing the observed
//! bandwidths. Authorities run this binary on a schedule (every
//! ~hour) and feed votes into the consensus-building pipeline.
//!
//! ## How measurements work
//!
//! For each candidate relay R:
//!   1. Build a 2-hop circuit through R as the first hop.
//!   2. Open a stream to a measurement endpoint that emits a
//!      known-size payload.
//!   3. Time the byte arrival rate, record `bw_kbs`.
//!
//! ## Why measurements are third-party attestations
//!
//! Relays can lie about their capacity. Scanners produce
//! attestations from a *third party* (the authority running the
//! scanner) so the consensus doesn't depend on relay self-reports.

use phinet_core::directory::{AuthorityVote, DirectoryAuthority, PeerEntry, PeerFlags};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Configuration for a scan run.
#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub payload_bytes: usize,
    pub per_relay_timeout: Duration,
    pub passes: u32,
    pub vote_window_secs: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            payload_bytes: 1024 * 1024,
            per_relay_timeout: Duration::from_secs(60),
            passes: 3,
            vote_window_secs: 3600,
        }
    }
}

/// Result of one relay measurement.
#[derive(Clone, Debug, PartialEq)]
pub struct RelayMeasurement {
    pub node_id_hex: String,
    /// Observed throughput in kilobytes/sec. 0 means failure.
    pub bw_kbs: u32,
    pub rtt_ms: u32,
    pub success: bool,
    pub error: Option<String>,
}

/// Boxed-future return type. Same pattern as `transport.rs` —
/// gives us trait-objects without an `async-trait` proc-macro dep.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait for the actual transport layer that does the measurement.
pub trait MeasurementTransport: Send + Sync {
    fn measure<'a>(
        &'a self,
        relay: &'a PeerEntry,
        config: &'a ScanConfig,
    ) -> BoxFuture<'a, RelayMeasurement>;
}

pub struct Scanner {
    transport: Box<dyn MeasurementTransport>,
    config: ScanConfig,
}

impl Scanner {
    pub fn new(transport: Box<dyn MeasurementTransport>, config: ScanConfig) -> Self {
        Self { transport, config }
    }

    pub async fn run(
        &self,
        relays: &[PeerEntry],
        authority: &DirectoryAuthority,
    ) -> AuthorityVote {
        let measurements = self.measure_all(relays).await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let valid_after = now;
        let valid_until = now + self.config.vote_window_secs;

        let mut peers: Vec<PeerEntry> = relays.iter().map(|p| {
            let m = measurements.get(&p.node_id_hex);
            let measured_bw = m.map(|m| m.bw_kbs).unwrap_or(0);

            let mut flags = PeerFlags::from_bits_truncate(p.flags);
            match m {
                Some(m) if m.success => flags |= PeerFlags::RUNNING,
                _                    => flags.remove(PeerFlags::RUNNING),
            }

            PeerEntry {
                node_id_hex:    p.node_id_hex.clone(),
                host:           p.host.clone(),
                port:           p.port,
                static_pub_hex: p.static_pub_hex.clone(),
                flags:          flags.bits(),
                bandwidth_kbs:  measured_bw,
                exit_policy_summary: p.exit_policy_summary.clone(),
            }
        }).collect();

        peers.sort_by(|a, b| a.node_id_hex.cmp(&b.node_id_hex));
        authority.vote(valid_after, valid_until, peers)
    }

    async fn measure_all(&self, relays: &[PeerEntry]) -> HashMap<String, RelayMeasurement> {
        let mut out = HashMap::with_capacity(relays.len());
        for relay in relays {
            let id = relay.node_id_hex.clone();
            tracing::info!("measuring {}…", &id[..16.min(id.len())]);
            let m = self.measure_one_with_passes(relay).await;
            tracing::info!("  → bw_kbs={} success={}", m.bw_kbs, m.success);
            out.insert(id, m);
        }
        out
    }

    async fn measure_one_with_passes(&self, relay: &PeerEntry) -> RelayMeasurement {
        let mut samples: Vec<RelayMeasurement> = Vec::with_capacity(self.config.passes as usize);
        for _pass in 0..self.config.passes {
            let m = tokio::time::timeout(
                self.config.per_relay_timeout,
                self.transport.measure(relay, &self.config),
            ).await.unwrap_or_else(|_| RelayMeasurement {
                node_id_hex: relay.node_id_hex.clone(),
                bw_kbs: 0, rtt_ms: 0, success: false,
                error: Some(format!("measurement timed out after {:?}",
                    self.config.per_relay_timeout)),
            });
            samples.push(m);
        }
        median_measurement(samples, &relay.node_id_hex)
    }
}

fn median_measurement(samples: Vec<RelayMeasurement>, node_id: &str) -> RelayMeasurement {
    if samples.is_empty() {
        return RelayMeasurement {
            node_id_hex: node_id.into(),
            bw_kbs: 0, rtt_ms: 0, success: false,
            error: Some("no samples".into()),
        };
    }
    if samples.iter().any(|s| !s.success) {
        let err = samples.iter().find_map(|s| s.error.clone());
        return RelayMeasurement {
            node_id_hex: node_id.into(),
            bw_kbs: 0, rtt_ms: 0, success: false,
            error: err.or_else(|| Some("at least one sample failed".into())),
        };
    }
    let mut sorted = samples;
    sorted.sort_by_key(|s| s.bw_kbs);
    let n = sorted.len();
    let mid = &sorted[n / 2];
    RelayMeasurement {
        node_id_hex: node_id.into(),
        bw_kbs: mid.bw_kbs,
        rtt_ms: mid.rtt_ms,
        success: true,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::collections::HashSet;

    struct MockTransport {
        observations: HashMap<String, u32>,
        unreachable: HashSet<String>,
        calls: Arc<AtomicUsize>,
    }

    impl MeasurementTransport for MockTransport {
        fn measure<'a>(
            &'a self,
            relay: &'a PeerEntry,
            _config: &'a ScanConfig,
        ) -> BoxFuture<'a, RelayMeasurement> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let id = &relay.node_id_hex;
                if self.unreachable.contains(id) {
                    return RelayMeasurement {
                        node_id_hex: id.clone(),
                        bw_kbs: 0, rtt_ms: 0, success: false,
                        error: Some("mock: unreachable".into()),
                    };
                }
                let bw = self.observations.get(id).copied().unwrap_or(0);
                RelayMeasurement {
                    node_id_hex: id.clone(),
                    bw_kbs: bw, rtt_ms: 50, success: true, error: None,
                }
            })
        }
    }

    fn peer(id: &str) -> PeerEntry {
        PeerEntry {
            node_id_hex: id.into(),
            host: "10.0.0.1".into(),
            port: 7700,
            static_pub_hex: format!("{:0<64}", id),
            flags: (PeerFlags::STABLE | PeerFlags::FAST | PeerFlags::RUNNING
                    | PeerFlags::VALID).bits(),
            bandwidth_kbs: 0,
            exit_policy_summary: String::new(),
        }
    }

    #[tokio::test]
    async fn scan_produces_signed_vote_with_measured_bandwidths() {
        let mut obs = HashMap::new();
        obs.insert("aaaa".into(), 1500);
        obs.insert("bbbb".into(), 2500);
        let transport = MockTransport {
            observations: obs, unreachable: HashSet::new(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let scanner = Scanner::new(Box::new(transport), ScanConfig {
            passes: 1, ..Default::default()
        });
        let relays = vec![peer("aaaa"), peer("bbbb")];
        let auth = DirectoryAuthority::generate("phinet-test");
        let vote = scanner.run(&relays, &auth).await;

        phinet_core::directory::verify_vote(&vote).expect("vote must self-verify");
        let aaaa = vote.peers.iter().find(|p| p.node_id_hex == "aaaa").unwrap();
        let bbbb = vote.peers.iter().find(|p| p.node_id_hex == "bbbb").unwrap();
        assert_eq!(aaaa.bandwidth_kbs, 1500);
        assert_eq!(bbbb.bandwidth_kbs, 2500);
    }

    #[tokio::test]
    async fn unreachable_relays_get_zero_bw_and_lose_running_flag() {
        let mut obs = HashMap::new();
        obs.insert("aaaa".into(), 1000);
        let mut unreachable = HashSet::new();
        unreachable.insert("bbbb".into());
        let transport = MockTransport {
            observations: obs, unreachable,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let scanner = Scanner::new(Box::new(transport), ScanConfig {
            passes: 1, ..Default::default()
        });
        let relays = vec![peer("aaaa"), peer("bbbb")];
        let auth = DirectoryAuthority::generate("phinet-test");
        let vote = scanner.run(&relays, &auth).await;
        let bbbb = vote.peers.iter().find(|p| p.node_id_hex == "bbbb").unwrap();
        assert_eq!(bbbb.bandwidth_kbs, 0);
        assert!(bbbb.flags & PeerFlags::RUNNING.bits() == 0);
    }

    #[tokio::test]
    async fn vote_peers_sorted_canonically() {
        let mut obs = HashMap::new();
        obs.insert("ccc".into(), 100);
        obs.insert("aaa".into(), 100);
        obs.insert("bbb".into(), 100);
        let transport = MockTransport {
            observations: obs, unreachable: HashSet::new(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let scanner = Scanner::new(Box::new(transport), ScanConfig {
            passes: 1, ..Default::default()
        });
        let relays = vec![peer("ccc"), peer("aaa"), peer("bbb")];
        let auth = DirectoryAuthority::generate("phinet-test");
        let vote = scanner.run(&relays, &auth).await;
        let ids: Vec<&str> = vote.peers.iter()
            .map(|p| p.node_id_hex.as_str()).collect();
        assert_eq!(ids, vec!["aaa", "bbb", "ccc"]);
    }

    #[test]
    fn median_returns_middle_of_three_successful_samples() {
        let samples = vec![
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 100, rtt_ms: 0, success: true, error: None },
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 500, rtt_ms: 0, success: true, error: None },
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 200, rtt_ms: 0, success: true, error: None },
        ];
        let m = median_measurement(samples, "x");
        assert!(m.success);
        assert_eq!(m.bw_kbs, 200);
    }

    #[test]
    fn median_fails_if_any_sample_failed() {
        let samples = vec![
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 100, rtt_ms: 0, success: true, error: None },
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 0, rtt_ms: 0, success: false, error: Some("oops".into()) },
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 200, rtt_ms: 0, success: true, error: None },
        ];
        let m = median_measurement(samples, "x");
        assert!(!m.success);
        assert_eq!(m.bw_kbs, 0);
    }

    #[test]
    fn median_of_empty_is_failure() {
        let m = median_measurement(vec![], "x");
        assert!(!m.success);
    }

    #[tokio::test]
    async fn passes_call_transport_n_times() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut obs = HashMap::new();
        obs.insert("aaaa".into(), 1000);
        let transport = MockTransport {
            observations: obs, unreachable: HashSet::new(),
            calls: calls.clone(),
        };
        let scanner = Scanner::new(Box::new(transport), ScanConfig {
            passes: 5, ..Default::default()
        });
        let relays = vec![peer("aaaa")];
        let auth = DirectoryAuthority::generate("phinet-test");
        let _vote = scanner.run(&relays, &auth).await;
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn timeout_yields_failed_measurement() {
        struct SlowTransport;
        impl MeasurementTransport for SlowTransport {
            fn measure<'a>(
                &'a self,
                relay: &'a PeerEntry,
                _config: &'a ScanConfig,
            ) -> BoxFuture<'a, RelayMeasurement> {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    RelayMeasurement {
                        node_id_hex: relay.node_id_hex.clone(),
                        bw_kbs: 9999, rtt_ms: 0, success: true, error: None,
                    }
                })
            }
        }
        let scanner = Scanner::new(Box::new(SlowTransport), ScanConfig {
            passes: 1,
            per_relay_timeout: Duration::from_millis(50),
            ..Default::default()
        });
        let relays = vec![peer("aaaa")];
        let auth = DirectoryAuthority::generate("phinet-test");
        let vote = scanner.run(&relays, &auth).await;
        let p = vote.peers.iter().find(|p| p.node_id_hex == "aaaa").unwrap();
        assert_eq!(p.bandwidth_kbs, 0);
    }

    #[tokio::test]
    async fn empty_relay_list_produces_empty_vote() {
        let transport = MockTransport {
            observations: HashMap::new(),
            unreachable: HashSet::new(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let scanner = Scanner::new(Box::new(transport), ScanConfig::default());
        let auth = DirectoryAuthority::generate("phinet-test");
        let vote = scanner.run(&[], &auth).await;
        assert!(vote.peers.is_empty());
        phinet_core::directory::verify_vote(&vote).expect("empty vote must verify");
    }
}
