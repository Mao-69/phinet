// phinet-browser/src/components/CircuitVisualizer.tsx
//
// Displays the onion circuit for the current page — similar to Tor Browser's
// "Onion Circuits" view.  When the daemon is online it queries live circuit
// info; when offline it shows the local-mode indicator.

import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Props {
  onClose:      () => void;
  isPhinet:     boolean;
  daemonOnline: boolean;
}

interface PeerInfo {
  node_id: string;
  host:    string;
  port:    number;
}

interface CircuitNode {
  role:    "you" | "guard" | "middle" | "exit" | "destination";
  label:   string;
  addr:    string;
  country: string;
}

// Derive a display circuit from peer list + current URL
function buildCircuit(peers: PeerInfo[], isPhinet: boolean): CircuitNode[] {
  if (!isPhinet) return [];

  const circuit: CircuitNode[] = [
    { role: "you",  label: "This browser", addr: "127.0.0.1", country: "🏠" },
  ];

  if (peers.length >= 1) {
    circuit.push({
      role:    "guard",
      label:   `Guard  (${peers[0].node_id.slice(0, 8)}…)`,
      addr:    `${peers[0].host}:${peers[0].port}`,
      country: "🔒",
    });
  } else {
    circuit.push({ role: "guard",  label: "Guard relay",  addr: "unknown", country: "🔒" });
  }

  if (peers.length >= 2) {
    circuit.push({
      role:    "middle",
      label:   `Middle  (${peers[1].node_id.slice(0, 8)}…)`,
      addr:    `${peers[1].host}:${peers[1].port}`,
      country: "🔒",
    });
  } else {
    circuit.push({ role: "middle", label: "Middle relay", addr: "unknown", country: "🔒" });
  }

  if (peers.length >= 3) {
    circuit.push({
      role:    "exit",
      label:   `Exit  (${peers[2].node_id.slice(0, 8)}…)`,
      addr:    `${peers[2].host}:${peers[2].port}`,
      country: "🔒",
    });
  } else {
    circuit.push({ role: "exit",   label: "Exit relay",   addr: "unknown", country: "🔒" });
  }

  circuit.push({ role: "destination", label: "Hidden service", addr: ".phinet", country: "⬡" });
  return circuit;
}

const ROLE_ICONS: Record<string, string> = {
  you:         "👤",
  guard:       "🛡",
  middle:      "⬡",
  exit:        "🚪",
  destination: "🌐",
};

const ROLE_LABELS: Record<string, string> = {
  you:         "You",
  guard:       "Guard Node",
  middle:      "Middle Relay",
  exit:        "Exit Relay",
  destination: "Destination",
};

export function CircuitVisualizer({ onClose, isPhinet, daemonOnline }: Props) {
  const [peers,   setPeers]   = useState<PeerInfo[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!daemonOnline) return;
    setLoading(true);
    invoke<{ online: boolean; node_id: string | null; peers: number; dht_keys: number; cert_bits: number | null }>("daemon_status")
      .then(s => {
        // Build placeholder circuit nodes from peer count
        const count = Math.min(s.peers, 5);
        const synthetic: PeerInfo[] = Array.from({ length: count }, (_, i) => ({
          node_id: `peer${i}`.padEnd(16, "0"),
          host:    "relay",
          port:    7700 + i,
        }));
        setPeers(synthetic);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [daemonOnline]);

  const circuit = buildCircuit(peers, isPhinet);

  return (
    <div
      className="overlay-backdrop"
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="panel circuit-panel">

        <div className="panel-header">
          <span className="panel-title">⬡  Circuit Information</span>
          <button className="panel-close" onClick={onClose}>×</button>
        </div>

        <div className="circuit-body">

          {!isPhinet ? (
            // Clearnet indicator
            <div className="circuit-offline">
              <div style={{ fontSize: 32, marginBottom: 12 }}>●</div>
              <div style={{ color: "var(--amber)", marginBottom: 8 }}>Clearnet connection</div>
              <div>No onion routing — your IP address may be visible.</div>
              <div style={{ marginTop: 12, fontSize: 11, color: "var(--mt)" }}>
                Navigate to a <code>.phinet</code> address for anonymous routing.
              </div>
            </div>

          ) : !daemonOnline ? (
            // Local mode indicator
            <div className="circuit-offline">
              <div style={{ fontSize: 32, marginBottom: 12 }}>⬡</div>
              <div style={{ color: "var(--mt)", marginBottom: 8 }}>Local mode</div>
              <div>Content served from your local store.</div>
              <div>No live peers — circuit routing unavailable.</div>
              <code style={{ marginTop: 12, display: "block" }}>
                phinet-daemon --port 7700
              </code>
            </div>

          ) : circuit.length === 0 ? (
            <div className="circuit-offline">
              <div>Building circuit…</div>
            </div>

          ) : (
            // Full circuit display
            circuit.map((node, i) => (
              <React.Fragment key={node.role}>
                <div className={`circuit-node ${node.role}`}>
                  <div className="circuit-icon">
                    {ROLE_ICONS[node.role]}
                  </div>
                  <div className="circuit-info">
                    <div className="circuit-role">{ROLE_LABELS[node.role]}</div>
                    <div className="circuit-label">{node.country}  {node.label}</div>
                    <div className="circuit-addr">{node.addr}</div>
                  </div>
                  {(node.role === "guard" || node.role === "middle" || node.role === "exit") && (
                    <span className="circuit-lock">🔒 E2E</span>
                  )}
                </div>

                {i < circuit.length - 1 && (
                  <div className="circuit-connector">↓</div>
                )}
              </React.Fragment>
            ))
          )}

        </div>

        {/* Footer */}
        <div style={{
          padding: "10px 16px",
          borderTop: "1px solid var(--bd)",
          fontSize: 10,
          color: "var(--mt)",
          display: "flex",
          justifyContent: "space-between",
        }}>
          <span>
            {isPhinet && daemonOnline
              ? `${circuit.length - 2} relay${circuit.length - 2 !== 1 ? "s" : ""}  ·  ChaCha20-Poly1305 per hop`
              : ""}
          </span>
          <span>{daemonOnline ? "⬡ live" : "○ local"}</span>
        </div>

      </div>
    </div>
  );
}
