// phinet-browser/src/components/StatusBar.tsx
import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Tab, DaemonStatus } from "../App";

interface Props {
  tab:    Tab | null;
  daemon: DaemonStatus;
}

export function StatusBar({ tab, daemon }: Props) {
  const [showConnect, setShowConnect] = useState(false);
  const [peerAddr,    setPeerAddr]    = useState("");
  const [connecting,  setConnecting]  = useState(false);
  const [connectMsg,  setConnectMsg]  = useState("");

  const isPhinet   = tab?.isPhinet ?? false;
  const isHome     = tab?.url === "about:home" || !tab?.url;
  const urlDisplay = isHome ? "" : (tab?.url ?? "");

  const isHttps = !!tab?.url?.startsWith("https://");
  const isHttp  = !!tab?.url?.startsWith("http://") && !isPhinet;

  // Status indicator label / class
  let modeLabel  = "Home";
  let modeClass  = "local";
  if (isPhinet)      { modeLabel = "⬡ ΦNET · onion-routed"; modeClass = "phinet";   }
  else if (isHttps)  { modeLabel = "🔒 Secure (HTTPS)";       modeClass = "clearnet"; }
  else if (isHttp)   { modeLabel = "⚠ Not secure (HTTP)";     modeClass = "http";     }

  const doConnect = async () => {
    const addr = peerAddr.trim();
    if (!addr) return;
    const lastColon = addr.lastIndexOf(":");
    const host = lastColon > 0 ? addr.slice(0, lastColon) : addr;
    const port = lastColon > 0 ? parseInt(addr.slice(lastColon + 1)) || 7700 : 7700;
    setConnecting(true);
    setConnectMsg("");
    try {
      await invoke("connect_peer", { host, port });
      setConnectMsg("Connecting…");
      setTimeout(() => { setShowConnect(false); setPeerAddr(""); setConnectMsg(""); }, 2000);
    } catch (e) {
      setConnectMsg(String(e));
    } finally {
      setConnecting(false);
    }
  };

  return (
    <>
      {/* Connect-to-peer popup */}
      {showConnect && (
        <div style={{
          position: "absolute", bottom: 32, right: 12, zIndex: 200,
          background: "var(--bg2)", border: "1px solid var(--bd)",
          borderRadius: 10, padding: "14px 16px", display: "flex",
          flexDirection: "column", gap: 10, minWidth: 320,
          boxShadow: "var(--shadow-lg)",
          animation: "slideUp 0.15s ease",
        }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "var(--tx)", marginBottom: 2 }}>
            Connect to peer
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              autoFocus
              placeholder="host:7700"
              value={peerAddr}
              onChange={e => setPeerAddr(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter") doConnect(); if (e.key === "Escape") setShowConnect(false); }}
              style={{ flex: 1 }}
            />
            <button
              className="primary"
              onClick={doConnect}
              disabled={connecting}
            >
              {connecting ? "…" : "Connect"}
            </button>
          </div>
          {connectMsg && (
            <div style={{
              fontSize: 12,
              color: connectMsg.startsWith("Conn") ? "var(--green)" : "var(--red)",
            }}>
              {connectMsg}
            </div>
          )}
          <div style={{ fontSize: 11, color: "var(--mt)", lineHeight: 1.5 }}>
            Or via CLI: <code>phinet-daemon --bootstrap host:7700</code>
          </div>
        </div>
      )}

      <div className="status-bar">
        <span className="status-url">{urlDisplay}</span>
        {urlDisplay && <span className="status-sep">·</span>}

        <span className={`status-indicator ${modeClass}`}>
          {modeLabel}
        </span>

        <span
          className={`status-daemon ${daemon.online ? "online" : "offline"}`}
          title={daemon.online ? "Click to add a peer" : "phinet-daemon is not running"}
          style={{ cursor: daemon.online ? "pointer" : "default" }}
          onClick={() => daemon.online && setShowConnect(v => !v)}
        >
          <span className="status-daemon-dot" />
          {daemon.online
            ? `${daemon.peers} ${daemon.peers !== 1 ? "peers" : "peer"}${daemon.peers === 0 ? " · click to connect" : ""}`
            : "Daemon offline"}
        </span>

        {daemon.online && daemon.cert_bits && (
          <>
            <span className="status-sep">·</span>
            <span style={{ color: "var(--mt)", fontSize: 10 }}>
              {daemon.cert_bits}b cert
            </span>
          </>
        )}
      </div>
    </>
  );
}
