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
  const modeLabel  = isPhinet ? "⬡ ΦNET · anonymous" : "● clearnet";

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
          position: "absolute", bottom: 28, right: 8, zIndex: 200,
          background: "var(--bg2)", border: "1px solid var(--bd2)",
          borderRadius: 8, padding: "10px 12px", display: "flex",
          flexDirection: "column", gap: 6, minWidth: 280,
          boxShadow: "0 8px 24px rgba(0,0,0,.5)",
        }}>
          <div style={{ fontSize: 11, color: "var(--ac2)", marginBottom: 2 }}>
            Connect to peer
          </div>
          <div style={{ display: "flex", gap: 6 }}>
            <input
              autoFocus
              placeholder="host:7700"
              value={peerAddr}
              onChange={e => setPeerAddr(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter") doConnect(); if (e.key === "Escape") setShowConnect(false); }}
              style={{ flex: 1, fontSize: 11 }}
            />
            <button
              className="primary"
              style={{ fontSize: 11, padding: "4px 10px" }}
              onClick={doConnect}
              disabled={connecting}
            >
              {connecting ? "…" : "Connect"}
            </button>
          </div>
          {connectMsg && (
            <div style={{ fontSize: 10, color: connectMsg.startsWith("Conn") ? "var(--green)" : "var(--red)" }}>
              {connectMsg}
            </div>
          )}
          <div style={{ fontSize: 10, color: "var(--mt)" }}>
            Or via CLI:&nbsp; <code>phi status</code> then&nbsp;
            <code>phinet-daemon --bootstrap host:7700</code>
          </div>
        </div>
      )}

      <div className="status-bar">
        <span className="status-url">{urlDisplay}</span>
        <span className="status-sep">·</span>

        <span className={`status-indicator ${isPhinet ? "phinet" : "clearnet"}`}>
          {modeLabel}
        </span>

        <span
          className={`status-daemon ${daemon.online ? "online" : "offline"}`}
          title={daemon.online ? "Click to add a peer" : "phinet-daemon is not running"}
          style={{ cursor: daemon.online ? "pointer" : "default" }}
          onClick={() => daemon.online && setShowConnect(v => !v)}
        >
          {daemon.online
            ? `⬡ network · ${daemon.peers} peer${daemon.peers !== 1 ? "s" : ""}${daemon.peers === 0 ? " — click to connect" : ""}`
            : "○ local only"}
        </span>

        {daemon.online && daemon.cert_bits && (
          <>
            <span className="status-sep">·</span>
            <span className="status-indicator" style={{ color: "var(--mt)" }}>
              {daemon.cert_bits}b cert
            </span>
          </>
        )}
      </div>
    </>
  );
}
