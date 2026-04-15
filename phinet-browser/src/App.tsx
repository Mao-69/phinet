// phinet-browser/src/App.tsx
import React, { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AddressBar }        from "./components/AddressBar";
import { TabBar }            from "./components/TabBar";
import { WebView }           from "./components/WebView";
import { SiteManager }       from "./components/SiteManager";
import { CircuitVisualizer } from "./components/CircuitVisualizer";
import { StatusBar }         from "./components/StatusBar";
import "./styles/App.css";

// ── Types ─────────────────────────────────────────────────────────────

export interface Tab {
  id:      string;
  title:   string;
  url:     string;
  loading: boolean;
  isPhinet: boolean;
}

export interface DaemonStatus {
  online:    boolean;
  node_id:   string | null;
  peers:     number;
  dht_keys:  number;
  cert_bits: number | null;
}

// ── New-tab page ──────────────────────────────────────────────────────

function newTabHtml(daemonOnline: boolean): string {
  const statusCol  = daemonOnline ? "#3a9e6a" : "#4a5878";
  const statusDot  = daemonOnline ? "●" : "○";
  const statusText = daemonOnline ? "live network" : "local only";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ΦNET Browser</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:#080812;color:#b8c8e0;font-family:'JetBrains Mono',monospace}
body{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:2rem}
.logo{position:relative;margin-bottom:2rem}
.hex{width:80px;height:80px;opacity:.9}
.ring{position:absolute;inset:-16px;border-radius:50%;border:1px solid #3a6cbe;
  opacity:.2;animation:pulse 3s ease-in-out infinite}
.ring:nth-child(2){inset:-28px;animation-delay:1s;opacity:.12}
.ring:nth-child(3){inset:-42px;animation-delay:2s;opacity:.06}
@keyframes pulse{0%,100%{transform:scale(1);opacity:.2}50%{transform:scale(1.05);opacity:.35}}
h1{font-size:2.2rem;font-weight:500;letter-spacing:.1em;color:#5a9cee;margin-bottom:.4rem}
.tagline{color:#4a5878;font-size:.85rem;letter-spacing:.12em;margin-bottom:2rem}
.search-box{display:flex;gap:8px;width:100%;max-width:560px;margin-bottom:1.5rem}
#addr{flex:1;background:#131328;border:1px solid #1e2040;border-radius:6px;
  color:#b8c8e0;font-family:inherit;font-size:1rem;padding:10px 16px;
  outline:none;transition:border-color .2s}
#addr:focus{border-color:#3a6cbe}
#addr::placeholder{color:#4a5878}
#go{background:#3a6cbe;border:none;border-radius:6px;color:#fff;
  font-family:inherit;font-size:.95rem;padding:10px 20px;cursor:pointer;transition:background .2s}
#go:hover{background:#5a9cee}
.props{display:flex;gap:2rem;margin-bottom:1.5rem}
.prop{text-align:center}
.prop-icon{font-size:1.4rem;margin-bottom:.3rem}
.prop-label{font-size:.7rem;letter-spacing:.1em;color:#4a5878;text-transform:uppercase}
.divider{width:1px;height:40px;background:#1e2040;align-self:center}
.node-status{font-size:.72rem;color:${statusCol};margin-bottom:1.5rem;letter-spacing:.08em}
.notice{font-size:.68rem;color:#1e2040;text-align:center;max-width:480px;line-height:1.8;
  margin-top:1rem;border-top:1px solid #1e2040;padding-top:.8rem}
code{background:#131328;border:1px solid #1e2040;border-radius:3px;padding:1px 6px;
  color:#5a9cee;font-size:.9em}
</style>
</head>
<body>
<div class="logo">
  <div class="ring"></div><div class="ring"></div><div class="ring"></div>
  <svg class="hex" viewBox="0 0 80 80" fill="none">
    <polygon points="40,4 72,22 72,58 40,76 8,58 8,22"
      stroke="#3a6cbe" stroke-width="1.5" fill="none" opacity=".8"/>
    <polygon points="40,14 62,27 62,53 40,66 18,53 18,27"
      stroke="#2a5cae" stroke-width="1" fill="none" opacity=".4"/>
    <circle cx="40" cy="40" r="8" fill="#3a6cbe" opacity=".9"/>
    <circle cx="40" cy="40" r="14" stroke="#3a6cbe" stroke-width="1" fill="none" opacity=".3"/>
    <circle cx="40" cy="40" r="20" stroke="#3a6cbe" stroke-width=".5"
      fill="none" opacity=".15" stroke-dasharray="3,2"/>
  </svg>
</div>
<h1>ΦNET BROWSER</h1>
<p class="tagline">UTPC CERTS · ONION-ROUTED · OVERLAY NETWORK</p>
<div class="search-box">
  <input id="addr" type="text" placeholder="Enter .phinet address  (40 hex characters)"
    autocomplete="off" spellcheck="false">
  <button id="go" onclick="go()">Navigate</button>
</div>
<div class="props">
  <div class="prop"><div class="prop-icon">🔐</div><div class="prop-label">End-to-end<br>encrypted</div></div>
  <div class="divider"></div>
  <div class="prop"><div class="prop-icon">🧅</div><div class="prop-label">3-hop onion<br>routing</div></div>
  <div class="divider"></div>
  <div class="prop"><div class="prop-icon">⬡</div><div class="prop-label">ΦNET<br>identity</div></div>
  <div class="divider"></div>
  <div class="prop"><div class="prop-icon">🚫</div><div class="prop-label">No IP<br>exposed</div></div>
</div>
<p class="node-status">${statusDot} ${statusText}</p>
<p class="notice">
  ΦNET Hidden Services is still early-stage.
</p>
<script>
document.getElementById('addr').addEventListener('keydown', e => { if(e.key==='Enter') go(); });
document.getElementById('addr').focus();
function go(){
  const v=document.getElementById('addr').value.trim();
  if(!v)return;
  const hs=v.replace(/\\.phinet$/,'');
  if(/^[0-9a-fA-F]{40}$/.test(hs)){
    window.location.href='http://'+hs.toLowerCase()+'.phinet/';
  } else if(v.includes('://')){ window.location.href=v; }
  else { window.location.href='http://'+v; }
}
</script>
</body>
</html>`;
}

// ── App ───────────────────────────────────────────────────────────────

export default function App() {
  const [tabs, setTabs]   = useState<Tab[]>([]);
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const [showSiteManager,   setSiteManager]   = useState(false);
  const [showCircuitView,   setCircuitView]   = useState(false);
  const [daemonStatus, setDaemonStatus] = useState<DaemonStatus>({
    online: false, node_id: null, peers: 0, dht_keys: 0, cert_bits: null,
  });

  // Poll daemon status every 6 s
  useEffect(() => {
    const poll = async () => {
      try {
        const s = await invoke<DaemonStatus>("daemon_status");
        setDaemonStatus(s);
      } catch { /* daemon offline */ }
    };
    poll();
    const id = setInterval(poll, 6000);
    return () => clearInterval(id);
  }, []);

  // Open home tab on start
  useEffect(() => {
    openNewTab();
  }, []);

  const openNewTab = useCallback(() => {
    const id = crypto.randomUUID();
    const tab: Tab = {
      id, title: "New Tab", url: "about:home",
      loading: false, isPhinet: false,
    };
    setTabs(prev => [...prev, tab]);
    setActiveTab(id);
  }, []);

  const closeTab = useCallback((id: string) => {
    setTabs(prev => {
      const remaining = prev.filter(t => t.id !== id);
      if (remaining.length === 0) {
        // Open fresh tab instead of closing the window
        const newTab: Tab = {
          id: crypto.randomUUID(), title: "New Tab",
          url: "about:home", loading: false, isPhinet: false,
        };
        setActiveTab(newTab.id);
        return [newTab];
      }
      if (activeTab === id) {
        setActiveTab(remaining[remaining.length - 1].id);
      }
      return remaining;
    });
  }, [activeTab]);

  const navigateTab = useCallback((url: string) => {
    if (!activeTab) return;
    setTabs(prev => prev.map(t =>
      t.id === activeTab
        ? { ...t, url, loading: true, isPhinet: url.includes(".phinet") }
        : t
    ));
  }, [activeTab]);

  const updateTab = useCallback((id: string, update: Partial<Tab>) => {
    setTabs(prev => prev.map(t => t.id === id ? { ...t, ...update } : t));
  }, []);

  const currentTab = tabs.find(t => t.id === activeTab) ?? null;

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey) {
        switch (e.key) {
          case "t": e.preventDefault(); openNewTab();           break;
          case "w": e.preventDefault(); activeTab && closeTab(activeTab); break;
          case "m": e.preventDefault(); setSiteManager(v => !v); break;
          case "i": e.preventDefault(); setCircuitView(v => !v); break;
        }
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [activeTab, openNewTab, closeTab]);

  return (
    <div className="browser-shell">
      {/* Tab bar */}
      <TabBar
        tabs={tabs}
        activeTab={activeTab}
        onSelect={setActiveTab}
        onClose={closeTab}
        onNewTab={openNewTab}
      />

      {/* Navigation bar */}
      <div className="nav-bar">
        <button className="nav-btn" title="Back" onClick={() => {/* webview back */}}>←</button>
        <button className="nav-btn" title="Forward">→</button>
        <button className="nav-btn" title="Reload" onClick={() => currentTab && navigateTab(currentTab.url)}>↻</button>

        <AddressBar
          value={currentTab?.url ?? ""}
          loading={currentTab?.loading ?? false}
          isPhinet={currentTab?.isPhinet ?? false}
          onNavigate={navigateTab}
        />

        <button className="nav-btn" title="Circuit info (Ctrl+I)" onClick={() => setCircuitView(v => !v)}>⬡</button>
        <button className="nav-btn icon-site-mgr" title="Site Manager (Ctrl+M)" onClick={() => setSiteManager(v => !v)}>
          ⊞
        </button>
      </div>

      {/* WebView area */}
      <div className="webview-container">
        {tabs.map(tab => (
          <WebView
            key={tab.id}
            tab={tab}
            active={tab.id === activeTab}
            daemonOnline={daemonStatus.online}
            onTitleChange={title => updateTab(tab.id, { title })}
            onUrlChange={url   => updateTab(tab.id, { url, isPhinet: url.includes(".phinet") })}
            onLoadStart={()    => updateTab(tab.id, { loading: true  })}
            onLoadEnd={()      => updateTab(tab.id, { loading: false })}
          />
        ))}
      </div>

      {/* Panels */}
      {showSiteManager && (
        <SiteManager
          onClose={() => setSiteManager(false)}
          onNavigate={url => { navigateTab(url); setSiteManager(false); }}
        />
      )}
      {showCircuitView && (
        <CircuitVisualizer
          onClose={() => setCircuitView(false)}
          isPhinet={currentTab?.isPhinet ?? false}
          daemonOnline={daemonStatus.online}
        />
      )}

      {/* Status bar */}
      <StatusBar
        tab={currentTab}
        daemon={daemonStatus}
      />
    </div>
  );
}
