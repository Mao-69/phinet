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
  const statusCol  = daemonOnline ? "#3fb950" : "#7d8590";
  const statusDot  = daemonOnline ? "●" : "○";
  const statusText = daemonOnline ? "Connected to ΦNET" : "Daemon offline";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ΦNET Browser</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:#0d1117;color:#e6edf3;
  font-family:'Inter',-apple-system,'Segoe UI',system-ui,sans-serif;
  -webkit-font-smoothing:antialiased}
body{display:flex;flex-direction:column;align-items:center;justify-content:center;
  padding:2rem;
  background:radial-gradient(ellipse at top, #161b22 0%, #0d1117 70%)}

.logo{position:relative;margin-bottom:1.5rem}
.hex{width:88px;height:88px}
.ring{position:absolute;inset:-18px;border-radius:50%;
  border:1.5px solid #2f81f7;opacity:.18;
  animation:pulse 4s ease-in-out infinite}
.ring:nth-child(2){inset:-32px;animation-delay:1.3s;opacity:.10}
.ring:nth-child(3){inset:-48px;animation-delay:2.6s;opacity:.05}
@keyframes pulse{0%,100%{transform:scale(1);opacity:.18}
  50%{transform:scale(1.06);opacity:.32}}

h1{font-size:2.4rem;font-weight:700;letter-spacing:-.02em;
  color:#e6edf3;margin-bottom:.4rem}
h1 .accent{color:#39c5cf}

.tagline{color:#7d8590;font-size:.9rem;margin-bottom:2.5rem;
  letter-spacing:.02em}

.search-box{display:flex;gap:8px;width:100%;max-width:600px;
  margin-bottom:2rem;position:relative}
#addr{flex:1;background:#161b22;border:1px solid #30363d;
  border-radius:10px;color:#e6edf3;
  font-family:inherit;font-size:.95rem;padding:14px 18px 14px 44px;
  outline:none;
  transition:border-color .15s, background .15s, box-shadow .15s}
#addr::placeholder{color:#7d8590}
#addr:focus{border-color:#2f81f7;background:#0d1117;
  box-shadow:0 0 0 4px rgba(47,129,247,.18)}
.search-icon{position:absolute;left:16px;top:50%;
  transform:translateY(-50%);color:#7d8590;pointer-events:none;
  font-size:14px}

#go{background:#2f81f7;border:none;border-radius:10px;
  color:#fff;font-family:inherit;font-weight:600;font-size:.95rem;
  padding:0 24px;cursor:pointer;transition:background .15s, transform .1s}
#go:hover{background:#58a6ff}
#go:active{transform:translateY(1px)}

.props{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;
  width:100%;max-width:600px;margin-bottom:2rem}
.prop{background:#161b22;border:1px solid #30363d;border-radius:10px;
  padding:18px 14px;text-align:center;
  transition:border-color .15s, transform .15s}
.prop:hover{border-color:#444c56;transform:translateY(-2px)}
.prop-icon{font-size:1.6rem;margin-bottom:.5rem;display:block}
.prop-label{font-size:.72rem;color:#c9d1d9;line-height:1.4}
.prop-sub{font-size:.65rem;color:#7d8590;margin-top:2px}

.node-status{display:inline-flex;align-items:center;gap:6px;
  font-size:.8rem;color:${statusCol};margin-bottom:2rem;
  background:#161b22;border:1px solid #30363d;border-radius:999px;
  padding:6px 14px}

.notice{font-size:.78rem;color:#7d8590;text-align:center;
  max-width:520px;line-height:1.7;margin-top:1rem;
  border-top:1px solid #21262d;padding-top:1.2rem}
.notice strong{color:#c9d1d9;font-weight:600}
code{font-family:'JetBrains Mono',monospace;
  background:#161b22;border:1px solid #30363d;border-radius:4px;
  padding:1px 6px;color:#58a6ff;font-size:.85em}
</style>
</head>
<body>
<div class="logo">
  <div class="ring"></div><div class="ring"></div><div class="ring"></div>
  <svg class="hex" viewBox="0 0 88 88" fill="none">
    <defs>
      <linearGradient id="hexgrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#39c5cf"/>
        <stop offset="100%" stop-color="#2f81f7"/>
      </linearGradient>
    </defs>
    <polygon points="44,4 80,24 80,64 44,84 8,64 8,24"
      stroke="url(#hexgrad)" stroke-width="2" fill="none" opacity="0.9"/>
    <polygon points="44,16 68,30 68,58 44,72 20,58 20,30"
      stroke="#2f81f7" stroke-width="1.2" fill="none" opacity="0.4"/>
    <circle cx="44" cy="44" r="9" fill="url(#hexgrad)" opacity="0.95"/>
    <circle cx="44" cy="44" r="16" stroke="#2f81f7"
      stroke-width="1" fill="none" opacity="0.25"/>
    <circle cx="44" cy="44" r="22" stroke="#39c5cf"
      stroke-width="0.8" fill="none" opacity="0.15" stroke-dasharray="3,2"/>
  </svg>
</div>

<h1>ΦNET <span class="accent">Browser</span></h1>
<p class="tagline">Anonymous · Onion-routed · Decentralized</p>

<div class="search-box">
  <span class="search-icon">⌕</span>
  <input id="addr" type="text"
    placeholder="Enter a .phinet address, URL, or search the web"
    autocomplete="off" spellcheck="false">
  <button id="go" onclick="go()">Go</button>
</div>

<div class="props">
  <div class="prop">
    <span class="prop-icon">🔐</span>
    <div class="prop-label">End-to-end</div>
    <div class="prop-sub">encrypted</div>
  </div>
  <div class="prop">
    <span class="prop-icon">🧅</span>
    <div class="prop-label">Onion</div>
    <div class="prop-sub">routing</div>
  </div>
  <div class="prop">
    <span class="prop-icon">⬡</span>
    <div class="prop-label">ΦNET</div>
    <div class="prop-sub">identity</div>
  </div>
  <div class="prop">
    <span class="prop-icon">🌐</span>
    <div class="prop-label">HTTPS &amp;</div>
    <div class="prop-sub">.phinet</div>
  </div>
</div>

<div class="node-status">${statusDot} ${statusText}</div>

<p class="notice">
  <strong>Privacy by design.</strong> Hidden services are not listed or indexed.
  You must know the exact 64-character address to visit one.
  Clearnet URLs (<code>https://example.com</code>) work normally too.
</p>

<script>
document.getElementById('addr').addEventListener('keydown', e => { if(e.key==='Enter') go(); });
document.getElementById('addr').focus();
function go(){
  const v=document.getElementById('addr').value.trim();
  if(!v)return;
  const hs=v.replace(/\\.phinet$/,'');
  // 64-hex .phinet address (Ed25519-derived hs_id, current format)
  if(/^[0-9a-fA-F]{64}$/.test(hs)){
    window.location.href='http://'+hs.toLowerCase()+'.phinet/';
    return;
  }
  // Legacy 40-hex .phinet still accepted for old descriptors
  if(/^[0-9a-fA-F]{40}$/.test(hs)){
    window.location.href='http://'+hs.toLowerCase()+'.phinet/';
    return;
  }
  // Already has scheme? Use as-is
  if(v.includes('://')){ window.location.href=v; return; }
  // Looks like a domain (contains a dot, no spaces)
  if(/^[\\w-]+(\\.[\\w-]+)+(\\/.*)?$/.test(v)){
    window.location.href='https://'+v;
    return;
  }
  // Otherwise treat as a search query
  window.location.href='https://duckduckgo.com/?q='+encodeURIComponent(v);
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
