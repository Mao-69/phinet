// phinet-browser/src/components/WebView.tsx
//
// Tauri's WebKit cannot resolve .phinet DNS or auto-route through SOCKS5.
// Instead, every navigation goes through the Rust fetch_page command which
// uses the embedded SOCKS5 proxy, then the HTML is written into the iframe
// via srcdoc.  This works for both local .phinet sites and clearnet URLs.

import React, { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Tab } from "../App";

interface Props {
  tab:           Tab;
  active:        boolean;
  daemonOnline:  boolean;
  onTitleChange: (t: string) => void;
  onUrlChange:   (u: string) => void;
  onLoadStart:   () => void;
  onLoadEnd:     () => void;
}

interface FetchResult {
  status:       number;
  content_type: string;
  body_hex:     string;
  is_phinet:    boolean;
}

function hexToString(hex: string): string {
  const bytes = new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
  return new TextDecoder().decode(bytes);
}

function homePageHtml(daemonOnline: boolean): string {
  const dot  = daemonOnline ? "●" : "○";
  const text = daemonOnline ? "live network" : "local only";
  const col  = daemonOnline ? "#3a9e6a" : "#4a5878";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PHINET Browser</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:#080812;color:#b8c8e0;font-family:monospace}
body{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:2rem}
.logo{position:relative;margin-bottom:2rem}
.hex{width:80px;height:80px;opacity:.9}
.ring{position:absolute;inset:-16px;border-radius:50%;border:1px solid #3a6cbe;
  opacity:.2;animation:pulse 3s ease-in-out infinite}
.ring:nth-child(2){inset:-28px;animation-delay:1s;opacity:.12}
.ring:nth-child(3){inset:-42px;animation-delay:2s;opacity:.06}
@keyframes pulse{0%,100%{transform:scale(1);opacity:.2}50%{transform:scale(1.05);opacity:.35}}
h1{font-size:2rem;font-weight:500;letter-spacing:.1em;color:#5a9cee;margin-bottom:.4rem}
.tagline{color:#4a5878;font-size:.8rem;letter-spacing:.12em;margin-bottom:2rem}
.search-box{display:flex;gap:8px;width:100%;max-width:520px;margin-bottom:1.5rem}
#addr{flex:1;background:#131328;border:1px solid #1e2040;border-radius:6px;
  color:#b8c8e0;font-family:inherit;font-size:.95rem;padding:9px 14px;
  outline:none;transition:border-color .2s}
#addr:focus{border-color:#3a6cbe}
#addr::placeholder{color:#4a5878}
#go{background:#3a6cbe;border:none;border-radius:6px;color:#fff;
  font-family:inherit;font-size:.9rem;padding:9px 18px;cursor:pointer}
#go:hover{background:#5a9cee}
.props{display:flex;gap:2rem;margin-bottom:1.5rem}
.prop{text-align:center}
.prop-icon{font-size:1.2rem;margin-bottom:.25rem}
.prop-label{font-size:.65rem;letter-spacing:.08em;color:#4a5878;text-transform:uppercase}
.divider{width:1px;height:36px;background:#1e2040;align-self:center}
.status{font-size:.7rem;color:${col};margin-bottom:1.5rem;letter-spacing:.08em}
.notice{font-size:.65rem;color:#2a3050;text-align:center;max-width:460px;line-height:1.8;
  margin-top:1rem;border-top:1px solid #1a2040;padding-top:.8rem}
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
  </svg>
</div>
<h1>PHINET BROWSER</h1>
<p class="tagline">UTPC CERTS · ONION-ROUTED · OVERLAY NETWORK</p>
<div class="search-box">
  <input id="addr" type="text" placeholder="Enter .phinet address (40 hex chars)"
    autocomplete="off" spellcheck="false">
  <button id="go" onclick="go()">Go</button>
</div>
<div class="props">
  <div class="prop"><div class="prop-icon">🔐</div><div class="prop-label">E2E<br>encrypted</div></div>
  <div class="divider"></div>
  <div class="prop"><div class="prop-icon">🧅</div><div class="prop-label">3-hop<br>onion</div></div>
  <div class="divider"></div>
  <div class="prop"><div class="prop-icon">⬡</div><div class="prop-label">PHINET<br>identity</div></div>
  <div class="divider"></div>
  <div class="prop"><div class="prop-icon">🚫</div><div class="prop-label">No IP<br>exposed</div></div>
</div>
<p class="status">${dot} ${text}</p>
<p class="notice">
  ΦNET Hidden Services is still early-stage.
</p>
<script>
document.getElementById('addr').addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
document.getElementById('addr').focus();
function go() {
  const v = document.getElementById('addr').value.trim();
  if (!v) return;
  const hs = v.replace(/\\.phinet$/, '');
  if (/^[0-9a-fA-F]{40}$/.test(hs)) {
    window.parent.postMessage({ type: 'navigate', url: 'http://' + hs.toLowerCase() + '.phinet/' }, '*');
  } else if (v.includes('://')) {
    window.parent.postMessage({ type: 'navigate', url: v }, '*');
  } else if (v.includes('.')) {
    window.parent.postMessage({ type: 'navigate', url: 'http://' + v }, '*');
  }
}
</script>
</body>
</html>`;
}

function errorPageHtml(url: string, err: string): string {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Error</title>
<style>body{font-family:monospace;background:#080812;color:#b8c8e0;
max-width:540px;margin:60px auto;padding:2rem;line-height:1.7}
h1{color:#c04848;margin-bottom:1rem}p{color:#4a5878;margin-bottom:.8rem}
code{background:#0e0e1c;border:1px solid #1e2040;border-radius:3px;
padding:2px 6px;color:#8ab4e8;word-break:break-all}</style>
</head><body>
<h1>Could not load page</h1>
<p><code>${url}</code></p>
<p>${err}</p>
<p>If this is a .phinet address, make sure <code>phinet-daemon</code> is running
and the site has been deployed with <code>phi deploy</code>.</p>
</body></html>`;
}

export function WebView({
  tab, active, daemonOnline,
  onTitleChange, onUrlChange, onLoadStart, onLoadEnd,
}: Props) {
  const frameRef = useRef<HTMLIFrameElement>(null);

  // Listen for navigate messages from the home page iframe
  useEffect(() => {
    const handler = (e: MessageEvent) => {
      if (e.data?.type === "navigate" && e.data?.url) {
        onUrlChange(e.data.url);
      }
    };
    window.addEventListener("message", handler);
    return () => window.removeEventListener("message", handler);
  }, [onUrlChange]);

  useEffect(() => {
    const frame = frameRef.current;
    if (!frame) return;

    // Home / new tab
    if (!tab.url || tab.url === "about:home") {
      frame.srcdoc = homePageHtml(daemonOnline);
      onTitleChange("New Tab");
      onLoadEnd();
      return;
    }

    // Fetch via Tauri invoke → write into srcdoc
    onLoadStart();
    invoke<FetchResult>("fetch_page", { url: tab.url })
      .then(result => {
        const html = hexToString(result.body_hex);

        // Extract title from HTML
        const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
        if (titleMatch) onTitleChange(titleMatch[1].trim().slice(0, 60));
        else onTitleChange(tab.url.replace(/^https?:\/\//, "").slice(0, 40));

        // Inject base tag so relative URLs resolve correctly
        const base = `<base href="${tab.url}">`;
        const withBase = html.includes("<head>")
          ? html.replace("<head>", `<head>${base}`)
          : base + html;

        frame.srcdoc = withBase;
        onLoadEnd();
      })
      .catch(err => {
        frame.srcdoc = errorPageHtml(tab.url, String(err));
        onTitleChange("Error");
        onLoadEnd();
      });
  }, [tab.url]);

  // Refresh home page when daemon comes online
  useEffect(() => {
    if ((!tab.url || tab.url === "about:home") && frameRef.current) {
      frameRef.current.srcdoc = homePageHtml(daemonOnline);
    }
  }, [daemonOnline, tab.url]);

  return (
    <iframe
      ref={frameRef}
      className={`webview-frame${active ? " active" : ""}`}
      sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
      onLoad={() => { /* loading handled by invoke promise */ }}
      title={`tab-${tab.id}`}
    />
  );
}
