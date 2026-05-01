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
  const text = daemonOnline ? "Connected to ΦNET" : "Daemon offline";
  const col  = daemonOnline ? "#3fb950" : "#7d8590";

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

.status{display:inline-flex;align-items:center;gap:6px;
  font-size:.8rem;color:${col};margin-bottom:2rem;
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

<div class="status">${dot} ${text}</div>

<p class="notice">
  <strong>Privacy by design.</strong> Hidden services are not listed or indexed.
  You must know the exact address to visit one.
  Clearnet URLs work normally too.
</p>

<script>
document.getElementById('addr').addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
document.getElementById('addr').focus();
function go() {
  const v = document.getElementById('addr').value.trim();
  if (!v) return;
  const hs = v.replace(/\\.phinet$/, '');
  // 64-hex (current Ed25519-derived) or 40-hex (legacy) hidden-service id
  if (/^[0-9a-fA-F]{64}$/.test(hs) || /^[0-9a-fA-F]{40}$/.test(hs)) {
    window.parent.postMessage({ type: 'navigate', url: 'http://' + hs.toLowerCase() + '.phinet/' }, '*');
  } else if (v.includes('://')) {
    window.parent.postMessage({ type: 'navigate', url: v }, '*');
  } else if (/^[\\w-]+(\\.[\\w-]+)+(\\/.*)?$/.test(v)) {
    window.parent.postMessage({ type: 'navigate', url: 'https://' + v }, '*');
  } else {
    window.parent.postMessage({ type: 'navigate', url: 'https://duckduckgo.com/?q=' + encodeURIComponent(v) }, '*');
  }
}
</script>
</body>
</html>`;
}

function errorPageHtml(url: string, err: string): string {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Error</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{background:#0d1117;color:#e6edf3;
  font-family:'Inter',-apple-system,system-ui,sans-serif;
  -webkit-font-smoothing:antialiased}
body{max-width:600px;margin:80px auto;padding:2rem;line-height:1.7}
.icon{font-size:3rem;margin-bottom:1rem;color:#f85149}
h1{color:#f85149;font-size:1.4rem;font-weight:600;margin-bottom:1rem}
.url{font-family:'JetBrains Mono',monospace;font-size:.85rem;
  background:#161b22;border:1px solid #30363d;
  border-radius:6px;padding:10px 14px;color:#58a6ff;
  word-break:break-all;margin-bottom:1.5rem}
.msg{color:#c9d1d9;margin-bottom:1rem}
.help{color:#7d8590;font-size:.85rem;line-height:1.8;
  border-top:1px solid #21262d;padding-top:1rem;margin-top:1rem}
code{font-family:'JetBrains Mono',monospace;
  background:#161b22;border:1px solid #30363d;border-radius:4px;
  padding:2px 6px;color:#58a6ff;font-size:.85em;word-break:break-all}
</style>
</head><body>
<div class="icon">⚠</div>
<h1>Could not load page</h1>
<div class="url">${url}</div>
<p class="msg">${err}</p>
<p class="help">If this is a <code>.phinet</code> address, make sure
<code>phinet-daemon</code> is running and the site has been deployed with
<code>phi deploy</code>. For HTTPS sites, check your network connection.</p>
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
      const data = e.data;
      if (!data || typeof data !== "object") return;

      if (data.type === "navigate" && data.url) {
        onUrlChange(data.url);
        return;
      }

      // Subresource fetch from inside the iframe. The preload script
      // we injected dispatches these for every <img>/<link>/<script>/
      // fetch()/XHR call. We invoke the Tauri backend, get the result,
      // post it back to the iframe by request id.
      if (data.type === "phinet-fetch" && typeof data.id === "number" && data.url) {
        const respond = (msg: any) => {
          // The iframe is the source of the original message; reply
          // by posting to its contentWindow if we still have it.
          const target = (e.source as Window | null) ?? frameRef.current?.contentWindow;
          if (target) target.postMessage({ type: "phinet-fetch-result", ...msg }, "*");
        };
        invoke<{ status: number; content_type: string; body_b64: string }>(
          "fetch_subresource",
          { url: data.url, method: data.method || "GET" }
        ).then(result => {
          respond({ id: data.id, status: result.status, content_type: result.content_type, body_b64: result.body_b64 });
        }).catch(err => {
          respond({ id: data.id, error: String(err) });
        });
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

        // Inject base tag so relative URLs resolve correctly. For
        // .phinet hosts, rewrite to the phinet:// scheme so the
        // custom URI scheme handler we registered in main.rs picks
        // up <img>/<link>/etc. Without this rewrite, subresources
        // would dispatch as http://hs_id.phinet/... which isn't
        // routable.
        let baseUrl = tab.url;
        const phinetMatch = tab.url.match(/^https?:\/\/([0-9a-fA-F]{40,64})\.phinet(\/.*)?$/);
        if (phinetMatch) {
          const hsId = phinetMatch[1].toLowerCase();
          const path = phinetMatch[2] || "/";
          baseUrl = `phinet://${hsId}${path}`;
        }
        const base = `<base href="${baseUrl}">`;

        // Subresource-interception preload script. Runs before any
        // page script (we put it as the first thing in <head>).
        // Overrides window.fetch and XMLHttpRequest so that any
        // network request the page makes — for images, CSS, JS,
        // XHR/fetch API calls — gets routed through the parent
        // window via postMessage, which has invoke() access to the
        // Tauri backend.
        //
        // Without this, an iframe rendered via srcdoc has *no*
        // network capability for absolute URLs and only works for
        // resources under the registered phinet:// scheme. With
        // this, every subresource request goes through us.
        //
        // Also installs **anti-fingerprinting basics**: normalizes
        // the most common fingerprinting surfaces so that two ΦNET
        // browser users look identical to a tracking script. This
        // is not full Tor Browser parity — that requires a forked
        // engine — but blocks the easy attacks like canvas
        // fingerprinting, navigator.plugins enumeration, screen
        // dimensions, and timezone offsets.
        const preload = `<script>(function(){
          if (window.__phinet_preload_installed) return;
          window.__phinet_preload_installed = true;

          // ── Anti-fingerprinting normalization ─────────────────────
          // Override navigator properties so all ΦNET users present
          // identical values. Spoof to Tor Browser's canonical values
          // for maximum anonymity-set size with the broader privacy
          // browser population.
          try {
            Object.defineProperty(navigator, 'userAgent', {
              get: function() { return 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'; },
              configurable: false,
            });
            Object.defineProperty(navigator, 'platform', {
              get: function() { return 'Linux x86_64'; }, configurable: false,
            });
            Object.defineProperty(navigator, 'language', {
              get: function() { return 'en-US'; }, configurable: false,
            });
            Object.defineProperty(navigator, 'languages', {
              get: function() { return ['en-US', 'en']; }, configurable: false,
            });
            Object.defineProperty(navigator, 'hardwareConcurrency', {
              get: function() { return 2; }, configurable: false,
            });
            Object.defineProperty(navigator, 'deviceMemory', {
              get: function() { return 4; }, configurable: false,
            });
            // Empty plugins/mimeTypes to match Tor Browser
            Object.defineProperty(navigator, 'plugins', {
              get: function() { return []; }, configurable: false,
            });
            Object.defineProperty(navigator, 'mimeTypes', {
              get: function() { return []; }, configurable: false,
            });
            // Honor Do Not Track, set globally
            Object.defineProperty(navigator, 'doNotTrack', {
              get: function() { return '1'; }, configurable: false,
            });
            // No webdriver flag (standard for non-automated browsing)
            Object.defineProperty(navigator, 'webdriver', {
              get: function() { return false; }, configurable: false,
            });
          } catch(_){}

          // Screen dimensions: pin to Tor Browser's canonical 1000×1000
          // letterbox. Most tracking scripts use screen.width/height
          // to fingerprint.
          try {
            Object.defineProperty(screen, 'width',  { get: function(){ return 1000; }, configurable: false });
            Object.defineProperty(screen, 'height', { get: function(){ return 1000; }, configurable: false });
            Object.defineProperty(screen, 'availWidth',  { get: function(){ return 1000; }, configurable: false });
            Object.defineProperty(screen, 'availHeight', { get: function(){ return 1000; }, configurable: false });
            Object.defineProperty(screen, 'colorDepth', { get: function(){ return 24; }, configurable: false });
            Object.defineProperty(screen, 'pixelDepth', { get: function(){ return 24; }, configurable: false });
          } catch(_){}

          // Timezone: report UTC for everyone. Most timezone-based
          // fingerprinting checks use Date.prototype.getTimezoneOffset.
          try {
            const _origGetOffset = Date.prototype.getTimezoneOffset;
            Date.prototype.getTimezoneOffset = function(){ return 0; };
            // Intl.DateTimeFormat.resolvedOptions() also leaks tz
            const _origResolved = Intl.DateTimeFormat.prototype.resolvedOptions;
            Intl.DateTimeFormat.prototype.resolvedOptions = function() {
              const r = _origResolved.call(this);
              r.timeZone = 'UTC';
              return r;
            };
          } catch(_){}

          // Canvas fingerprinting: add per-pixel noise to readback
          // operations so each call returns subtly different bytes.
          // Real Tor Browser asks for permission before allowing
          // canvas readback at all; this is a simpler approach that
          // breaks identification while keeping pages working.
          try {
            const noise = function(data) {
              // Perturb the alpha of a few random pixels by ±1
              for (var i = 0; i < 16; i++) {
                var idx = (Math.floor(Math.random() * (data.length / 4)) * 4) + 3;
                if (idx < data.length) data[idx] = data[idx] ^ 1;
              }
            };
            const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function() {
              const ctx = this.getContext('2d');
              if (ctx) {
                try {
                  const img = ctx.getImageData(0, 0, this.width, this.height);
                  noise(img.data);
                  ctx.putImageData(img, 0, 0);
                } catch(_){}
              }
              return _origToDataURL.apply(this, arguments);
            };
            const _origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            CanvasRenderingContext2D.prototype.getImageData = function() {
              const data = _origGetImageData.apply(this, arguments);
              noise(data.data);
              return data;
            };
          } catch(_){}

          // WebGL: refuse to expose renderer info (the standard
          // fingerprinting vector). Returning empty strings is safer
          // than spoofing — many sites use these only for "do you
          // have GPU acceleration" checks and an empty string fails
          // open.
          try {
            const _origGetParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(p) {
              // 0x9245 = UNMASKED_VENDOR_WEBGL, 0x9246 = UNMASKED_RENDERER_WEBGL
              if (p === 0x9245 || p === 0x9246) return '';
              // Vendor: 'WebKit', Renderer: 'WebKit WebGL' for everyone
              if (p === 0x1F00 /* VENDOR */)   return 'WebKit';
              if (p === 0x1F01 /* RENDERER */) return 'WebKit WebGL';
              return _origGetParameter.call(this, p);
            };
          } catch(_){}

          // Audio context: nudge the sample rate readback so audio
          // fingerprinting (which uses subtle floating-point
          // differences across hardware) doesn't work. We don't
          // disable audio; we just slightly perturb the values.
          try {
            const _origGetChannelData = AudioBuffer.prototype.getChannelData;
            AudioBuffer.prototype.getChannelData = function(ch) {
              const data = _origGetChannelData.call(this, ch);
              // Don't perturb every sample — that would audibly
              // distort sound. Just every 100th, which breaks
              // fingerprinting hashes but is inaudible.
              for (var i = 0; i < data.length; i += 100) {
                data[i] = data[i] + (Math.random() - 0.5) * 0.0000001;
              }
              return data;
            };
          } catch(_){}

          // Performance.now() resolution dampening: round to 100ms
          // so timing-based fingerprinting (cache-timing, JIT-warmup
          // detection) loses the precision it needs. Tor Browser
          // does this with a 100ms quantum.
          try {
            const _origNow = performance.now.bind(performance);
            performance.now = function() {
              return Math.floor(_origNow() / 100) * 100;
            };
          } catch(_){}

          // Block battery API entirely — pure fingerprinting surface.
          try { delete navigator.getBattery; } catch(_){}

          // Block WebRTC IP leak (RTCPeerConnection ICE candidates
          // can leak local network addresses). Constructor still
          // exists but throws on use.
          try {
            const _origRTC = window.RTCPeerConnection;
            window.RTCPeerConnection = function() {
              throw new Error('RTCPeerConnection blocked by ΦNET browser');
            };
          } catch(_){}

          // ── Subresource interception ─────────────────────────────
          var pending = {};
          var nextId = 1;

          window.addEventListener('message', function(e) {
            var d = e.data;
            if (!d || d.type !== 'phinet-fetch-result') return;
            var p = pending[d.id];
            if (!p) return;
            delete pending[d.id];
            if (d.error) p.reject(new Error(d.error));
            else p.resolve(d);
          });

          function dispatchFetch(url, init) {
            return new Promise(function(resolve, reject) {
              var id = nextId++;
              pending[id] = { resolve: resolve, reject: reject };
              window.parent.postMessage({
                type: 'phinet-fetch',
                id: id,
                url: url,
                method: (init && init.method) || 'GET',
                headers: (init && init.headers) || {},
              }, '*');
              setTimeout(function() {
                if (pending[id]) {
                  delete pending[id];
                  reject(new Error('phinet fetch timeout: ' + url));
                }
              }, 30000);
            });
          }

          // Override window.fetch
          var origFetch = window.fetch;
          window.fetch = function(input, init) {
            var url = typeof input === 'string' ? input
                    : (input && input.url) || String(input);
            return dispatchFetch(url, init).then(function(r) {
              // Build a Response-like object the page can use
              var bytes = Uint8Array.from(atob(r.body_b64), function(c) { return c.charCodeAt(0); });
              return new Response(bytes, {
                status: r.status,
                statusText: 'OK',
                headers: { 'Content-Type': r.content_type || 'application/octet-stream' },
              });
            });
          };

          // Override XMLHttpRequest. Browsers use this for legacy
          // AJAX; many libraries still depend on it.
          var OrigXHR = window.XMLHttpRequest;
          function PhinetXHR() {
            this._headers = {};
            this._method = 'GET';
            this._url = '';
            this.readyState = 0;
            this.status = 0;
            this.responseText = '';
            this.response = null;
          }
          PhinetXHR.prototype.open = function(method, url) {
            this._method = method;
            this._url = url;
            this.readyState = 1;
          };
          PhinetXHR.prototype.setRequestHeader = function(k, v) {
            this._headers[k] = v;
          };
          PhinetXHR.prototype.send = function(_body) {
            var self = this;
            dispatchFetch(self._url, { method: self._method, headers: self._headers })
              .then(function(r) {
                var bytes = Uint8Array.from(atob(r.body_b64), function(c) { return c.charCodeAt(0); });
                self.status = r.status;
                self.readyState = 4;
                // Best-effort text decode for responseText
                try { self.responseText = new TextDecoder().decode(bytes); }
                catch(_) { self.responseText = ''; }
                self.response = self.responseText;
                if (typeof self.onreadystatechange === 'function') self.onreadystatechange();
                if (typeof self.onload === 'function') self.onload();
              })
              .catch(function(err) {
                self.status = 0;
                self.readyState = 4;
                if (typeof self.onerror === 'function') self.onerror(err);
                else if (typeof self.onreadystatechange === 'function') self.onreadystatechange();
              });
          };
          PhinetXHR.prototype.abort = function() {};
          PhinetXHR.prototype.getAllResponseHeaders = function() { return ''; };
          PhinetXHR.prototype.getResponseHeader = function() { return null; };
          window.XMLHttpRequest = PhinetXHR;
        })();</` + `script>`;

        const withBase = html.includes("<head>")
          ? html.replace("<head>", `<head>${base}${preload}`)
          : base + preload + html;

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
