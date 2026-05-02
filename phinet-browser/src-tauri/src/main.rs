// phinet-browser/src-tauri/src/main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use phinet_core::store::SiteStore;
use serde::{Serialize};
use std::{net::TcpListener, sync::Arc};
use tauri::{State};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::Mutex,
};
use tracing::info;

mod proxy;

// ── App state ─────────────────────────────────────────────────────────

pub struct AppState {
    store:         Arc<SiteStore>,
    daemon_online: Arc<Mutex<bool>>,
    socks_port:    u16,   // renamed from proxy_port to avoid shadowing the command
}

// ── Daemon control ────────────────────────────────────────────────────

async fn ctl(req: serde_json::Value) -> Option<serde_json::Value> {
    let stream = TcpStream::connect("127.0.0.1:7799").await.ok()?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let mut line = req.to_string();
    line.push('\n');
    writer.write_all(line.as_bytes()).await.ok()?;
    writer.flush().await.ok()?;
    let resp = lines.next_line().await.ok()??;
    serde_json::from_str(&resp).ok()
}

// ── Tauri commands ────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DaemonStatus {
    online:    bool,
    node_id:   Option<String>,
    peers:     u64,
    dht_keys:  u64,
    cert_bits: Option<u64>,
}

#[tauri::command]
async fn daemon_status(state: State<'_, AppState>) -> Result<DaemonStatus, String> {
    match ctl(serde_json::json!({"cmd": "whoami"})).await {
        Some(r) => {
            *state.daemon_online.lock().await = true;
            Ok(DaemonStatus {
                online:    true,
                node_id:   r["node_id"].as_str().map(|s| s[..16.min(s.len())].to_string()),
                peers:     r["peers"].as_u64().unwrap_or(0),
                dht_keys:  r["dht_keys"].as_u64().unwrap_or(0),
                cert_bits: r["cert_bits"].as_u64(),
            })
        }
        None => {
            *state.daemon_online.lock().await = false;
            Ok(DaemonStatus { online: false, node_id: None, peers: 0, dht_keys: 0, cert_bits: None })
        }
    }
}

#[derive(Serialize)]
pub struct ServiceInfo {
    hs_id:   String,
    name:    String,
    address: String,
    files:   Vec<String>,
    created: u64,
}

#[tauri::command]
async fn list_services(state: State<'_, AppState>) -> Result<Vec<ServiceInfo>, String> {
    let svcs = state.store.list_services().await;
    let mut out = Vec::new();
    for m in svcs {
        let files = state.store.list_files(&m.hs_id).await;
        out.push(ServiceInfo {
            address: format!("{}.phinet", m.hs_id),
            hs_id:   m.hs_id,
            name:    m.name,
            files,
            created: m.created,
        });
    }
    Ok(out)
}

#[tauri::command]
async fn create_service(name: String, state: State<'_, AppState>) -> Result<ServiceInfo, String> {
    let hs_id = {
        let resp = ctl(serde_json::json!({"cmd":"whoami"})).await;
        match resp.and_then(|r| r["node_id"].as_str().map(|s| s[..40.min(s.len())].to_string())) {
            Some(id) => id,
            None     => random_id(),
        }
    };
    state.store.create_service(&hs_id, &name, &random_id()).await
        .map_err(|e| e.to_string())?;
    Ok(ServiceInfo {
        address: format!("{}.phinet", hs_id),
        files:   state.store.list_files(&hs_id).await,
        hs_id,
        name,
        created: unix_now(),
    })
}

#[tauri::command]
async fn upload_file(
    hs_id:    String,
    url_path: String,
    body_hex: String,
    state:    State<'_, AppState>,
) -> Result<(), String> {
    let body = hex::decode(&body_hex).map_err(|e| e.to_string())?;
    let path = if url_path.starts_with('/') { url_path } else { format!("/{}", url_path) };
    state.store.put_file(&hs_id, &path, &body).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_service(hs_id: String, state: State<'_, AppState>) -> Result<(), String> {
    state.store.delete_service(&hs_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn register_service(
    hs_id: String,
    name:  String,
    _state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    ctl(serde_json::json!({"cmd":"hs_register","hs_id":hs_id,"name":name}))
        .await
        .ok_or_else(|| "daemon not reachable".into())
}

#[tauri::command]
async fn fetch_page(url: String, state: State<'_, AppState>) -> Result<FetchResult, String> {
    let is_phinet = url.contains(".phinet");

    if is_phinet {
        // Extract hs_id and path from the URL
        // e.g. http://3e40e4f8...phinet/some/path
        let without_scheme = url
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let (host_part, path) = without_scheme
            .split_once('/')
            .map(|(h, p)| (h, format!("/{}", p)))
            .unwrap_or((without_scheme, "/".to_string()));
        let hs_id = host_part
            .trim_end_matches(".phinet")
            .to_lowercase();

        // 1. Try daemon control socket (serves from DHT / intro points)
        if let Some(resp) = fetch_via_daemon(&hs_id, &path).await {
            return Ok(resp);
        }

        // 2. Fall back to local disk store
        if let Some((status, ct, body)) = state.store.get_file(&hs_id, &path).await {
            return Ok(FetchResult {
                status,
                content_type: ct,
                body_hex: hex::encode(&body),
                is_phinet: true,
            });
        }

        // 3. Not found anywhere
        return Ok(FetchResult {
            status:       404,
            content_type: "text/html; charset=utf-8".into(),
            body_hex:     hex::encode(not_found_html(&hs_id, &url)),
            is_phinet:    true,
        });
    }

    // ── Clearnet (HTTP/HTTPS) ─────────────────────────────────────
    //
    // Real-world web fetch via reqwest + rustls. No openssl dep, so
    // this works cross-platform without any system TLS configuration.
    //
    // Design notes:
    //   * `User-Agent` mimics a stock browser to avoid the long tail
    //     of sites that reject obviously-headless clients.
    //   * No referer header — privacy-preserving default.
    //   * Auto-decoding for gzip/brotli/deflate is handled by reqwest.
    //   * Redirects follow up to 10 hops (reqwest default).
    //   * No cookies are persisted between fetches — each call is
    //     stateless. A future cookie-jar feature would attach here.
    //   * 30-second total timeout protects against pathological sites
    //     that hang the connection without sending data.
    fetch_clearnet(&url).await
}

async fn fetch_clearnet(url: &str) -> Result<FetchResult, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) \
             Gecko/20100101 Firefox/128.0"
        )
        // Don't auto-add a Referer when following redirects — the
        // ΦNET browser is privacy-first.
        .referer(false)
        .build()
        .map_err(|e| format!("HTTP client init: {e}"))?;

    let resp = client.get(url).send().await
        .map_err(|e| format!("Fetch failed: {e}"))?;

    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    // Cap body at 50MB so a runaway response doesn't OOM the renderer.
    // We accumulate chunks and check size on each one — checking only
    // after the full body is read defeats the purpose, since a server
    // claiming Content-Length: 100GB would already have OOMed us.
    const MAX_BODY: usize = 50 * 1024 * 1024;

    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Read body: {e}"))?;
        if buf.len() + chunk.len() > MAX_BODY {
            return Err(format!(
                "Response too large (max {} MB)",
                MAX_BODY / (1024 * 1024)
            ));
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(FetchResult {
        status,
        content_type,
        body_hex: hex::encode(&buf),
        is_phinet: false,
    })
}

#[derive(Serialize)]
struct SubresourceResult {
    status:       u16,
    content_type: String,
    /// Base64-encoded raw body. Base64 instead of hex because
    /// subresources are often binary (images, fonts) and base64
    /// is 33% smaller than hex over the IPC boundary, which adds
    /// up when a page loads dozens of resources.
    body_b64:     String,
}

/// Fetch any subresource the iframe asks for. Called by the preload
/// script's overridden `window.fetch` and `XMLHttpRequest`. Routes:
///
///   - `phinet://hs_id/path` → daemon (already proxied via custom
///     URI scheme handler, but iframe srcdoc can't always reach
///     custom schemes for fetch(), so we re-route here for symmetry).
///   - Bare relative paths → caller is expected to resolve them
///     against the page's base href before calling, but as a
///     fallback we treat unknown schemes as errors.
///   - `http(s)://...` → plain reqwest fetch, same code path as the
///     top-level fetch_clearnet.
///
/// All responses come back base64-encoded so binary content survives
/// the JSON IPC channel intact.
#[tauri::command]
async fn fetch_subresource(url: String, method: Option<String>) -> Result<SubresourceResult, String> {
    let _method = method.unwrap_or_else(|| "GET".into());

    // Route by scheme
    if let Some(rest) = url.strip_prefix("phinet://") {
        // phinet://hs_id/path → daemon hs_fetch
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None    => (rest, "/"),
        };
        if host.is_empty() {
            return Err("empty hs_id in phinet:// URL".into());
        }
        let daemon_result = fetch_via_daemon(host, path).await
            .ok_or_else(|| format!("daemon fetch failed for {}", url))?;
        let bytes = hex::decode(&daemon_result.body_hex)
            .map_err(|e| format!("body hex decode: {e}"))?;
        return Ok(SubresourceResult {
            status:       daemon_result.status,
            content_type: daemon_result.content_type,
            body_b64:     base64_encode(&bytes),
        });
    }

    if url.starts_with("http://") || url.starts_with("https://") {
        // Reuse the existing clearnet fetcher for consistency. It
        // already handles streaming-with-cap, gzip/brotli, sane
        // timeouts, no Referer/cookies. The only conversion is
        // body_hex → body_b64.
        let r = fetch_clearnet(&url).await?;
        let bytes = hex::decode(&r.body_hex)
            .map_err(|e| format!("body hex decode: {e}"))?;
        return Ok(SubresourceResult {
            status:       r.status,
            content_type: r.content_type,
            body_b64:     base64_encode(&bytes),
        });
    }

    Err(format!("unsupported subresource URL scheme: {}", url))
}

/// Standard base64 encode without padding control. Using a small
/// inline implementation to avoid pulling in another dep just for
/// this one function. ~10 lines.
fn base64_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHA[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

async fn fetch_via_daemon(hs_id: &str, path: &str) -> Option<FetchResult> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let stream = TcpStream::connect("127.0.0.1:7799").await.ok()?;
    let (reader, mut writer) = stream.into_split();
    let req = serde_json::json!({
        "cmd":    "hs_fetch",
        "hs_id":  hs_id,
        "path":   path,
        "method": "GET",
    });
    let mut line = req.to_string();
    line.push('\n');
    writer.write_all(line.as_bytes()).await.ok()?;
    writer.flush().await.ok()?;

    let mut lines = BufReader::new(reader).lines();
    let resp_str = lines.next_line().await.ok()??;
    let resp: serde_json::Value = serde_json::from_str(&resp_str).ok()?;

    if resp["ok"].as_bool() != Some(true) { return None; }

    let status = resp["status"].as_u64().unwrap_or(200) as u16;
    let ct = resp["headers"]["Content-Type"]
        .as_str()
        .unwrap_or("text/html; charset=utf-8")
        .to_string();
    let body_hex = resp["body_b64"].as_str().unwrap_or("").to_string();

    Some(FetchResult { status, content_type: ct, body_hex, is_phinet: true })
}

/// Fetch a phinet:// subresource through the daemon. Used by the
/// custom URI scheme handler. Returns (status, content_type, body_bytes).
///
/// URL format: `phinet://<hs_id>/<path>`. We extract hs_id from the
/// host part and the rest as the path. The daemon's hs_fetch handler
/// returns hex-encoded bodies — we decode to raw bytes here so the
/// WebView gets the binary content (images, etc.) intact.
async fn fetch_phinet_subresource(
    url: &str,
    _socks_port: u16,
) -> std::result::Result<(u16, String, Vec<u8>), String> {
    // Parse: phinet://hs_id[/path]
    let url = url.strip_prefix("phinet://")
        .ok_or_else(|| "url missing phinet:// prefix".to_string())?;
    let (host, path) = match url.find('/') {
        Some(i) => (&url[..i], &url[i..]),
        None    => (url, "/"),
    };
    if host.is_empty() {
        return Err("empty hs_id in phinet:// URL".into());
    }

    // Reuse the existing daemon-fetch path. The daemon handles
    // descriptor lookup, rendezvous setup, circuit construction,
    // HTTP request through the rendezvous circuit. All we do here
    // is the hex-decode of the body.
    let result = fetch_via_daemon(host, path).await
        .ok_or_else(|| format!("daemon could not fetch phinet://{}{}", host, path))?;

    let bytes = hex::decode(&result.body_hex)
        .map_err(|e| format!("body decode: {e}"))?;
    Ok((result.status, result.content_type, bytes))
}

fn not_found_html(hs_id: &str, _url: &str) -> Vec<u8> {
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Not found</title>\
         <style>\
         @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono&display=swap');\
         *{{box-sizing:border-box;margin:0;padding:0}}\
         body{{font-family:'Inter',-apple-system,system-ui,sans-serif;\
         background:#0d1117;color:#e6edf3;\
         max-width:600px;margin:80px auto;padding:2rem;line-height:1.7;\
         -webkit-font-smoothing:antialiased}}\
         .icon{{font-size:3rem;margin-bottom:1rem;opacity:.6}}\
         h1{{color:#f85149;font-size:1.4rem;font-weight:600;margin-bottom:1rem}}\
         p{{color:#c9d1d9;margin-bottom:.8rem}}\
         code{{font-family:'JetBrains Mono',monospace;\
         background:#161b22;border:1px solid #30363d;\
         border-radius:4px;padding:2px 8px;color:#58a6ff;\
         word-break:break-all;font-size:.9em}}\
         .deploy{{color:#7d8590;font-size:.9rem;margin-top:1.5rem;\
         border-top:1px solid #21262d;padding-top:1rem;line-height:2}}\
         .deploy code{{display:inline-block;padding:4px 10px;margin-top:4px}}\
         </style></head><body>\
         <div class=\"icon\">🔍</div>\
         <h1>Site not found</h1>\
         <p><code>{hs_id}.phinet</code></p>\
         <div class=\"deploy\">\
         <p>Make sure the daemon is running and the site has been deployed:</p>\
         <code>phinet-daemon --port 7700</code><br>\
         <code>phi deploy {hs_id} ./my-site/</code>\
         </div>\
         </body></html>"
    ).into_bytes()
}

#[derive(Serialize)]
pub struct FetchResult {
    status:       u16,
    content_type: String,
    body_hex:     String,
    is_phinet:    bool,
}

#[tauri::command]
async fn connect_peer(host: String, port: u16) -> Result<serde_json::Value, String> {
    ctl(serde_json::json!({"cmd":"connect","name":host,"path":port.to_string()}))
        .await
        .ok_or_else(|| "daemon not reachable — is phinet-daemon running?".into())
}

// Renamed from proxy_port → socks_proxy_port to avoid clashing with the
// local variable `proxy_port` / `socks_port` in main().
#[tauri::command]
fn socks_proxy_port(state: State<'_, AppState>) -> u16 {
    state.socks_port
}

// ── Main ──────────────────────────────────────────────────────────────

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("phinet=info,phinet_core=info")
        .init();

    let socks_port = find_free_port(19050);
    let store      = Arc::new(SiteStore::new());

    let store_ref = store.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(proxy::run_proxy("127.0.0.1", socks_port, store_ref));
    });

    info!("PHINET Browser — proxy on 127.0.0.1:{}", socks_port);

    // Register a custom phinet:// URI scheme so iframes loading
    // .phinet content can fetch subresources (images, CSS, JS)
    // through our local SOCKS proxy. Without this, iframe-srcdoc
    // pages can render top-level HTML but every <img>/<link> 404s
    // because the iframe has no context for relative URLs.
    //
    // Wire format: phinet://<hs_id>/<path> → proxy to <hs_id>.phinet/<path>
    // through the local SOCKS5 daemon, return raw bytes with the
    // upstream Content-Type. The WebView treats these like any
    // other HTTP response.
    let socks_for_proto = socks_port;

    tauri::Builder::default()
        .register_uri_scheme_protocol("phinet", move |_app, req| {
            let socks = socks_for_proto;
            let url = req.uri().to_string();
            // Clone for the worker thread; keep `url` available for
            // logging on the error path.
            let url_for_thread = url.clone();
            // The WebView decodes the response synchronously, but we
            // need an async runtime to do the SOCKS5 dial + HTTP
            // fetch. Block on a one-shot tokio runtime.
            let body = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("rt: {e}"))?;
                rt.block_on(fetch_phinet_subresource(&url_for_thread, socks))
            }).join().unwrap_or_else(|_| Err("thread panic".into()));

            match body {
                Ok((status, content_type, bytes)) => {
                    tauri::http::Response::builder()
                        .status(status)
                        .header("Content-Type", content_type)
                        // Allow the page itself to embed these resources.
                        .header("Access-Control-Allow-Origin", "*")
                        .body(bytes)
                        .unwrap_or_else(|_| {
                            tauri::http::Response::builder()
                                .status(500)
                                .body(b"phinet:// internal error".to_vec())
                                .unwrap()
                        })
                }
                Err(e) => {
                    tracing::warn!("phinet:// {} failed: {}", url, e);
                    tauri::http::Response::builder()
                        .status(502)
                        .header("Content-Type", "text/plain; charset=utf-8")
                        .body(format!("phinet:// fetch error: {e}").into_bytes())
                        .unwrap()
                }
            }
        })
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            store,
            daemon_online: Arc::new(Mutex::new(false)),
            socks_port,
        })
        .invoke_handler(tauri::generate_handler![
            daemon_status,
            list_services,
            create_service,
            upload_file,
            delete_service,
            register_service,
            fetch_page,
            fetch_subresource,
            connect_peer,
            socks_proxy_port,
        ])
        .run(tauri::generate_context!())
        .expect("Tauri error");
}

fn find_free_port(preferred: u16) -> u16 {
    if TcpListener::bind(format!("127.0.0.1:{}", preferred)).is_ok() {
        return preferred;
    }
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn random_id() -> String {
    use rand::RngCore;
    let mut v = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut v);
    hex::encode(v)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
