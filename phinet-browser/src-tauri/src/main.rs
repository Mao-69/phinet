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

    // Clearnet URLs: not supported in this build
    // (would need reqwest or system proxy; browser is .phinet-focused)
    Err(format!(
        "Clearnet URLs are not yet supported. Navigate to a .phinet address instead.\n\
         URL attempted: {url}"
    ))
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

fn not_found_html(hs_id: &str, _url: &str) -> Vec<u8> {
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Not found</title>\
         <style>body{{font-family:monospace;background:#080812;color:#b8c8e0;\
         max-width:560px;margin:60px auto;padding:2rem;line-height:1.7}}\
         h1{{color:#c04848}}p{{color:#4a5878}}\
         code{{background:#0e0e1c;padding:1px 6px;border-radius:3px;color:#8ab4e8}}</style>\
         </head><body>\
         <h1>Site not found</h1>\
         <p><code>{hs_id}.phinet</code></p>\
         <p>Make sure the daemon is running and the site has been deployed:</p>\
         <p><code>phinet-daemon --port 7700</code></p>\
         <p><code>phi deploy {hs_id} ./my-site/</code></p>\
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

    tauri::Builder::default()
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
