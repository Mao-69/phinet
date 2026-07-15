// phinet-browser/src-tauri/src/main.rs
//! com — the ΦNET end-to-end encrypted messenger, as a native Tauri
//! desktop app. The UI (React) calls these commands; each one bridges
//! to the running ΦNET daemon's control socket (127.0.0.1:7799) with a
//! single line-delimited JSON request, exactly like the ΦNET browser.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod vault;
mod daemon;

use serde_json::{json, Value};
use tauri::Manager;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

/// Control-socket port the daemon listens on (its default `--ctl-port`).
const CTL_ADDR: &str = "127.0.0.1:7799";

/// Send one control request and read one JSON response line.
async fn ctl(req: Value) -> Option<Value> {
    let stream = TcpStream::connect(CTL_ADDR).await.ok()?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let mut line = req.to_string();
    line.push('\n');
    writer.write_all(line.as_bytes()).await.ok()?;
    writer.flush().await.ok()?;
    let resp = lines.next_line().await.ok()??;
    serde_json::from_str(&resp).ok()
}

fn offline() -> Value { json!({ "ok": false, "error": "daemon offline" }) }

#[tauri::command]
async fn whoami() -> Value {
    ctl(json!({ "cmd": "whoami" })).await.unwrap_or_else(offline)
}

/// Connected peers, usable as contacts (node_id + static_pub + addr).
#[tauri::command]
async fn peers() -> Value {
    ctl(json!({ "cmd": "peers" })).await.unwrap_or_else(offline)
}

/// Conversation thread peer ids, most-recent first.
#[tauri::command]
async fn com_threads() -> Value {
    ctl(json!({ "cmd": "com_threads" })).await.unwrap_or_else(offline)
}

/// Messages in the conversation with `peer` (hex node id).
#[tauri::command]
async fn com_thread(peer: String) -> Value {
    ctl(json!({ "cmd": "com_thread", "node_id_hex": peer })).await
        .unwrap_or_else(offline)
}

/// Send an end-to-end-encrypted message to `peer`. Works whether the
/// recipient is online (direct) or offline (store-and-forward), as long
/// as the daemon has learned the recipient's key.
#[tauri::command]
async fn com_send(peer: String, text: String) -> Value {
    ctl(json!({ "cmd": "com_send", "node_id_hex": peer, "text": text })).await
        .unwrap_or_else(offline)
}

/// Groups & channels.
#[tauri::command]
async fn com_groups() -> Value {
    ctl(json!({ "cmd": "com_groups" })).await.unwrap_or_else(offline)
}

#[tauri::command]
async fn com_create_group(name: String, is_channel: bool) -> Value {
    ctl(json!({ "cmd": "com_create_group", "name": name, "is_channel": is_channel }))
        .await.unwrap_or_else(offline)
}

#[tauri::command]
async fn com_invite(group_id: String, peer: String) -> Value {
    ctl(json!({ "cmd": "com_invite", "group_id": group_id, "node_id_hex": peer }))
        .await.unwrap_or_else(offline)
}

#[tauri::command]
async fn com_send_group(group_id: String, text: String) -> Value {
    ctl(json!({ "cmd": "com_send_group", "group_id": group_id, "text": text }))
        .await.unwrap_or_else(offline)
}

/// This node's shareable com address (phi:<128 hex>). Hand it out so
/// others can add you — there is no public roster.
#[tauri::command]
async fn com_my_address() -> Value {
    ctl(json!({ "cmd": "com_my_address" })).await.unwrap_or_else(offline)
}

/// Add a contact from an address someone shared with you out of band.
#[tauri::command]
async fn com_add_contact(address: String) -> Value {
    ctl(json!({ "cmd": "com_add_contact", "address": address })).await
        .unwrap_or_else(offline)
}


/// Unsend a message (removes it here and asks the peer to remove it).
#[tauri::command]
async fn com_delete(peer: String, msg_id: String) -> Value {
    ctl(json!({ "cmd": "com_delete", "node_id_hex": peer, "msg_id": msg_id })).await
        .unwrap_or_else(offline)
}

/// Fetch a `.phinet` hidden site through the local node. `hs_id` is the
/// site id (without the .phinet suffix); returns { ok, status, body_b64 }.
#[tauri::command]
async fn browser_fetch(hs_id: String, path: String) -> Value {
    ctl(json!({ "cmd": "hs_fetch", "hs_id": hs_id, "path": path, "method": "GET" })).await
        .unwrap_or_else(offline)
}

/// Open a clearnet URL in a real webview window. An iframe can't show most
/// sites (X-Frame-Options / CSP frame-ancestors block embedding → white
/// screen); a top-level webview navigation isn't subject to that. Note:
/// clearnet traffic is a DIRECT connection, not routed through ΦNET.
#[tauri::command]
async fn open_web(app: tauri::AppHandle, url: String) -> Value {
    use tauri::{WebviewUrl, WebviewWindowBuilder};
    let parsed = match url.parse() {
        Ok(u) => u,
        Err(e) => return json!({ "ok": false, "error": format!("bad url: {e}") }),
    };
    // Reuse a single "web" window so we don't spawn one per navigation.
    if let Some(w) = app.get_webview_window("web") {
        let _ = w.eval(&format!("window.location.replace({:?})", url));
        let _ = w.set_focus();
        return json!({ "ok": true });
    }
    match WebviewWindowBuilder::new(&app, "web", WebviewUrl::External(parsed))
        .title("Web")
        .inner_size(1100.0, 800.0)
        .build()
    {
        Ok(_)  => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

/// Tor-style circuit + identity view.
#[tauri::command]
async fn circuit_info() -> Value {
    ctl(json!({ "cmd": "circuit_info" })).await.unwrap_or_else(offline)
}

/// Rotate to a new identity (retire guards, drop circuits, reselect).
#[tauri::command]
async fn new_identity() -> Value {
    ctl(json!({ "cmd": "new_identity" })).await.unwrap_or_else(offline)
}

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(vault::VaultState::default())
        .manage(daemon::DaemonGuard::default())
        .setup(|app| {
            // Auto-bootstrap: make sure a local node is running + joining the
            // network the moment the app opens.
            let guard = app.state::<daemon::DaemonGuard>();
            let status = daemon::ensure_running(guard.inner());
            eprintln!("[phinet] {status}");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            whoami,
            peers,
            com_threads,
            com_thread,
            com_send,
            com_delete,
            com_groups,
            com_create_group,
            com_invite,
            com_send_group,
            com_my_address,
            com_add_contact,
            browser_fetch,
            open_web,
            circuit_info,
            new_identity,
            daemon::daemon_status,
            vault::vault_exists,
            vault::vault_status,
            vault::vault_create,
            vault::vault_unlock,
            vault::vault_lock,
            vault::vault_list,
            vault::vault_add,
            vault::vault_delete,
            vault::vault_import,
            vault::vault_reveal,
            vault::vault_share_body,
        ])
        .build(tauri::generate_context!())
        .expect("error while building com")
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                    daemon::shutdown(app.state::<daemon::DaemonGuard>().inner());
            }
        });
}
