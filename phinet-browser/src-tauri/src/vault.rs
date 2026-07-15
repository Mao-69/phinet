// phinet-browser/src-tauri/src/vault.rs
//! Desktop vault — pure-Rust crypto so it builds identically on Linux,
//! Windows, and macOS with no C cross-compile. Same primitives as the
//! Android Lockr vault: Argon2id derives the master key from a passphrase,
//! XChaCha20-Poly1305 seals the data.
//!
//! Layout under <app-data>/phinet-vault/:
//!   vault.salt   — Argon2 salt (not secret)
//!   index.enc    — sealed JSON list of items (small text items inline)
//!   blobs/<id>   — sealed file contents (one AEAD blob each)
//!
//! The master key lives only in memory (VaultState) while unlocked.

use argon2::{Argon2, Algorithm, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, path::PathBuf, sync::Mutex};

const AAD_SALT: &str = "phinet_vault_v1";

#[derive(Default)]
pub struct VaultState {
    pub master: Mutex<Option<[u8; 32]>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultItem {
    pub id: String,
    pub kind: String,           // "link" | "note" | "secret" | "file"
    pub title: String,
    #[serde(default)]
    pub content: String,        // small text items
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub mime: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct Index {
    items: Vec<VaultItem>,
}

fn dir() -> PathBuf {
    let mut d = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    d.push("phinet-vault");
    d
}
fn salt_path() -> PathBuf { dir().join("vault.salt") }
fn index_path() -> PathBuf { dir().join("index.enc") }
fn blob_path(id: &str) -> PathBuf { dir().join("blobs").join(id) }

fn derive(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(65536, 3, 2, Some(32)).map_err(|e| e.to_string())?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    a.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

/// nonce(24) || ciphertext+tag
fn seal(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plain)
        .map_err(|_| "encrypt failed".to_string())?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}
fn open(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 24 { return Err("blob too short".into()); }
    let cipher = XChaCha20Poly1305::new(key.into());
    let (nonce, ct) = data.split_at(24);
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| "wrong passphrase or corrupt data".to_string())
}

fn read_index(key: &[u8; 32]) -> Index {
    let p = index_path();
    if !p.exists() { return Index::default(); }
    match fs::read(&p).ok().and_then(|b| open(key, &b).ok()) {
        Some(plain) => serde_json::from_slice(&plain).unwrap_or_default(),
        None => Index::default(),
    }
}
fn write_index(key: &[u8; 32], idx: &Index) -> Result<(), String> {
    fs::create_dir_all(dir()).map_err(|e| e.to_string())?;
    let plain = serde_json::to_vec(idx).map_err(|e| e.to_string())?;
    fs::write(index_path(), seal(key, &plain)?).map_err(|e| e.to_string())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0)
}

// ── Tauri commands ──────────────────────────────────────────────

#[tauri::command]
pub fn vault_exists() -> bool { salt_path().exists() }

#[tauri::command]
pub fn vault_status(state: tauri::State<VaultState>) -> Value {
    json!({ "exists": salt_path().exists(), "unlocked": state.master.lock().unwrap().is_some() })
}

#[tauri::command]
pub fn vault_create(passphrase: String, state: tauri::State<VaultState>) -> Value {
    if passphrase.len() < 6 { return json!({ "ok": false, "error": "use at least 6 characters" }); }
    if let Err(e) = fs::create_dir_all(dir().join("blobs")) { return json!({ "ok": false, "error": e.to_string() }); }
    let mut salt = [0u8; 16]; OsRng.fill_bytes(&mut salt);
    if let Err(e) = fs::write(salt_path(), salt) { return json!({ "ok": false, "error": e.to_string() }); }
    match derive(&passphrase, &salt) {
        Ok(key) => {
            if let Err(e) = write_index(&key, &Index::default()) { return json!({ "ok": false, "error": e }); }
            *state.master.lock().unwrap() = Some(key);
            json!({ "ok": true })
        }
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

#[tauri::command]
pub fn vault_unlock(passphrase: String, state: tauri::State<VaultState>) -> Value {
    let salt = match fs::read(salt_path()) { Ok(s) => s, Err(_) => return json!({ "ok": false, "error": "no vault yet" }) };
    let key = match derive(&passphrase, &salt) { Ok(k) => k, Err(e) => return json!({ "ok": false, "error": e }) };
    // verify by decrypting the index
    let p = index_path();
    if p.exists() {
        match fs::read(&p).ok().and_then(|b| open(&key, &b).ok()) {
            Some(_) => {}
            None => return json!({ "ok": false, "error": "wrong passphrase" }),
        }
    }
    *state.master.lock().unwrap() = Some(key);
    json!({ "ok": true })
}

#[tauri::command]
pub fn vault_lock(state: tauri::State<VaultState>) { *state.master.lock().unwrap() = None; }

#[tauri::command]
pub fn vault_list(state: tauri::State<VaultState>) -> Value {
    let g = state.master.lock().unwrap();
    match g.as_ref() {
        Some(key) => json!({ "ok": true, "items": read_index(key).items }),
        None => json!({ "ok": false, "error": "locked" }),
    }
}

#[tauri::command]
pub fn vault_add(kind: String, title: String, content: String, state: tauri::State<VaultState>) -> Value {
    let g = state.master.lock().unwrap();
    let key = match g.as_ref() { Some(k) => k, None => return json!({ "ok": false, "error": "locked" }) };
    let mut idx = read_index(key);
    idx.items.insert(0, VaultItem {
        id: uuid::Uuid::new_v4().to_string(), kind, title, content,
        file_name: String::new(), mime: String::new(), size: 0, created_at: now(),
    });
    match write_index(key, &idx) { Ok(_) => json!({ "ok": true, "items": idx.items }), Err(e) => json!({ "ok": false, "error": e }) }
}

#[tauri::command]
pub fn vault_delete(id: String, state: tauri::State<VaultState>) -> Value {
    let g = state.master.lock().unwrap();
    let key = match g.as_ref() { Some(k) => k, None => return json!({ "ok": false, "error": "locked" }) };
    let mut idx = read_index(key);
    idx.items.retain(|i| i.id != id);
    let _ = fs::remove_file(blob_path(&id));
    match write_index(key, &idx) { Ok(_) => json!({ "ok": true, "items": idx.items }), Err(e) => json!({ "ok": false, "error": e }) }
}

/// Import a file from disk: read → seal → store as a FILE item.
#[tauri::command]
pub fn vault_import(path: String, state: tauri::State<VaultState>) -> Value {
    let g = state.master.lock().unwrap();
    let key = match g.as_ref() { Some(k) => k, None => return json!({ "ok": false, "error": "locked" }) };
    let src = std::path::Path::new(&path);
    let name = src.file_name().and_then(|s| s.to_str()).unwrap_or("file").to_string();
    let bytes = match fs::read(src) { Ok(b) => b, Err(e) => return json!({ "ok": false, "error": e.to_string() }) };
    let size = bytes.len() as u64;
    let id = uuid::Uuid::new_v4().to_string();
    let sealed = match seal(key, &bytes) { Ok(s) => s, Err(e) => return json!({ "ok": false, "error": e }) };
    if let Err(e) = fs::create_dir_all(dir().join("blobs")) { return json!({ "ok": false, "error": e.to_string() }); }
    if let Err(e) = fs::write(blob_path(&id), sealed) { return json!({ "ok": false, "error": e.to_string() }); }
    let mime = mime_for(&name);
    let mut idx = read_index(key);
    idx.items.insert(0, VaultItem {
        id, kind: "file".into(), title: name.clone(), content: String::new(),
        file_name: name, mime, size, created_at: now(),
    });
    match write_index(key, &idx) { Ok(_) => json!({ "ok": true, "items": idx.items }), Err(e) => json!({ "ok": false, "error": e }) }
}

/// Decrypt a file item to a temp path for viewing/opening. Returns the path;
/// the caller can open it with the OS. (Temp file is the OS temp dir.)
#[tauri::command]
pub fn vault_reveal(id: String, state: tauri::State<VaultState>) -> Value {
    let g = state.master.lock().unwrap();
    let key = match g.as_ref() { Some(k) => k, None => return json!({ "ok": false, "error": "locked" }) };
    let idx = read_index(key);
    let item = match idx.items.iter().find(|i| i.id == id) { Some(i) => i, None => return json!({ "ok": false, "error": "not found" }) };
    let sealed = match fs::read(blob_path(&id)) { Ok(b) => b, Err(e) => return json!({ "ok": false, "error": e.to_string() }) };
    let plain = match open(key, &sealed) { Ok(p) => p, Err(e) => return json!({ "ok": false, "error": e }) };
    let mut tmp = std::env::temp_dir();
    tmp.push(format!("phinet-{}-{}", &id[..8], item.file_name));
    if let Err(e) = fs::write(&tmp, &plain) { return json!({ "ok": false, "error": e.to_string() }); }
    json!({ "ok": true, "path": tmp.to_string_lossy(), "mime": item.mime })
}

/// Encode a small (non-file) item as a shareable payload the recipient's
/// client renders as a vault card (same tagged prefix as Android).
#[tauri::command]
pub fn vault_share_body(kind: String, title: String, content: String) -> Value {
    let payload = json!({ "id": "shared", "kind": kind, "title": title, "content": content });
    json!({ "ok": true, "body": format!("\u{1}phinet-vault\u{1}{}", payload) })
}

fn mime_for(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "png" => "image/png", "jpg" | "jpeg" => "image/jpeg", "gif" => "image/gif",
        "webp" => "image/webp", "pdf" => "application/pdf", "mp4" => "video/mp4",
        "mp3" => "audio/mpeg", "txt" => "text/plain", "md" => "text/markdown",
        _ => "application/octet-stream",
    }.to_string()
}

// Keep AAD constant referenced (documents intent; folded into future framing).
#[allow(dead_code)]
fn _aad() -> &'static str { AAD_SALT }
