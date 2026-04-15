// phinet-core/src/store.rs
//! Persistent site store at ~/.phinet/sites/

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

// ── Directories ───────────────────────────────────────────────────────

pub fn phinet_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".phinet")
}

pub fn sites_dir() -> PathBuf { phinet_dir().join("sites") }
pub fn identity_path() -> PathBuf { phinet_dir().join("identity.json") }

// ── Site metadata ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteMeta {
    pub name:      String,
    pub hs_id:     String,
    pub nonce_hex: String,
    pub created:   u64,
}

// ── Store ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SiteStore {
    root: PathBuf,
}

impl SiteStore {
    pub fn new() -> Self { Self { root: sites_dir() } }

    pub fn new_test() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir()
            .join(format!("phinet_test_{}", CTR.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&root).ok();
        Self { root }
    }

    fn site_dir(&self, hs_id: &str) -> PathBuf { self.root.join(hs_id) }
    fn meta_path(&self, hs_id: &str) -> PathBuf { self.site_dir(hs_id).join("_meta.json") }
    fn www_dir(&self,  hs_id: &str) -> PathBuf { self.site_dir(hs_id).join("www") }

    // ── Writes ────────────────────────────────────────────────────────

    pub async fn create_service(&self, hs_id: &str, name: &str, nonce_hex: &str) -> Result<SiteMeta> {
        fs::create_dir_all(self.www_dir(hs_id)).await?;
        let meta = SiteMeta {
            name:      name.to_string(),
            hs_id:     hs_id.to_string(),
            nonce_hex: nonce_hex.to_string(),
            created:   unix_now(),
        };
        fs::write(self.meta_path(hs_id), serde_json::to_string_pretty(&meta)?).await?;
        fs::write(self.www_dir(hs_id).join("index.html"), default_index_html(name, hs_id)).await?;
        Ok(meta)
    }

    pub async fn put_file(&self, hs_id: &str, url_path: &str, body: &[u8]) -> Result<()> {
        if !self.site_dir(hs_id).exists() {
            return Err(Error::NotFound(format!("service {}", hs_id)));
        }
        let dest = self.resolve(hs_id, url_path);
        if let Some(p) = dest.parent() { fs::create_dir_all(p).await?; }
        fs::write(dest, body).await?;
        Ok(())
    }

    pub async fn deploy_directory(&self, hs_id: &str, local: &std::path::Path) -> Result<Vec<String>> {
        let mut deployed = Vec::new();
        self.walk(hs_id, local, local, &mut deployed).await?;
        Ok(deployed)
    }

    fn walk<'a>(
        &'a self, hs_id: &'a str, base: &'a std::path::Path, dir: &'a std::path::Path,
        out: &'a mut Vec<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut rd = fs::read_dir(dir).await?;
            while let Some(e) = rd.next_entry().await? {
                let p = e.path();
                let n = p.file_name().unwrap_or_default().to_string_lossy();
                if n.starts_with('.') || n.ends_with(".pyc") { continue; }
                if p.is_dir() {
                    self.walk(hs_id, base, &p, out).await?;
                } else {
                    let rel = p.strip_prefix(base).unwrap_or(&p);
                    let url = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
                    let body = fs::read(&p).await?;
                    self.put_file(hs_id, &url, &body).await?;
                    out.push(url);
                }
            }
            Ok(())
        })
    }

    pub async fn delete_service(&self, hs_id: &str) -> Result<()> {
        let d = self.site_dir(hs_id);
        if d.exists() { fs::remove_dir_all(d).await?; }
        Ok(())
    }

    pub async fn delete_file(&self, hs_id: &str, url_path: &str) -> Result<()> {
        let p = self.resolve(hs_id, url_path);
        if p.exists() { fs::remove_file(p).await?; }
        Ok(())
    }

    // ── Reads ─────────────────────────────────────────────────────────

    /// Returns (status, content-type, body) or None if service unknown.
    pub async fn get_file(&self, hs_id: &str, url_path: &str) -> Option<(u16, String, Vec<u8>)> {
        if !self.site_dir(hs_id).exists() { return None; }
        let www = self.www_dir(hs_id);
        if !www.exists() {
            return Some((404, "text/html".into(), not_found_html(url_path)));
        }
        let clean = url_path.trim_end_matches('/');
        let clean = if clean.is_empty() { "/" } else { clean };
        let candidates = [
            www.join(clean.trim_start_matches('/')),
            www.join(format!("{}/index.html", clean.trim_start_matches('/'))),
            www.join(format!("{}.html", clean.trim_start_matches('/'))),
            www.join("index.html"),
        ];
        for c in &candidates {
            if c.is_file() {
                if let Ok(body) = fs::read(c).await {
                    return Some((200, guess_mime(c), body));
                }
            }
        }
        Some((404, "text/html; charset=utf-8".into(), not_found_html(url_path)))
    }

    pub async fn get_service(&self, hs_id: &str) -> Option<SiteMeta> {
        serde_json::from_str(&fs::read_to_string(self.meta_path(hs_id)).await.ok()?).ok()
    }

    pub async fn list_services(&self) -> Vec<SiteMeta> {
        let mut out = Vec::new();
        let Ok(mut rd) = fs::read_dir(&self.root).await else { return out };
        while let Ok(Some(e)) = rd.next_entry().await {
            let id = e.file_name().to_string_lossy().to_string();
            if let Some(m) = self.get_service(&id).await { out.push(m); }
        }
        out.sort_by(|a, b| b.created.cmp(&a.created));
        out
    }

    pub async fn list_files(&self, hs_id: &str) -> Vec<String> {
        let www   = self.www_dir(hs_id);
        let mut v = Vec::new();
        collect_files(&www, &www, &mut v).await;
        v
    }

    // ── Path resolution ───────────────────────────────────────────────

    fn resolve(&self, hs_id: &str, url_path: &str) -> PathBuf {
        let www = self.www_dir(hs_id);
        let rel = url_path.trim_start_matches('/');
        let rel = if rel.is_empty() { "index.html" } else { rel };
        let parts: Vec<&str> = rel.split('/')
            .filter(|p| !p.is_empty() && *p != "..").collect();
        let mut path = www;
        for part in parts { path = path.join(part); }
        path
    }
}

impl Default for SiteStore {
    fn default() -> Self { Self::new() }
}

// ── Recursive file collector ──────────────────────────────────────────

fn collect_files<'a>(
    base: &'a std::path::Path,
    dir:  &'a std::path::Path,
    out:  &'a mut Vec<String>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        let Ok(mut rd) = fs::read_dir(dir).await else { return };
        while let Ok(Some(e)) = rd.next_entry().await {
            let p = e.path();
            if p.is_file() {
                let rel = p.strip_prefix(base).unwrap_or(&p);
                out.push(format!("/{}", rel.to_string_lossy()));
            } else if p.is_dir() {
                collect_files(base, &p, out).await;
            }
        }
    })
}

// ── MIME detection ────────────────────────────────────────────────────

fn guess_mime(path: &std::path::Path) -> String {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html"|"htm" => "text/html; charset=utf-8",
        "css"        => "text/css; charset=utf-8",
        "js"|"mjs"   => "application/javascript",
        "json"       => "application/json",
        "svg"        => "image/svg+xml",
        "png"        => "image/png",
        "jpg"|"jpeg" => "image/jpeg",
        "gif"        => "image/gif",
        "webp"       => "image/webp",
        "woff"       => "font/woff",
        "woff2"      => "font/woff2",
        "ico"        => "image/x-icon",
        "txt"        => "text/plain; charset=utf-8",
        "wasm"       => "application/wasm",
        _            => "application/octet-stream",
    }.to_string()
}

// ── Built-in pages ────────────────────────────────────────────────────

pub fn default_index_html(name: &str, hs_id: &str) -> Vec<u8> {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{name}</title>
<style>
body{{font-family:monospace;background:#080812;color:#b8c8e0;
     max-width:660px;margin:60px auto;padding:2rem;line-height:1.7}}
h1{{color:#5a9cee;font-size:1.8rem;margin-bottom:.3rem}}
.addr{{background:#0e0e1c;border:1px solid #1e2040;border-radius:6px;
       padding:10px 14px;font-size:.85rem;color:#3a6cbe;
       word-break:break-all;margin:1.5rem 0}}
p{{color:#4a5878}}code{{background:#0e0e1c;padding:1px 6px;
border-radius:3px;color:#8ab4e8}}
</style>
</head>
<body>
<h1>⬡ {name}</h1>
<p>This hidden service is live on the ΦNET anonymous network.</p>
<div class="addr">{hs_id}.phinet</div>
<p>Deploy files:</p>
<p><code>phi deploy {hs_id} ./my-site/</code></p>
</body>
</html>"#).into_bytes()
}

pub fn not_found_html(path: &str) -> Vec<u8> {
    format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>404</title>
<style>body{{font-family:monospace;background:#080812;color:#b8c8e0;
max-width:560px;margin:60px auto;padding:2rem}}
h1{{color:#c04848}}p{{color:#4a5878}}
code{{background:#0e0e1c;padding:1px 5px;border-radius:3px}}</style>
</head>
<body><h1>404 — Not found</h1>
<p>The path <code>{path}</code> was not found on this hidden service.</p>
</body></html>"#).into_bytes()
}

/// Generate a complete starter site and return deployed URL paths.
pub async fn generate_starter_site(store: &SiteStore, hs_id: &str, name: &str) -> Result<Vec<String>> {
    let mut deployed = Vec::new();
    for (path, body) in starter_site_files(name, hs_id) {
        store.put_file(hs_id, path, body.as_bytes()).await?;
        deployed.push(path.to_string());
    }
    Ok(deployed)
}

fn starter_site_files(name: &str, hs_id: &str) -> Vec<(&'static str, String)> {
    let index = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{name}</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header><nav>
  <span class="logo">⬡ {name}</span>
  <div class="links"><a href="/">Home</a><a href="/about.html">About</a></div>
</nav></header>
<main>
  <section class="hero">
    <h1>{name}</h1>
    <p class="tagline">Anonymous · Encrypted · Decentralised</p>
    <div class="addr">{hs_id}.phinet</div>
  </section>
  <section>
    <h2>Welcome</h2>
    <p>This site is hosted anonymously on ΦNET. Your connection is onion-routed
    through 3 hops and end-to-end encrypted. No IP addresses are disclosed.</p>
  </section>
</main>
<footer><p>Hosted on ΦNET · no servers · no identity · no tracking</p></footer>
<script src="/app.js"></script>
</body>
</html>"#);

    let css = r#"*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#080812;--bg2:#0e0e1c;--bd:#1e2040;--tx:#b8c8e0;--mt:#4a5878;
      --ac:#3a6cbe;--a2:#5a9cee;--w:700px}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);
     color:var(--tx);line-height:1.7;min-height:100vh;display:flex;flex-direction:column}
a{color:var(--a2);text-decoration:none}a:hover{text-decoration:underline}
header{background:var(--bg2);border-bottom:1px solid var(--bd)}
nav{max-width:var(--w);margin:0 auto;padding:.8rem 2rem;display:flex;align-items:center;justify-content:space-between}
.logo{font-family:monospace;color:var(--ac);font-weight:700}
.links{display:flex;gap:1.5rem}.links a{color:var(--mt);font-size:.9rem}.links a:hover{color:var(--tx)}
main{flex:1;max-width:var(--w);margin:0 auto;padding:3rem 2rem;width:100%}
section{margin-bottom:2.5rem;padding:1.5rem;background:var(--bg2);border:1px solid var(--bd);border-radius:10px}
.hero{text-align:center;padding:2.5rem 1.5rem}
.hero h1{font-size:2rem;color:var(--a2);margin-bottom:.4rem}
.tagline{color:var(--mt);margin-bottom:1.2rem}
.addr{display:inline-block;font-family:monospace;font-size:.78rem;background:var(--bg);
      border:1px solid var(--bd);border-radius:6px;padding:6px 14px;color:var(--ac);word-break:break-all}
h2{color:var(--ac);font-size:1.15rem;margin-bottom:.8rem}
p{color:var(--mt);margin-bottom:.8rem}p:last-child{margin-bottom:0}
footer{text-align:center;padding:1.5rem;border-top:1px solid var(--bd);font-size:.8rem;color:var(--mt);font-family:monospace}"#;

    let js = r#"document.addEventListener("DOMContentLoaded",()=>{
  document.querySelectorAll("section").forEach((s,i)=>{
    s.style.cssText="opacity:0;transform:translateY(10px);transition:opacity .35s ease,transform .35s ease";
    setTimeout(()=>{s.style.opacity="1";s.style.transform="translateY(0)"},60*i);
  });
});"#;

    let about = format!(r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>About — {name}</title>
<link rel="stylesheet" href="/style.css"></head>
<body>
<header><nav><a href="/" class="logo">⬡ {name}</a>
<div class="links"><a href="/">Home</a><a href="/about.html">About</a></div></nav></header>
<main><section>
<h2>About</h2>
<p>Published anonymously on ΦNET. No accounts, no email, no tracking.</p>
</section></main>
<footer><p>Hosted on ΦNET</p></footer>
</body></html>"#);

    vec![
        ("/index.html", index),
        ("/about.html", about),
        ("/style.css",  css.to_string()),
        ("/app.js",     js.to_string()),
    ]
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_and_read() {
        let s = SiteStore::new_test();
        s.create_service("aaaa0000bbbb1111cccc", "test", "ff").await.unwrap();
        let m = s.get_service("aaaa0000bbbb1111cccc").await.unwrap();
        assert_eq!(m.name, "test");
    }

    #[tokio::test]
    async fn put_and_get_file() {
        let s = SiteStore::new_test();
        s.create_service("1111222233334444aaaa", "s", "00").await.unwrap();
        s.put_file("1111222233334444aaaa", "/hello.txt", b"world").await.unwrap();
        let (status, ct, body) = s.get_file("1111222233334444aaaa", "/hello.txt").await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"world");
        assert!(ct.contains("plain"));
    }

    #[tokio::test]
    async fn index_fallback() {
        let s = SiteStore::new_test();
        s.create_service("bbbb2222cccc3333dddd", "s", "00").await.unwrap();
        let (status, ct, body) = s.get_file("bbbb2222cccc3333dddd", "/").await.unwrap();
        assert_eq!(status, 200);
        assert!(ct.contains("html"));
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn unknown_service_none() {
        let s = SiteStore::new_test();
        assert!(s.get_file("0000000000000000dead", "/").await.is_none());
    }

    #[tokio::test]
    async fn path_traversal_blocked() {
        let s    = SiteStore::new_test();
        s.create_service("ffff0000aaaa1111bbbb", "s", "00").await.unwrap();
        let p    = s.resolve("ffff0000aaaa1111bbbb", "/../../../etc/passwd");
        let www  = s.www_dir("ffff0000aaaa1111bbbb");
        // Path must stay inside the www directory (no ../ escape above it)
        assert!(p.starts_with(&www), "resolved path escaped www_dir: {:?}", p);
    }

    #[tokio::test]
    async fn list_services() {
        let s = SiteStore::new_test();
        s.create_service("aaaa1111bbbb2222cccc", "a", "00").await.unwrap();
        s.create_service("bbbb2222cccc3333dddd", "b", "00").await.unwrap();
        assert_eq!(s.list_services().await.len(), 2);
    }
}
