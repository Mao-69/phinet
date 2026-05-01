// phinet-browser/src-tauri/src/proxy.rs
//! Embedded SOCKS5 proxy — routes .phinet traffic through local store or daemon.

use phinet_core::store::SiteStore;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::debug;

const PHINET_TLD: &str = ".phinet";
const HS_ID_LEN:  usize = 40;

pub async fn run_proxy(host: &str, port: u16, store: Arc<SiteStore>) {
    let addr     = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr).await.expect("proxy bind");
    tracing::info!("SOCKS5 proxy on {}", addr);
    loop {
        let Ok((conn, _)) = listener.accept().await else { continue };
        let store = store.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(conn, store).await {
                debug!("proxy: {}", e);
            }
        });
    }
}

async fn handle_socks5(mut conn: TcpStream, store: Arc<SiteStore>) -> anyhow::Result<()> {
    // Greeting
    let mut buf = [0u8; 2];
    conn.read_exact(&mut buf).await?;
    if buf[0] != 5 { anyhow::bail!("not socks5"); }
    let n = buf[1] as usize;
    let mut methods = vec![0u8; n];
    conn.read_exact(&mut methods).await?;
    conn.write_all(&[5u8, 0u8]).await?; // no-auth

    // Request header
    let mut hdr = [0u8; 4];
    conn.read_exact(&mut hdr).await?;
    let cmd  = hdr[1];
    let atyp = hdr[3];

    let host = match atyp {
        1 => {
            let mut a = [0u8; 4];
            conn.read_exact(&mut a).await?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        3 => {
            let mut ln = [0u8; 1];
            conn.read_exact(&mut ln).await?;
            let mut d = vec![0u8; ln[0] as usize];
            conn.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            conn.read_exact(&mut a).await?;
            format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([a[0],a[1]]),
                u16::from_be_bytes([a[2],a[3]]),
                u16::from_be_bytes([a[4],a[5]]),
                u16::from_be_bytes([a[6],a[7]]),
                u16::from_be_bytes([a[8],a[9]]),
                u16::from_be_bytes([a[10],a[11]]),
                u16::from_be_bytes([a[12],a[13]]),
                u16::from_be_bytes([a[14],a[15]]))
        }
        _ => anyhow::bail!("unsupported atyp {}", atyp),
    };

    let mut port_buf = [0u8; 2];
    conn.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    if cmd != 1 {
        conn.write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00").await?;
        anyhow::bail!("unsupported cmd {}", cmd);
    }

    if host.to_lowercase().ends_with(PHINET_TLD) {
        let hs_id = host[..host.len() - PHINET_TLD.len()].to_lowercase();
        conn.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00").await?;
        serve_phinet(conn, hs_id, host, store).await?;
    } else {
        match TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(remote) => {
                conn.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00").await?;
                relay(conn, remote).await;
            }
            Err(_) => {
                conn.write_all(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00").await?;
            }
        }
    }
    Ok(())
}

async fn serve_phinet(
    mut conn: TcpStream,
    hs_id:   String,
    host:    String,
    store:   Arc<SiteStore>,
) -> anyhow::Result<()> {
    conn.set_nodelay(true)?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 { break; }
        raw.extend_from_slice(&buf[..n]);
        if raw.windows(4).any(|w| w == b"\r\n\r\n") { break; }
        if raw.len() > 2_000_000 { anyhow::bail!("request too large"); }
    }

    let hdr_text  = String::from_utf8_lossy(&raw);
    let path      = hdr_text.lines().next().unwrap_or("GET / HTTP/1.1")
        .split_whitespace().nth(1).unwrap_or("/");
    let path      = path.split('?').next().unwrap_or("/");

    if hs_id.len() != HS_ID_LEN || !hs_id.chars().all(|c| c.is_ascii_hexdigit()) {
        send_http(&mut conn, 400, "text/html", b"<h1>Invalid .phinet address</h1>").await?;
        return Ok(());
    }

    // Try daemon first, fall back to local store
    if let Some(resp) = try_daemon_fetch(&hs_id, path).await {
        let status = resp["status"].as_u64().unwrap_or(200) as u16;
        let ct     = resp["headers"]["Content-Type"].as_str()
            .unwrap_or("text/html; charset=utf-8").to_string();
        let body   = resp["body_b64"].as_str()
            .and_then(|s| hex::decode(s).ok())
            .unwrap_or_default();
        let body = if ct.contains("text/html") { inject_bar(body, &host, true) } else { body };
        send_http(&mut conn, status, &ct, &body).await?;
        return Ok(());
    }

    if let Some((status, ct, body)) = store.get_file(&hs_id, path).await {
        let body = if ct.contains("text/html") { inject_bar(body, &host, false) } else { body };
        send_http(&mut conn, status, &ct, &body).await?;
        return Ok(());
    }

    send_http(&mut conn, 404, "text/html; charset=utf-8", &not_found_html(&hs_id)).await?;
    Ok(())
}

async fn try_daemon_fetch(hs_id: &str, path: &str) -> Option<serde_json::Value> {
    use tokio::io::AsyncBufReadExt;
    let stream = TcpStream::connect("127.0.0.1:7799").await.ok()?;
    let (reader, mut writer) = stream.into_split();
    let req = serde_json::json!({"cmd":"hs_fetch","hs_id":hs_id,"path":path,"method":"GET"});
    let mut line = req.to_string();
    line.push('\n');
    writer.write_all(line.as_bytes()).await.ok()?;
    writer.flush().await.ok()?;
    let mut lines = tokio::io::BufReader::new(reader).lines();
    let resp = lines.next_line().await.ok()??;
    serde_json::from_str(&resp).ok()
}

async fn send_http(conn: &mut TcpStream, status: u16, ct: &str, body: &[u8]) -> anyhow::Result<()> {
    let reason = match status { 200 => "OK", 404 => "Not Found", 400 => "Bad Request", _ => "Error" };
    let hdr = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ct}\r\n\
         Content-Length: {}\r\nConnection: close\r\nX-PHINET: 1\r\n\r\n",
        body.len()
    );
    conn.write_all(hdr.as_bytes()).await?;
    conn.write_all(body).await?;
    Ok(())
}

fn inject_bar(mut html: Vec<u8>, host: &str, live: bool) -> Vec<u8> {
    // Floating indicator at the bottom of every .phinet page so the
    // user always knows they're on the overlay network. Uses the
    // same teal accent (--phi: #39c5cf) as the main UI for visual
    // continuity. Designed to stay out of the way: low opacity,
    // pointer-events:none so clicks pass through to page content,
    // small fixed footer height.
    let mode_label = if live { "live · onion-routed" } else { "local · cached" };
    let dot_color  = if live { "#3fb950" } else { "#7d8590" };
    let bar = [
        "<div style=\"position:fixed;bottom:0;left:0;right:0;z-index:2147483647;",
        "background:rgba(13,17,23,.95);border-top:1px solid #30363d;",
        "backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);",
        "display:flex;align-items:center;gap:10px;padding:6px 16px;",
        "font-family:'Inter',-apple-system,system-ui,sans-serif;",
        "font-size:11px;color:#7d8590;pointer-events:none;\">",
        "<svg width=\"14\" height=\"14\" viewBox=\"0 0 14 14\" fill=\"none\">",
        "<polygon points=\"7,1 12,4 12,10 7,13 2,10 2,4\" stroke=\"#39c5cf\" stroke-width=\"1.2\" fill=\"none\"/>",
        "<circle cx=\"7\" cy=\"7\" r=\"2\" fill=\"#39c5cf\"/></svg>",
    ].concat();
    let bar2 = format!(
        "<span style=\"color:#39c5cf;font-weight:600;letter-spacing:.02em;\">ΦNET</span>\
         <span style=\"color:#30363d;\">|</span>\
         <span style=\"color:#c9d1d9;font-family:'JetBrains Mono',monospace;font-size:10px;\">{host}</span>\
         <span style=\"display:inline-block;width:6px;height:6px;border-radius:50%;\
         background:{dot_color};margin-left:auto;box-shadow:0 0 4px {dot_color};\"></span>\
         <span style=\"color:#7d8590;font-size:10px;\">{mode_label}</span>\
         </div><div style=\"height:30px\"></div>"
    );
    let full_bar = [bar.as_bytes(), bar2.as_bytes()].concat();

    for tag in [b"<body" as &[u8], b"<BODY"] {
        if let Some(pos) = html.windows(tag.len()).position(|w| w == tag) {
            if let Some(end) = html[pos..].iter().position(|&b| b == b'>') {
                let insert_at = pos + end + 1;
                html.splice(insert_at..insert_at, full_bar);
                return html;
            }
        }
    }
    let mut out = full_bar;
    out.extend_from_slice(&html);
    out
}

fn not_found_html(hs_id: &str) -> Vec<u8> {
    format!(
        "<html><head><meta charset=\"utf-8\"><title>404 — Not Found</title>\
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
         border-radius:6px;padding:6px 12px;color:#58a6ff;\
         display:inline-block;margin-top:.5rem;word-break:break-all}}\
         .help{{color:#7d8590;font-size:.85rem;margin-top:2rem;\
         border-top:1px solid #21262d;padding-top:1rem;line-height:1.8}}\
         </style></head><body>\
         <div class=\"icon\">🔍</div>\
         <h1>Hidden service not found</h1>\
         <p>No service is currently registered at:</p>\
         <code>{hs_id}.phinet</code>\
         <p class=\"help\">The service may not be deployed, or your daemon may not have \
         received its descriptor yet. Try again in a moment, or verify the address.</p>\
         </body></html>"
    ).into_bytes()
}

async fn relay(a: TcpStream, b: TcpStream) {
    let (mut ar, mut aw) = a.into_split();
    let (mut br, mut bw) = b.into_split();
    let t1 = tokio::spawn(async move { tokio::io::copy(&mut ar, &mut bw).await });
    let t2 = tokio::spawn(async move { tokio::io::copy(&mut br, &mut aw).await });
    let _ = tokio::join!(t1, t2);
}
