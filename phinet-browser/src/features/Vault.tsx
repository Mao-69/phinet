import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { open as openPath } from "@tauri-apps/plugin-shell";

type Item = {
  id: string; kind: string; title: string; content: string;
  file_name: string; mime: string; size: number;
};

const icon = (k: string) => (k === "link" ? "🔗" : k === "note" ? "📝" : k === "file" ? "📎" : "🔑");

export default function Vault() {
  const [status, setStatus] = useState<{ exists: boolean; unlocked: boolean }>({ exists: false, unlocked: false });
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [items, setItems] = useState<Item[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [toast, setToast] = useState("");

  const refresh = async () => {
    const s: any = await invoke("vault_status");
    setStatus({ exists: !!s.exists, unlocked: !!s.unlocked });
    if (s.unlocked) { const r: any = await invoke("vault_list"); if (r?.ok) setItems(r.items); }
  };
  useEffect(() => { refresh(); }, []);
  useEffect(() => { if (toast) { const t = setTimeout(() => setToast(""), 2200); return () => clearTimeout(t); } }, [toast]);

  const unlock = async () => {
    if (pass.length < 6) { setErr("Use at least 6 characters"); return; }
    setBusy(true); setErr("");
    const cmd = status.exists ? "vault_unlock" : "vault_create";
    const r: any = await invoke(cmd, { passphrase: pass });
    setBusy(false);
    if (r?.ok) { setPass(""); await refresh(); }
    else setErr(r?.error ?? "failed");
  };

  const importFile = async () => {
    const sel = await openDialog({ multiple: false });
    if (!sel || Array.isArray(sel)) return;
    const r: any = await invoke("vault_import", { path: sel });
    if (r?.ok) setItems(r.items); else setToast(r?.error ?? "import failed");
  };

  const reveal = async (it: Item) => {
    const r: any = await invoke("vault_reveal", { id: it.id });
    if (r?.ok) { try { await openPath(r.path); } catch { setToast("Saved to: " + r.path); } }
    else setToast(r?.error ?? "couldn't open");
  };

  const del = async (id: string) => {
    const r: any = await invoke("vault_delete", { id });
    if (r?.ok) setItems(r.items);
  };

  if (!status.unlocked) {
    return (
      <div className="vault-gate">
        <div className="vg-lock">🔒</div>
        <h2>{status.exists ? "Unlock your vault" : "Create your vault"}</h2>
        <p className="foot">Encrypted with XChaCha20-Poly1305; the key is derived from your passphrase (Argon2id) and never leaves this device.</p>
        <input type="password" value={pass} placeholder="Passphrase"
          onChange={(e) => setPass(e.target.value)} onKeyDown={(e) => e.key === "Enter" && unlock()} />
        {err && <div className="berr">{err}</div>}
        <button className="newbtn wide" disabled={busy} onClick={unlock}>
          {busy ? "Working…" : status.exists ? "Unlock" : "Create vault"}
        </button>
      </div>
    );
  }

  return (
    <div className="vault">
      <div className="vault-top">
        <div className="vname">Vault</div>
        <div className="vactions">
          <button className="newbtn" style={{ margin: 0 }} onClick={importFile}>⬆ Import file</button>
          <button className="newbtn" style={{ margin: 0 }} onClick={() => setShowAdd(true)}>+ Add</button>
          <button className="iconbtn" title="Lock" onClick={async () => { await invoke("vault_lock"); refresh(); }}>🔒</button>
        </div>
      </div>
      {items.length === 0 ? (
        <div className="empty">Your vault is empty. Add links, notes, secrets, or import a file.</div>
      ) : (
        <div className="vlist">
          {items.map((it) => (
            <div key={it.id} className="vcard">
              <div className="vic">{icon(it.kind)}</div>
              <div className="vmeta" onClick={() => it.kind === "file" && reveal(it)} style={{ cursor: it.kind === "file" ? "pointer" : "default" }}>
                <div className="vtitle">{it.title || "(untitled)"}</div>
                <div className="vsub">{it.kind === "secret" ? "••••••••" : it.kind === "file" ? `${it.mime} · ${(it.size / 1024).toFixed(0)} KB` : it.content}</div>
              </div>
              <button className="iconbtn" title="Delete" onClick={() => del(it.id)}>🗑</button>
            </div>
          ))}
        </div>
      )}
      {showAdd && <AddSheet onClose={() => setShowAdd(false)} onAdded={(list) => { setItems(list); setShowAdd(false); }} />}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function AddSheet({ onClose, onAdded }: { onClose: () => void; onAdded: (l: Item[]) => void }) {
  const [kind, setKind] = useState("link");
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const save = async () => {
    if (!content.trim()) return;
    const r: any = await invoke("vault_add", { kind, title, content });
    if (r?.ok) onAdded(r.items);
  };
  return (
    <div className="modal" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="card">
        <h3>Add to vault</h3>
        <div className="seg">
          {["link", "note", "secret"].map((k) => (
            <button key={k} className={kind === k ? "on" : ""} onClick={() => setKind(k)}>
              {k[0].toUpperCase() + k.slice(1)}
            </button>
          ))}
        </div>
        <input placeholder="Title" value={title} onChange={(e) => setTitle(e.target.value)} />
        <input placeholder={kind === "link" ? "URL" : kind === "note" ? "Note" : "Secret"}
          value={content} onChange={(e) => setContent(e.target.value)} onKeyDown={(e) => e.key === "Enter" && save()} />
        <button className="newbtn wide" onClick={save}>Save</button>
      </div>
    </div>
  );
}
