// phinet-browser/src/components/SiteManager.tsx
import React, { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ── Types ─────────────────────────────────────────────────────────────

interface ServiceInfo {
  hs_id:   string;
  name:    string;
  address: string;
  files:   string[];
  created: number;
}

interface Props {
  onClose:    () => void;
  onNavigate: (url: string) => void;
}

// ── Component ─────────────────────────────────────────────────────────

export function SiteManager({ onClose, onNavigate }: Props) {
  const [services,  setServices]  = useState<ServiceInfo[]>([]);
  const [selected,  setSelected]  = useState<string | null>(null);
  const [status,    setStatus]    = useState<{msg: string; ok: boolean} | null>(null);
  const [newName,   setNewName]   = useState("");
  const [creating,  setCreating]  = useState(false);

  const selectedSvc = services.find(s => s.hs_id === selected) ?? null;

  const load = useCallback(async () => {
    try {
      const svcs = await invoke<ServiceInfo[]>("list_services");
      setServices(svcs);
    } catch (e) {
      setStatus({ msg: String(e), ok: false });
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const setOk  = (msg: string) => setStatus({ msg, ok: true  });
  const setErr = (msg: string) => setStatus({ msg, ok: false });

  // ── CRUD ──────────────────────────────────────────────────────────

  const createService = async () => {
    const n = newName.trim();
    if (!n) return;
    try {
      const svc = await invoke<ServiceInfo>("create_service", { name: n });
      setNewName("");
      setCreating(false);
      await load();
      setSelected(svc.hs_id);
      setOk(`Created: ${svc.hs_id.slice(0, 12)}….phinet`);
    } catch (e) { setErr(String(e)); }
  };

  const deleteService = async () => {
    if (!selected) return;
    const svc = services.find(s => s.hs_id === selected);
    if (!window.confirm(`Delete "${svc?.name}"?`)) return;
    try {
      await invoke("delete_service", { hsId: selected });
      setSelected(null);
      await load();
      setOk("Deleted.");
    } catch (e) { setErr(String(e)); }
  };

  const uploadFolder = async () => {
    if (!selected) return;
    try {
      const dir = await open({ directory: true, multiple: false });
      if (!dir || typeof dir !== "string") return;
      // Read files and upload each
      setOk("Uploading…");
      // In production: read each file and call upload_file for each
      // For now: signal the deployment intent
      setOk("Deploy using:  phi deploy " + selected.slice(0, 12) + " " + dir);
    } catch (e) { setErr(String(e)); }
  };

  const uploadFile = async () => {
    if (!selected) return;
    try {
      const path = await open({ multiple: false });
      if (!path || typeof path !== "string") return;
      const name = path.split(/[\\/]/).pop() ?? "file";
      // Tauri FS plugin would read the file; for now show instructions
      setOk(`Use CLI:  phi put ${selected.slice(0,12)} /${name} ${path}`);
    } catch (e) { setErr(String(e)); }
  };

  const registerService = async () => {
    if (!selected || !selectedSvc) return;
    try {
      const r = await invoke<any>("register_service", { hsId: selected, name: selectedSvc.name });
      if (r?.ok) setOk("Registered on live network");
      else       setErr(r?.error ?? "Failed");
    } catch (e) { setErr("Daemon offline — start phinet-daemon"); }
  };

  const visitService = () => {
    if (!selected) return;
    onNavigate(`http://${selected}.phinet/`);
  };

  const copyAddress = () => {
    if (!selected) return;
    navigator.clipboard.writeText(`${selected}.phinet`)
      .then(() => setOk("Address copied"))
      .catch(() => setErr("Could not copy"));
  };

  // ── Render ────────────────────────────────────────────────────────

  return (
    <div className="overlay-backdrop" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="panel site-manager">

        {/* Header */}
        <div className="panel-header">
          <span className="panel-title">⬡  Site Manager</span>
          <button className="panel-close" onClick={onClose}>×</button>
        </div>

        <div className="site-manager-body">

          {/* Sidebar: service list */}
          <div className="sm-sidebar">
            <div className="sm-sidebar-label">Hidden Services</div>

            <div className="sm-service-list">
              {services.length === 0 && (
                <div className="empty-state" style={{ padding: "20px 8px", fontSize: 11 }}>
                  <span className="empty-icon">⬡</span>
                  No services yet
                </div>
              )}
              {services.map(svc => (
                <div
                  key={svc.hs_id}
                  className={`sm-service-item${svc.hs_id === selected ? " selected" : ""}`}
                  onClick={() => setSelected(svc.hs_id)}
                >
                  <div className="sm-service-name">⬡ {svc.name}</div>
                  <div className="sm-service-id">
                    {svc.hs_id.slice(0, 12)}…{svc.hs_id.slice(-4)}
                  </div>
                </div>
              ))}
            </div>

            {/* Create new */}
            {creating ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <input
                  type="text"
                  placeholder="Service name"
                  value={newName}
                  autoFocus
                  onChange={e => setNewName(e.target.value)}
                  onKeyDown={e => { if (e.key === "Enter") createService(); if (e.key === "Escape") setCreating(false); }}
                  style={{ fontSize: 11 }}
                />
                <div style={{ display: "flex", gap: 4 }}>
                  <button className="primary" style={{ flex: 1, fontSize: 11 }} onClick={createService}>Create</button>
                  <button style={{ fontSize: 11 }} onClick={() => setCreating(false)}>Cancel</button>
                </div>
              </div>
            ) : (
              <div className="sm-sidebar-actions">
                <button className="primary" onClick={() => setCreating(true)}>+ New</button>
                <button className="danger" onClick={deleteService} disabled={!selected}>Delete</button>
              </div>
            )}
          </div>

          {/* Main: file list */}
          <div className="sm-main">
            {selectedSvc ? (
              <>
                <div className="sm-file-header">
                  <strong>{selectedSvc.name}</strong>
                  {"  "}
                  <span className="dimmed">{selectedSvc.hs_id.slice(0,16)}….phinet</span>
                </div>

                {/* File table */}
                <div className="sm-file-table">
                  {selectedSvc.files.length === 0 ? (
                    <div className="empty-state" style={{ padding: "24px" }}>
                      <span className="empty-icon">📄</span>
                      No files deployed yet.<br />
                      <small className="dimmed">Use "↑ Upload" or the CLI.</small>
                    </div>
                  ) : (
                    <>
                      <div className="sm-file-table-header">
                        <span>Path</span><span>Type</span><span style={{ textAlign: "right" }}>Size</span>
                      </div>
                      {selectedSvc.files.map(f => (
                        <div key={f} className="sm-file-row">
                          <span className="sm-file-path">{f}</span>
                          <span className="sm-file-mime">{guessType(f)}</span>
                          <span className="sm-file-size">—</span>
                        </div>
                      ))}
                    </>
                  )}
                </div>

                {/* Actions */}
                <div className="sm-actions">
                  <button onClick={uploadFile}>↑ File</button>
                  <button onClick={uploadFolder}>↑ Folder</button>
                  <button onClick={registerService}>⊞ Register</button>
                  <button onClick={copyAddress}>⎘ Copy addr</button>
                  <button className="primary" onClick={visitService}>→ Visit</button>
                </div>

                {/* CLI hint */}
                <div style={{ fontSize: 10, color: "var(--mt)", paddingTop: 4 }}>
                  CLI: <code>phi deploy {selectedSvc.hs_id.slice(0,12)} ./site/</code>
                </div>
              </>
            ) : (
              <div className="empty-state">
                <span className="empty-icon">⬡</span>
                Select a service to manage its files
              </div>
            )}

            {/* Status */}
            {status && (
              <div className={`sm-status ${status.ok ? "ok" : "err"}`}>
                {status.ok ? "✓" : "✗"}  {status.msg}
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  );
}

function guessType(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    html: "text/html", htm: "text/html",
    css:  "text/css",  js: "javascript",
    json: "json",      svg: "svg",
    png:  "image/png", jpg: "image/jpeg",
    gif:  "image/gif", webp: "image/webp",
    txt:  "text/plain",
  };
  return map[ext] ?? "—";
}
