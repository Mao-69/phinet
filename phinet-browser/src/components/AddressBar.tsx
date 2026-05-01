// phinet-browser/src/components/AddressBar.tsx
import React, { useState, useRef, useEffect, KeyboardEvent } from "react";

interface Props {
  value:      string;
  loading:    boolean;
  isPhinet:   boolean;
  onNavigate: (url: string) => void;
}

export function AddressBar({ value, loading, isPhinet, onNavigate }: Props) {
  const [editing, setEditing] = useState(false);
  const [draft,   setDraft]   = useState(value);
  const inputRef = useRef<HTMLInputElement>(null);

  // Sync displayed value when not editing
  useEffect(() => {
    if (!editing) setDraft(value);
  }, [value, editing]);

  const navigate = () => {
    let url = draft.trim();
    if (!url) return;

    // Normalize .phinet addresses. Accept both 64-hex (current Ed25519
    // identity-derived) and 40-hex (legacy BLAKE2b) forms.
    const hs = url.replace(/\.phinet$/, "");
    if (/^[0-9a-fA-F]{64}$/i.test(hs) || /^[0-9a-fA-F]{40}$/i.test(hs)) {
      url = `http://${hs.toLowerCase()}.phinet/`;
    } else if (url.startsWith("about:")) {
      // keep as-is
    } else if (!/^[a-z]+:\/\//i.test(url)) {
      // No scheme — decide whether this is a URL or a search query
      const looksLikeDomain = /^[\w-]+(\.[\w-]+)+(\/.*)?$/.test(url);
      if (looksLikeDomain) {
        // Default to https — modern web is HTTPS by default
        url = `https://${url}`;
      } else if (url.includes(" ") || !url.includes(".")) {
        // Search query
        url = `https://duckduckgo.com/?q=${encodeURIComponent(url)}`;
      } else {
        url = `https://${url}`;
      }
    }
    onNavigate(url);
    setEditing(false);
    inputRef.current?.blur();
  };

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter")  navigate();
    if (e.key === "Escape") { setEditing(false); setDraft(value); inputRef.current?.blur(); }
  };

  // Determine security indicator
  const isHttps = value.startsWith("https://");
  const isHttp  = value.startsWith("http://") && !isPhinet;
  let iconClass = "default";
  let iconLabel = "🔍";
  if (isPhinet) { iconClass = "phinet";   iconLabel = "⬡"; }
  else if (isHttps) { iconClass = "clearnet"; iconLabel = "🔒"; }
  else if (isHttp)  { iconClass = "http";     iconLabel = "⚠"; }

  // Display: strip "about:home" → empty placeholder
  const displayVal = !editing && value === "about:home" ? "" : draft;

  return (
    <div className="addr-bar-wrap">
      <span className={`addr-icon ${iconClass}`} title={
        isPhinet ? "Hidden service — onion-routed"
        : isHttps ? "Encrypted (HTTPS)"
        : isHttp  ? "Not encrypted (HTTP)"
        : "Search or enter address"
      }>{iconLabel}</span>

      <input
        ref={inputRef}
        className={`addr-bar${isPhinet ? " is-phinet" : ""}`}
        type="text"
        spellCheck={false}
        autoComplete="off"
        placeholder="Search the web or enter a .phinet address"
        value={displayVal}
        onChange={e => { setEditing(true); setDraft(e.target.value); }}
        onFocus={e => { setEditing(true); setTimeout(() => e.target.select(), 0); }}
        onBlur={() => { setEditing(false); setDraft(value); }}
        onKeyDown={onKey}
      />

      {loading && <span className="addr-spinner" />}
    </div>
  );
}
