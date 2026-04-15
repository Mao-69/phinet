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
    // Normalise .phinet addresses
    const hs = url.replace(/\.phinet$/, "");
    if (/^[0-9a-fA-F]{40}$/i.test(hs)) {
      url = `http://${hs.toLowerCase()}.phinet/`;
    } else if (url.startsWith("about:")) {
      // keep as-is
    } else if (!/^[a-z]+:\/\//i.test(url)) {
      url = url.includes(".") && !url.includes(" ")
        ? `http://${url}`
        : `about:home`;
    }
    onNavigate(url);
    setEditing(false);
    inputRef.current?.blur();
  };

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter")  navigate();
    if (e.key === "Escape") { setEditing(false); setDraft(value); inputRef.current?.blur(); }
  };

  const iconLabel = isPhinet ? "⬡" : "●";
  const iconClass = isPhinet ? "phinet" : "clearnet";

  // Display: strip "about:home" → empty placeholder
  const displayVal = !editing && value === "about:home" ? "" : draft;

  return (
    <div className="addr-bar-wrap">
      <span className={`addr-icon ${iconClass}`}>{iconLabel}</span>

      <input
        ref={inputRef}
        className={`addr-bar${isPhinet ? " is-phinet" : ""}`}
        type="text"
        spellCheck={false}
        autoComplete="off"
        placeholder="Enter .phinet address or URL…"
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
