// phinet-browser/src/components/TabBar.tsx
import React from "react";
import { Tab } from "../App";

interface Props {
  tabs:      Tab[];
  activeTab: string | null;
  onSelect:  (id: string) => void;
  onClose:   (id: string) => void;
  onNewTab:  () => void;
}

export function TabBar({ tabs, activeTab, onSelect, onClose, onNewTab }: Props) {
  return (
    <div className="tab-bar">
      {tabs.map(tab => (
        <div
          key={tab.id}
          className={`tab${tab.id === activeTab ? " active" : ""}`}
          onClick={() => onSelect(tab.id)}
          title={tab.url}
        >
          <span className="tab-favicon">
            {tab.loading ? "⌛" : tab.isPhinet ? "⬡" : "●"}
          </span>
          <span className="tab-title">
            {tab.title === "New Tab" ? "New Tab" : tab.title}
          </span>
          <button
            className="tab-close"
            title="Close tab"
            onClick={e => { e.stopPropagation(); onClose(tab.id); }}
          >×</button>
        </div>
      ))}

      <button
        className="tab-new-btn"
        title="New tab  (Ctrl+T)"
        onClick={onNewTab}
      >+</button>
    </div>
  );
}
