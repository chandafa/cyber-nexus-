// src/components/DependencyCard.tsx — SDD §9.2 / §3.4.
// Status terbaca jelas; tombol Install per-tool dengan elevasi otomatis.
import React from "react";
import { Ic } from "../lib/icons";
import type { ToolStatus } from "../lib/tauri";

interface Props {
  name: string;
  tool: ToolStatus;
  onInstall?: (name: string) => void;
  installing?: boolean;
}

export const DependencyCard: React.FC<Props> = ({ name, tool, onInstall, installing }) => {
  let icon: React.ReactNode;
  let dot: string;
  if (tool.installed) {
    icon = <Ic.check className="h-[18px] w-[18px] text-nexus-green" />;
    dot = "bg-nexus-green";
  } else if (tool.required) {
    icon = <Ic.close className="h-[18px] w-[18px] text-severity-critical" />;
    dot = "bg-severity-critical";
  } else {
    icon = <Ic.warning className="h-[18px] w-[18px] text-severity-medium" />;
    dot = "bg-severity-medium";
  }

  return (
    <div className="flex items-center gap-3 border border-nexus-hairline bg-nexus-surface px-3 py-2.5 transition-colors hover:border-nexus-border">
      <div className="shrink-0">{icon}</div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[12.5px] font-semibold text-nexus-text">{name}</span>
          {!tool.required && <span className="nx-chip">opsional</span>}
        </div>
        <p className="flex items-center gap-1.5 truncate text-[11px]">
          <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dot}`} />
          {tool.installed ? (
            <span className="truncate text-nexus-green">{tool.version || "terpasang"}</span>
          ) : (
            <span className="text-nexus-muted">
              belum terpasang{tool.min_ver ? ` · butuh v${tool.min_ver}+` : ""}
            </span>
          )}
        </p>
      </div>

      {!tool.installed && onInstall && (
        <button
          className="nx-btn-ghost shrink-0 px-2.5 py-1 text-[11px]"
          onClick={() => onInstall(name)}
          disabled={installing}
          title={`Install ${name}`}
        >
          {installing ? (
            <>
              <Ic.refresh className="h-3.5 w-3.5 animate-spin" /> Memasang…
            </>
          ) : (
            <>
              <Ic.install className="h-3.5 w-3.5" /> Install
            </>
          )}
        </button>
      )}
    </div>
  );
};
