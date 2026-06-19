// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/components/Toast.tsx — notifikasi ringan (bottom-right).
import React from "react";
import { Ic } from "../lib/icons";
import { useToastStore } from "../app/store/toast.store";

const KIND_CLS: Record<string, string> = {
  success: "border-nexus-green/40",
  error: "border-severity-critical/50",
  info: "border-nexus-border",
};

export const ToastHost: React.FC = () => {
  const toasts = useToastStore((s) => s.toasts);
  const dismiss = useToastStore((s) => s.dismiss);

  if (!toasts.length) return null;
  return (
    <div className="fixed bottom-4 right-4 z-[200] flex flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`flex items-center gap-3 border ${KIND_CLS[t.kind]} bg-nexus-panel px-3.5 py-2.5 shadow-menu animate-fade-in`}
        >
          {t.kind === "success" && <Ic.check className="h-4 w-4 shrink-0 text-nexus-green" />}
          {t.kind === "error" && <Ic.close className="h-4 w-4 shrink-0 text-severity-critical" />}
          {t.kind === "info" && <Ic.info className="h-4 w-4 shrink-0 text-nexus-muted" />}
          <span className="max-w-[320px] break-all text-xs text-nexus-text">{t.message}</span>
          {t.action && (
            <button
              className="nx-btn-ghost px-2 py-1 text-[11px]"
              onClick={() => {
                t.action!();
                dismiss(t.id);
              }}
            >
              {t.actionLabel || "Aksi"}
            </button>
          )}
          <button className="text-nexus-subtle hover:text-nexus-text" onClick={() => dismiss(t.id)}>
            <Ic.close className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
};
