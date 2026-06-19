// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/components/StatusBadge.tsx — SDD bagian 9.2.
import React from "react";

const MAP: Record<string, string> = {
  running: "bg-nexus-accent2/20 text-nexus-accent2 border-nexus-accent2/40",
  completed: "bg-severity-low/20 text-blue-300 border-blue-500/40",
  failed: "bg-severity-critical/20 text-red-300 border-red-500/40",
  stopped: "bg-severity-medium/20 text-yellow-300 border-yellow-500/40",
  installed: "bg-green-500/20 text-green-300 border-green-500/40",
  missing: "bg-severity-critical/20 text-red-300 border-red-500/40",
  optional: "bg-severity-medium/20 text-yellow-300 border-yellow-500/40",
};

export const StatusBadge: React.FC<{ status: string; label?: string }> = ({ status, label }) => {
  const cls = MAP[status] || "bg-nexus-panel text-nexus-muted border-nexus-border";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${cls}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {label || status}
    </span>
  );
};
