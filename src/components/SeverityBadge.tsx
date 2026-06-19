// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/components/SeverityBadge.tsx — SDD komponen inti.
import React from "react";
import { normalizeSeverity, type Severity } from "../lib/parser";

const STYLES: Record<Severity, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-black",
  low: "bg-severity-low text-white",
  info: "bg-severity-info text-white",
};

export const SeverityBadge: React.FC<{ severity?: string }> = ({ severity }) => {
  const s = normalizeSeverity(severity);
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${STYLES[s]}`}>
      {s}
    </span>
  );
};
