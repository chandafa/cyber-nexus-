// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/components/ScanConsole.tsx
// Menampilkan output scan dari store global (scanRuntime). Buffer terminal
// bertahan lintas-navigasi: saat komponen mount ulang, buffer diputar ulang.
import React, { forwardRef, useEffect, useImperativeHandle, useRef, useState } from "react";
import { Terminal, type TerminalHandle } from "./Terminal";
import { StatusBadge } from "./StatusBadge";
import { Ic } from "../lib/icons";
import { useScanRuntimeStore } from "../app/store/scanRuntime.store";

export interface ScanConsoleHandle {
  start: (opts: {
    command: string;
    args: string[];
    module?: string;
    target?: string;
    mode?: string;
  }) => Promise<void>;
}

interface Props {
  module: string;
}

export const ScanConsole = forwardRef<ScanConsoleHandle, Props>(({ module }, ref) => {
  const termRef = useRef<TerminalHandle>(null);
  const [termReady, setTermReady] = useState(false);
  const writtenRef = useRef(0);

  const scan = useScanRuntimeStore((s) => s.scans[module]);
  const startScan = useScanRuntimeStore((s) => s.start);
  const stopScan = useScanRuntimeStore((s) => s.stop);
  const clearTerminal = useScanRuntimeStore((s) => s.clearTerminal);
  const getBuffer = useScanRuntimeStore((s) => s.getBuffer);

  useImperativeHandle(
    ref,
    () => ({
      start: ({ command, args, target, mode }) =>
        startScan({ module, command, args, target, mode }),
    }),
    [module, startScan]
  );

  // Reset penghitung saat ganti module (komponen dipakai ulang antar route).
  useEffect(() => {
    writtenRef.current = 0;
  }, [module]);

  // Putar ulang buffer ke terminal: saat mount, dan setiap ada baris baru.
  useEffect(() => {
    if (!termReady) return;
    const term = termRef.current;
    if (!term) return;
    const buf = getBuffer(module);
    if (buf.length < writtenRef.current) {
      term.clear();
      writtenRef.current = 0;
    }
    if (writtenRef.current === 0 && buf.length > 0) term.clear(); // hapus greeting saat replay
    for (let i = writtenRef.current; i < buf.length; i++) term.write(buf[i]);
    writtenRef.current = buf.length;
  }, [scan?.tick, termReady, module, getBuffer]);

  const status = scan?.status ?? "idle";
  const running = scan?.running ?? false;
  const progress = scan?.progress ?? null;

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b border-nexus-hairline bg-nexus-panel/60 px-3.5 py-2.5">
        <div className="flex items-center gap-2 text-sm text-nexus-muted">
          <Ic.terminal className="h-4 w-4" /> Output
          <StatusBadge status={status} />
        </div>
        <div className="flex items-center gap-2">
          {progress !== null && (
            <div className="flex items-center gap-2">
              <div className="h-1.5 w-28 overflow-hidden rounded-full bg-nexus-border">
                <div className="h-full bg-nexus-accent transition-all" style={{ width: `${progress}%` }} />
              </div>
              <span className="text-xs text-nexus-muted">{Math.round(progress)}%</span>
            </div>
          )}
          <button
            className="nx-btn-ghost px-2.5 py-1.5 text-xs"
            onClick={() => clearTerminal(module)}
            disabled={running}
            title="Bersihkan terminal"
          >
            <Ic.trash className="h-3.5 w-3.5" />
          </button>
          <button
            className="nx-btn-danger px-2.5 py-1.5 text-xs"
            onClick={() => stopScan(module)}
            disabled={!running}
          >
            <Ic.stop className="h-3.5 w-3.5" /> Stop
          </button>
        </div>
      </div>
      <div className="min-h-0 flex-1 bg-nexus-bg p-2">
        <Terminal ref={termRef} onReady={() => setTermReady(true)} />
      </div>
    </div>
  );
});

ScanConsole.displayName = "ScanConsole";
