// src/pages/Shell.tsx
// Terminal INTERAKTIF penuh — shell host sungguhan (PowerShell/bash) via PTY di
// backend Rust. Berbeda dari ScanConsole yang hanya menampilkan output scan:
// di sini pengguna bisa mengetik & menjalankan perintah apa pun.
import React, { useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import { v4 as uuidv4 } from "uuid";
import type { UnlistenFn } from "@tauri-apps/api/event";
import { Ic } from "../lib/icons";
import {
  isTauri,
  ptyOpen,
  ptyWrite,
  ptyResize,
  ptyClose,
  onPtyOutput,
  onPtyExit,
} from "../lib/tauri";

export const Shell: React.FC = () => {
  const hostRef = useRef<HTMLDivElement>(null);
  const [exited, setExited] = useState(false);
  const [sessionKey, setSessionKey] = useState(0); // untuk restart shell
  const idRef = useRef<string>("");

  useEffect(() => {
    if (!hostRef.current) return;
    setExited(false);

    const id = uuidv4();
    idRef.current = id;

    const term = new XTerm({
      theme: { background: "#0d0d1a", foreground: "#d8e0d8", cursor: "#a8d8a8" },
      fontSize: 13,
      fontFamily: "JetBrains Mono, Consolas, monospace",
      scrollback: 10000,
      cursorBlink: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    try {
      fit.fit();
    } catch {
      /* ignore */
    }

    if (!isTauri()) {
      term.writeln("\x1b[38;5;215mTerminal interaktif hanya tersedia di aplikasi desktop (Tauri).\x1b[0m");
      return () => term.dispose();
    }

    const unlisten: UnlistenFn[] = [];
    let disposed = false;

    (async () => {
      // Stream output shell → terminal.
      unlisten.push(await onPtyOutput(id, (data) => term.write(data)));
      unlisten.push(
        await onPtyExit(id, () => {
          if (disposed) return;
          term.writeln("\r\n\x1b[38;5;203m[sesi berakhir]\x1b[0m");
          setExited(true);
        })
      );
      try {
        await ptyOpen(id, term.cols, term.rows);
      } catch (e) {
        term.writeln(`\r\n\x1b[38;5;203m[gagal membuka shell] ${e}\x1b[0m`);
      }
    })();

    // Ketikan pengguna → stdin shell.
    const dataSub = term.onData((d) => {
      ptyWrite(id, d).catch(() => {});
    });

    // Resize → ikuti ukuran kontainer.
    const doFit = () => {
      try {
        fit.fit();
        ptyResize(id, term.cols, term.rows).catch(() => {});
      } catch {
        /* ignore */
      }
    };
    const observer = new ResizeObserver(doFit);
    observer.observe(hostRef.current);

    return () => {
      disposed = true;
      observer.disconnect();
      dataSub.dispose();
      unlisten.forEach((u) => u());
      ptyClose(id).catch(() => {});
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionKey]);

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-3.5 border-b border-nexus-hairline px-7 py-5">
        <div className="rounded-xl bg-nexus-accent/15 p-2.5">
          <Ic.terminal className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-semibold tracking-tight text-nexus-text">Terminal</h1>
          <p className="text-xs text-nexus-muted">
            Shell interaktif host ({navigator.userAgent.includes("Windows") ? "PowerShell" : "bash"}) — jalankan perintah apa pun.
          </p>
        </div>
        {exited && (
          <button className="nx-btn-primary" onClick={() => setSessionKey((k) => k + 1)}>
            <Ic.refresh className="h-4 w-4" /> Mulai Ulang
          </button>
        )}
      </header>
      <div className="min-h-0 flex-1 bg-nexus-bg p-2">
        <div ref={hostRef} className="h-full w-full" />
      </div>
    </div>
  );
};
