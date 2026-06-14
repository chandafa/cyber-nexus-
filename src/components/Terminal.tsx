// src/components/Terminal.tsx
// xterm.js wrapper — SDD bagian 9.3. Mendukung streaming via imperative handle.
import React, { useEffect, useRef, useImperativeHandle, forwardRef } from "react";
import { Terminal as XTerm } from "xterm";
import { FitAddon } from "xterm-addon-fit";

export interface TerminalHandle {
  write: (line: string) => void;
  clear: () => void;
}

interface TerminalProps {
  fontSize?: number;
  onReady?: (terminal: XTerm) => void;
}

// Pewarnaan ringan berdasarkan kata kunci output.
function colorize(line: string): string {
  const RESET = "\x1b[0m";
  if (/\[ERROR\]|error|failed|critical|CRITICAL/.test(line)) return `\x1b[38;5;203m${line}${RESET}`;
  if (/\[WARN\]|warning|WARN/.test(line)) return `\x1b[38;5;215m${line}${RESET}`;
  if (/\[DEMO\]/.test(line)) return `\x1b[38;5;111m${line}${RESET}`;
  if (/^\$ /.test(line)) return `\x1b[38;5;141m${line}${RESET}`;
  if (/open|found|success|completed|\bup\b/i.test(line)) return `\x1b[38;5;150m${line}${RESET}`;
  return line;
}

export const Terminal = forwardRef<TerminalHandle, TerminalProps>(
  ({ fontSize = 13, onReady }, ref) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const termRef = useRef<XTerm | null>(null);
    const fitRef = useRef<FitAddon | null>(null);

    useImperativeHandle(ref, () => ({
      write: (line: string) => termRef.current?.writeln(colorize(line)),
      clear: () => termRef.current?.clear(),
    }));

    useEffect(() => {
      if (!containerRef.current) return;
      const term = new XTerm({
        theme: { background: "#0d0d1a", foreground: "#a8d8a8", cursor: "#a8d8a8" },
        fontSize,
        fontFamily: "JetBrains Mono, Consolas, monospace",
        scrollback: 5000,
        convertEol: true,
        cursorBlink: false,
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      term.open(containerRef.current);
      try {
        fit.fit();
      } catch {
        /* ignore */
      }
      termRef.current = term;
      fitRef.current = fit;
      term.writeln("\x1b[38;5;141mNexus terminal siap. Mulai sebuah scan untuk melihat output.\x1b[0m");
      if (onReady) onReady(term);

      const observer = new ResizeObserver(() => {
        try {
          fit.fit();
        } catch {
          /* ignore */
        }
      });
      observer.observe(containerRef.current);
      return () => {
        observer.disconnect();
        term.dispose();
      };
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return <div ref={containerRef} className="terminal-host h-full w-full" />;
  }
);

Terminal.displayName = "Terminal";
