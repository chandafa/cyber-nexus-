// src/components/Select.tsx
// Dropdown minimalis (gaya VS Code): kotak, hairline, panel gelap/terang,
// highlight hover, centang pada item terpilih. Mengganti <select> bawaan.
import React, { useEffect, useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { cn } from "../lib/utils";

export interface Option {
  value: string;
  label: string;
  hint?: string;
}

interface Props {
  value: string;
  onChange: (value: string) => void;
  options: Option[] | string[];
  placeholder?: string;
  className?: string;
  disabled?: boolean;
}

function normalize(options: Option[] | string[]): Option[] {
  return options.map((o) => (typeof o === "string" ? { value: o, label: o } : o));
}

export const Select: React.FC<Props> = ({
  value,
  onChange,
  options,
  placeholder = "Pilih…",
  className,
  disabled,
}) => {
  const opts = normalize(options);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const current = opts.find((o) => o.value === value);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={ref} className={cn("relative", className)}>
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "flex w-full items-center justify-between gap-2 rounded-sm border bg-nexus-bg px-3 py-1.5 text-left text-[12.5px] outline-none transition-colors",
          open ? "border-nexus-accent" : "border-nexus-border hover:border-nexus-subtle",
          disabled && "cursor-not-allowed opacity-50"
        )}
      >
        <span className={cn("truncate", current ? "text-nexus-text" : "text-nexus-subtle")}>
          {current ? current.label : placeholder}
        </span>
        <Ic.chevronDown
          className={cn("h-4 w-4 shrink-0 text-nexus-muted transition-transform", open && "rotate-180")}
        />
      </button>

      {open && (
        <div className="absolute z-50 mt-1 max-h-64 w-full overflow-auto rounded-sm border border-nexus-border bg-nexus-panel py-1 shadow-menu animate-fade-in">
          {opts.length === 0 && (
            <div className="px-3 py-2 text-[12px] text-nexus-subtle">Tidak ada opsi</div>
          )}
          {opts.map((o) => {
            const active = o.value === value;
            return (
              <button
                key={o.value}
                type="button"
                onClick={() => {
                  onChange(o.value);
                  setOpen(false);
                }}
                className={cn(
                  "flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left text-[12.5px] transition-colors",
                  active ? "bg-nexus-accent/15 text-nexus-text" : "text-nexus-muted hover:bg-nexus-elevated hover:text-nexus-text"
                )}
              >
                <span className="min-w-0">
                  <span className="block truncate">{o.label}</span>
                  {o.hint && <span className="block truncate text-[11px] text-nexus-subtle">{o.hint}</span>}
                </span>
                {active && <Ic.checkSmall className="h-3.5 w-3.5 shrink-0 text-nexus-accent" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};
