// src/pages/PasswordAuditor.tsx — SDD bagian 5.4.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { Select } from "../components/Select";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { buildArgs } from "../lib/tauri";

const PROTOCOLS = ["ssh", "ftp", "http-get", "http-post-form", "smb", "rdp", "mysql", "postgres", "telnet"];
const HASH_MODES = [
  { m: 0, label: "MD5 (-m 0)" },
  { m: 100, label: "SHA1 (-m 100)" },
  { m: 1400, label: "SHA256 (-m 1400)" },
  { m: 1700, label: "SHA512 (-m 1700)" },
  { m: 1800, label: "SHA-512 Unix (-m 1800)" },
  { m: 1000, label: "NTLM (-m 1000)" },
  { m: 3200, label: "bcrypt (-m 3200)" },
  { m: 2500, label: "WPA/WPA2 (-m 2500)" },
];

export const PasswordAuditor: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [sub, setSub] = useState<"hydra" | "hashcat" | "detect">("hydra");

  // hydra
  const [target, setTarget] = useState("192.168.1.10");
  const [protocol, setProtocol] = useState("ssh");
  const [username, setUsername] = useState("admin");
  // hashcat
  const [hashFile, setHashFile] = useState("");
  const [hashMode, setHashMode] = useState(0);
  // detect
  const [hashStr, setHashStr] = useState("5f4dcc3b5aa765d61d8327deb882cf99");

  const run = () => {
    if (sub === "hydra") {
      consoleRef.current?.start({
        command: "password_audit",
        args: buildArgs({ submode: "hydra", target, protocol, username }),
        module: "password",
        target,
        mode: protocol,
      });
    } else if (sub === "hashcat") {
      consoleRef.current?.start({
        command: "password_audit",
        args: buildArgs({ submode: "hashcat", hash_file: hashFile, hash_mode: hashMode }),
        module: "password",
        mode: "hashcat",
      });
    } else {
      consoleRef.current?.start({
        command: "password_audit",
        args: buildArgs({ submode: "detect", hash_string: hashStr }),
        module: "password",
        mode: "detect",
      });
    }
  };

  return (
    <ModuleScaffold
      title="Password Auditor"
      description="Hydra (online brute force) & Hashcat (offline cracking)"
      icon={Ic.password}
      consoleRef={consoleRef}
      module="password"
      renderResult={(r) => {
        if (r.submode === "detect")
          return (
            <div className="nx-card">
              <div className="flex items-center gap-2 text-nexus-muted">
                <Ic.hashId className="h-4 w-4" /> Hash Type Terdeteksi
              </div>
              <div className="mt-2 font-mono text-lg text-nexus-accent2">{r.detected}</div>
            </div>
          );
        const rows = (r.found || r.cracked || []).map((x: string) => ({ result: x }));
        return (
          <ResultTable
            rows={rows}
            csvName="credentials.csv"
            columns={[{ key: "result", header: r.submode === "hashcat" ? "Hash:Password" : "Kredensial" }]}
            empty="Tidak ada kredensial ditemukan."
          />
        );
      }}
      form={
        <div className="space-y-4">
          <div className="flex rounded-lg border border-nexus-border p-1">
            {(["hydra", "hashcat", "detect"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSub(s)}
                className={`flex-1 rounded-md px-2 py-1.5 text-xs capitalize ${
                  sub === s ? "bg-nexus-accent text-white" : "text-nexus-muted"
                }`}
              >
                {s === "detect" ? "Hash ID" : s}
              </button>
            ))}
          </div>

          {sub === "hydra" && (
            <>
              <Field label="Target">
                <input className="nx-input font-mono" value={target} onChange={(e) => setTarget(e.target.value)} />
              </Field>
              <Field label="Protocol">
                <Select value={protocol} onChange={setProtocol} options={PROTOCOLS} />
              </Field>
              <Field label="Username">
                <input className="nx-input font-mono" value={username} onChange={(e) => setUsername(e.target.value)} />
              </Field>
              <p className="text-xs text-nexus-muted">
                Wordlist password default: <code className="font-mono">wordlists/rockyou.txt</code>
              </p>
            </>
          )}

          {sub === "hashcat" && (
            <>
              <Field label="Path File Hash">
                <input
                  className="nx-input font-mono"
                  value={hashFile}
                  onChange={(e) => setHashFile(e.target.value)}
                  placeholder="/path/to/hashes.txt"
                />
              </Field>
              <Field label="Hash Mode">
                <Select
                  value={String(hashMode)}
                  onChange={(v) => setHashMode(Number(v))}
                  options={HASH_MODES.map((h) => ({ value: String(h.m), label: h.label }))}
                />
              </Field>
            </>
          )}

          {sub === "detect" && (
            <Field label="Hash String">
              <textarea
                className="nx-input font-mono"
                rows={3}
                value={hashStr}
                onChange={(e) => setHashStr(e.target.value)}
              />
            </Field>
          )}

          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> {sub === "detect" ? "Identifikasi" : "Mulai"}
          </button>
          <p className="rounded-lg border border-yellow-500/30 bg-severity-medium/10 px-3 py-2 text-xs text-yellow-200">
            Gunakan hanya pada sistem milik sendiri atau dengan izin tertulis.
          </p>
        </div>
      }
    />
  );
};

const Field: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div>
    <label className="nx-label">{label}</label>
    {children}
  </div>
);
