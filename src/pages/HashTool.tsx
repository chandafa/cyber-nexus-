// src/pages/HashTool.tsx — Hash Identifier & Cracker.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { Select } from "../components/Select";
import { buildArgs } from "../lib/tauri";

export const HashTool: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [submode, setSubmode] = useState<"identify" | "crack">("identify");
  const [hash, setHash] = useState("");
  const [hashes, setHashes] = useState("");
  const [wordlist, setWordlist] = useState("wordlists/rockyou_sample.txt");
  const [hashtype, setHashtype] = useState("auto");

  const run = () =>
    consoleRef.current?.start({
      command: "hash_tool",
      module: "hash_tool",
      mode: submode,
      target: submode === "identify" ? hash : undefined,
      args:
        submode === "identify"
          ? buildArgs({ submode: "identify", hash })
          : buildArgs({ submode: "crack", hashes, wordlist, hashtype }),
    });

  return (
    <ModuleScaffold
      title="Hash Identifier & Cracker"
      description="Deteksi tipe hash & dictionary attack nyata (hashlib)"
      icon={Ic.hashId}
      consoleRef={consoleRef}
      module="hash_tool"
      renderResult={(r) =>
        r.submode === "crack" ? (
          <div className="space-y-4">
            <div className="nx-card text-center">
              <div className="text-xl font-bold">
                {(r.cracked || []).length}/{r.total ?? 0}
              </div>
              <div className="text-xs text-nexus-muted">hash cracked</div>
            </div>
            <ResultTable
              csvName="cracked.csv"
              rows={r.cracked || []}
              columns={[
                { key: "hash", header: "Hash" },
                { key: "plaintext", header: "Plaintext" },
                { key: "type", header: "Tipe" },
              ]}
            />
          </div>
        ) : (
          <div className="space-y-4">
            <div className="nx-card text-center">
              <div className="text-xl font-bold">{r.length ?? 0}</div>
              <div className="text-xs text-nexus-muted">panjang input</div>
            </div>
            <ResultTable
              csvName="hash_candidates.csv"
              rows={r.candidates || []}
              columns={[
                { key: "name", header: "Tipe" },
                { key: "hashcat_mode", header: "Hashcat Mode" },
                { key: "john_format", header: "John Format" },
              ]}
            />
          </div>
        )
      }
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Submode</label>
            <Select
              value={submode}
              onChange={(v) => setSubmode(v as "identify" | "crack")}
              options={[
                { value: "identify", label: "Identify (deteksi tipe)" },
                { value: "crack", label: "Crack (dictionary attack)" },
              ]}
            />
          </div>

          {submode === "identify" ? (
            <div>
              <label className="nx-label">Hash</label>
              <input
                className="nx-input font-mono"
                value={hash}
                onChange={(e) => setHash(e.target.value)}
                placeholder="5f4dcc3b5aa765d61d8327deb882cf99"
              />
            </div>
          ) : (
            <>
              <div>
                <label className="nx-label">Hashes (pisah baris/koma)</label>
                <textarea
                  className="nx-input font-mono"
                  rows={4}
                  value={hashes}
                  onChange={(e) => setHashes(e.target.value)}
                  placeholder="5f4dcc3b5aa765d61d8327deb882cf99"
                />
              </div>
              <div>
                <label className="nx-label">Path Wordlist</label>
                <input
                  className="nx-input font-mono"
                  value={wordlist}
                  onChange={(e) => setWordlist(e.target.value)}
                  placeholder="wordlists/rockyou_sample.txt"
                />
              </div>
              <div>
                <label className="nx-label">Tipe Hash</label>
                <Select
                  value={hashtype}
                  onChange={setHashtype}
                  options={["auto", "md5", "sha1", "sha256", "sha512", "ntlm"]}
                />
              </div>
            </>
          )}

          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" />{" "}
            {submode === "identify" ? "Identify Hash" : "Crack Hashes"}
          </button>
          <p className="text-xs text-nexus-muted">
            Hanya untuk audit yang sah atas hash milik/berizin Anda.
          </p>
        </div>
      }
    />
  );
};
