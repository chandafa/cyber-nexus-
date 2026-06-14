// src/pages/SetupWizard.tsx — SDD bagian 3.4 & 8.1. Onboarding first-run.
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Ic } from "../lib/icons";
import { useSettingsStore } from "../app/store/settings.store";
import { useScanRuntimeStore } from "../app/store/scanRuntime.store";
import { DependencyCard } from "../components/DependencyCard";
import {
  checkPrivileges,
  getInstallInfo,
  isTauri,
} from "../lib/tauri";

type Step = 0 | 1 | 2 | 3 | 4;
const STEP_LABELS = ["Welcome", "Dependency Check", "Auto Install", "Permission", "Selesai"];

export const SetupWizard: React.FC = () => {
  const navigate = useNavigate();
  const { deps, refreshDeps, loading, missingRequired, missingAny, update, install } =
    useSettingsStore();
  const installing = useScanRuntimeStore((s) => s.scans["install"]?.running ?? false);
  const [step, setStep] = useState<Step>(0);
  const [agreed, setAgreed] = useState(false);
  const [installCmd, setInstallCmd] = useState<any>(null);
  const [copied, setCopied] = useState(false);
  const [priv, setPriv] = useState<{ is_admin: boolean; platform: string } | null>(null);
  const [selected, setSelected] = useState<string[]>([]);

  const runInstall = (tools: string[]) => {
    install(tools);
    setSelected((sel) => sel.filter((t) => !tools.includes(t)));
  };

  const toggleSel = (name: string) =>
    setSelected((sel) => (sel.includes(name) ? sel.filter((t) => t !== name) : [...sel, name]));

  useEffect(() => {
    if (step === 1) refreshDeps();
    if (step === 3 && isTauri()) checkPrivileges().then(setPriv).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  const missing = missingRequired();
  const allMissing = Object.entries(deps)
    .filter(([, v]) => !v.installed)
    .map(([k]) => k);

  const loadInstall = async () => {
    if (!isTauri()) return;
    try {
      setInstallCmd(await getInstallInfo(allMissing));
    } catch {
      /* ignore */
    }
  };

  useEffect(() => {
    if (step === 2) loadInstall();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  const finish = async () => {
    await update("onboarding_complete", "true");
    navigate("/", { replace: true });
  };

  const copy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-nexus-bg">
      {/* Stepper */}
      <div className="flex items-center justify-center gap-2 border-b border-nexus-border py-4">
        {STEP_LABELS.map((label, i) => (
          <div key={label} className="flex items-center gap-2">
            <div
              className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-bold ${
                i <= step ? "bg-nexus-accent text-white" : "bg-nexus-panel text-nexus-muted"
              }`}
            >
              {i + 1}
            </div>
            <span className={`text-xs ${i <= step ? "text-nexus-text" : "text-nexus-muted"}`}>
              {label}
            </span>
            {i < STEP_LABELS.length - 1 && <div className="h-px w-6 bg-nexus-border" />}
          </div>
        ))}
      </div>

      <div className="mx-auto w-full max-w-3xl flex-1 overflow-auto p-8">
        {/* Step 0: Welcome */}
        {step === 0 && (
          <div className="text-center">
            <Ic.logo className="mx-auto h-16 w-16 text-nexus-accent" />
            <h1 className="mt-4 text-3xl font-bold text-nexus-text">Selamat datang di Nexus</h1>
            <p className="mx-auto mt-2 max-w-xl text-sm text-nexus-muted">
              Antarmuka terpadu untuk berbagai tools keamanan jaringan — scanning, monitoring,
              analysis, dan defense dalam satu dashboard.
            </p>
            <div className="mx-auto mt-6 max-w-xl rounded-xl border border-yellow-500/30 bg-severity-medium/10 p-4 text-left text-sm text-yellow-100">
              <strong className="flex items-center gap-2">
                <Ic.defense className="h-4 w-4" /> Disclaimer Penggunaan Etis
              </strong>
              <p className="mt-2 text-yellow-100/80">
                Nexus dirancang semata-mata untuk pembelajaran ethical hacking, penetration testing
                dengan izin, dan security research pribadi. Penggunaan terhadap sistem yang tidak
                Anda miliki atau tanpa izin eksplisit adalah ilegal. Anda bertanggung jawab penuh
                atas semua aktivitas yang dilakukan.
              </p>
              <label className="mt-3 flex cursor-pointer items-center gap-2 text-yellow-50">
                <input
                  type="checkbox"
                  checked={agreed}
                  onChange={(e) => setAgreed(e.target.checked)}
                  className="accent-nexus-accent"
                />
                Saya memahami dan menyetujui penggunaan etis.
              </label>
            </div>
            <button
              className="nx-btn-primary mx-auto mt-6"
              disabled={!agreed}
              onClick={() => setStep(1)}
            >
              Lanjut <Ic.arrowRight className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Step 1: Dependency Check */}
        {step === 1 && (
          <div>
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-xl font-semibold text-nexus-text">Dependency Check</h2>
              <button className="nx-btn-ghost" onClick={refreshDeps} disabled={loading}>
                <Ic.refresh className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Periksa Ulang
              </button>
            </div>
            {!isTauri() && (
              <p className="mb-3 rounded-lg bg-severity-medium/10 p-3 text-xs text-yellow-200">
                Preview browser: pemeriksaan dependency butuh backend Tauri.
              </p>
            )}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {Object.entries(deps).map(([name, tool]) => (
                <DependencyCard key={name} name={name} tool={tool} />
              ))}
            </div>
            <div className="mt-6 flex justify-between">
              <button className="nx-btn-ghost" onClick={() => setStep(0)}>
                Kembali
              </button>
              <button className="nx-btn-primary" onClick={() => setStep(2)}>
                Lanjut <Ic.arrowRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Auto Install */}
        {step === 2 && (
          <div>
            <h2 className="mb-1 text-xl font-semibold text-nexus-text">Instalasi Tools</h2>
            {allMissing.length === 0 ? (
              <p className="border border-nexus-green/40 bg-nexus-green/10 p-4 text-sm text-nexus-green">
                Semua tools sudah terpasang. Anda bisa lanjut.
              </p>
            ) : (
              <>
                <p className="mb-3 text-sm text-nexus-muted">
                  Centang tools yang ingin dipasang, lalu klik <b>Install Terpilih</b> — atau pasang
                  sekaligus dengan <b>Install Semua</b>. Nexus akan meminta izin Administrator otomatis.
                </p>

                <div className="mb-3 flex flex-wrap gap-2">
                  <button
                    className="nx-btn-primary"
                    onClick={() => runInstall(allMissing)}
                    disabled={installing}
                  >
                    {installing ? (
                      <Ic.refresh className="h-4 w-4 animate-spin" />
                    ) : (
                      <Ic.install className="h-4 w-4" />
                    )}
                    Install Semua ({allMissing.length})
                  </button>
                  <button
                    className="nx-btn-ghost"
                    onClick={() => runInstall(selected)}
                    disabled={selected.length === 0 || installing}
                  >
                    <Ic.install className="h-4 w-4" /> Install Terpilih ({selected.length})
                  </button>
                  <button className="nx-btn-ghost" onClick={refreshDeps} disabled={loading}>
                    <Ic.refresh className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Periksa Ulang
                  </button>
                </div>

                <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                  {allMissing.map((name) => (
                    <label
                      key={name}
                      className="flex cursor-pointer items-center gap-2 border border-nexus-hairline bg-nexus-surface px-3 py-2"
                    >
                      <input
                        type="checkbox"
                        checked={selected.includes(name)}
                        onChange={() => toggleSel(name)}
                        className="accent-nexus-accent"
                        disabled={installing}
                      />
                      <span className="flex-1 font-mono text-[12.5px] text-nexus-text">{name}</span>
                      {deps[name] && !deps[name].required && <span className="nx-chip">opsional</span>}
                      <button
                        type="button"
                        className="nx-btn-ghost px-2 py-0.5 text-[11px]"
                        onClick={(e) => {
                          e.preventDefault();
                          runInstall([name]);
                        }}
                        disabled={installing}
                      >
                        {installing ? (
                          <Ic.refresh className="h-3 w-3 animate-spin" />
                        ) : (
                          <Ic.install className="h-3 w-3" />
                        )}
                      </button>
                    </label>
                  ))}
                </div>

                <details className="mt-4">
                  <summary className="cursor-pointer text-xs text-nexus-muted">
                    Atau jalankan perintah manual
                  </summary>
                  {installCmd?.command ? (
                    <div className="mt-2 border border-nexus-border bg-nexus-bg p-3">
                      <div className="mb-2 flex items-center justify-between text-xs text-nexus-muted">
                        <span>Package manager: {installCmd.pkg_manager}</span>
                        <button className="nx-btn-ghost px-2 py-0.5" onClick={() => copy(installCmd.command)}>
                          {copied ? <Ic.check className="h-3.5 w-3.5" /> : <Ic.copy className="h-3.5 w-3.5" />} Salin
                        </button>
                      </div>
                      <pre className="overflow-auto font-mono text-xs text-nexus-green">{installCmd.command}</pre>
                      {installCmd.pkg_manager === "choco" && (
                        <p className="mt-2 text-xs text-nexus-muted">
                          Windows memakai Chocolatey. Jika belum ada, pasang Chocolatey lebih dulu
                          via PowerShell (Administrator).
                        </p>
                      )}
                    </div>
                  ) : (
                    <p className="mt-2 text-xs text-nexus-muted">Memuat perintah…</p>
                  )}
                </details>
              </>
            )}
            <div className="mt-6 flex justify-between">
              <button className="nx-btn-ghost" onClick={() => setStep(1)}>
                Kembali
              </button>
              <button className="nx-btn-primary" onClick={() => setStep(3)}>
                Lanjut <Ic.arrowRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Permission */}
        {step === 3 && (
          <div>
            <h2 className="mb-2 text-xl font-semibold text-nexus-text">Permission Check</h2>
            <div className="nx-card flex items-center gap-4">
              <Ic.lock className={`h-7 w-7 ${priv?.is_admin ? "text-nexus-green" : "text-severity-medium"}`} />
              <div>
                <div className="text-sm font-semibold text-nexus-text">
                  {priv ? (priv.is_admin ? "Berjalan dengan hak admin/root" : "Tanpa hak admin/root") : "Memeriksa..."}
                </div>
                <p className="text-xs text-nexus-muted">
                  Beberapa fitur (tshark capture, nmap OS detection, iptables) memerlukan privilege
                  elevated. Jalankan Nexus sebagai Administrator untuk fungsi penuh.
                </p>
              </div>
            </div>
            <div className="mt-6 flex justify-between">
              <button className="nx-btn-ghost" onClick={() => setStep(2)}>
                Kembali
              </button>
              <button className="nx-btn-primary" onClick={() => setStep(4)}>
                Lanjut <Ic.arrowRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {/* Step 4: Done */}
        {step === 4 && (
          <div className="text-center">
            <Ic.check className="mx-auto h-14 w-14 text-nexus-green" />
            <h2 className="mt-4 text-2xl font-bold text-nexus-text">Setup Selesai</h2>
            <p className="mt-2 text-sm text-nexus-muted">
              {missing.length > 0
                ? `Masih ada ${missing.length} required tool yang kurang — modul terkait akan berjalan dalam mode demo sampai dipasang.`
                : "Semua siap. Selamat menggunakan Nexus secara bertanggung jawab."}
            </p>
            <button className="nx-btn-primary mx-auto mt-6" onClick={finish}>
              Mulai Nexus <Ic.arrowRight className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
