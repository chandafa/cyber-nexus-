// src/pages/HumanElement.tsx — Layer 8 Human Element: Phishing & Security Awareness
import React, { useState } from "react";
import { Ic } from "../lib/icons";

interface Campaign {
  id: string;
  name: string;
  targetGroup: string;
  schedule: string;
  status: string;
  clickRate: string;
  reportRate: string;
  lastRun: string;
}

const CAMPAIGN_TEMPLATES = [
  { value: "gcp_alert", label: "[Urgent] GCP Billing Threshold Exceeded", level: "Medium" },
  { value: "hr_policy", label: "Perubahan Kebijakan Insentif Karyawan 2026", level: "High" },
  { value: "ceo_wire", label: "CEO Request: Urgent Wire Transfer Confirmation", level: "Critical" },
  { value: "mfa_reset", label: "Security Alert: Microsoft 365 MFA Verification Required", level: "High" },
];

const TARGET_GROUPS = ["Seluruh Karyawan", "Departemen Keuangan", "Tim Engineering & Devs", "Divisi Sales & Marketing"];
const SCHEDULES = ["Jalankan Sekarang (Simulasi)", "Setiap Hari Senin (09:00)", "Setiap Awal Bulan", "Kustom Cron"];

const QUIZ_QUESTIONS = [
  {
    id: 1,
    scenario: "Anda menerima email dari 'keamanan-gcp@google-support.net' yang mengabarkan bahwa akun cloud server Anda akan di-suspend dalam 2 jam jika tidak melakukan verifikasi password melalui link yang dilampirkan.",
    options: [
      { text: "Segera klik link dan login agar server produksi tidak mati.", isCorrect: false },
      { text: "Abaikan saja karena server cloud jarang mengalami error suspend.", isCorrect: false },
      { text: "Periksa domain pengirim secara teliti (google-support.net bukan domain resmi Google), jangan klik link tersebut, dan laporkan ke divisi IT/Security.", isCorrect: true }
    ],
    explanation: "Email ini menggunakan taktik urgensi tinggi ('2 jam') dan domain spoofing ('google-support.net' yang mirip tapi palsu). Tindakan terbaik adalah selalu memverifikasi domain pengirim dan melaporkannya."
  },
  {
    id: 2,
    scenario: "Saat membuka dashboard, Anda melihat pop-up yang menyamar sebagai notifikasi sistem: 'Browser update required to view this report. Click here to download chrome_patch.exe'.",
    options: [
      { text: "Klik download dan jalankan patch untuk memperbarui browser.", isCorrect: false },
      { text: "Tutup pop-up, jangan mengunduh file, dan akses url situs resmi Google Chrome secara terpisah untuk memeriksa versi browser Anda.", isCorrect: true },
      { text: "Salin file tersebut dan bagikan ke teman kerja agar mereka juga ter-update.", isCorrect: false }
    ],
    explanation: "Serangan ini adalah drive-by download / browser hijacker. Notifikasi update browser di dalam halaman web pihak ketiga hampir selalu merupakan malware (.exe). Periksa update hanya langsung melalui setelan browser resmi."
  },
  {
    id: 3,
    scenario: "Rekan kerja Anda mengirim pesan instan via media chat personal (bukan Slack/Teams resmi perusahaan) yang berbunyi: 'Eh, tolong bukain file spreadsheet pengeluaran kantor ini dong di laptop lu, gw lagi di luar ga bawa leptop. [link: sharing-data-finance.zip]'.",
    options: [
      { text: "Langsung buka karena dia adalah teman baik dan rekan kerja terpercaya.", isCorrect: false },
      { text: "Hubungi rekan tersebut melalui saluran komunikasi resmi perusahaan (misal nomor telepon seluler atau video call resmi) untuk mengonfirmasi apakah dia benar-benar mengirimkannya sebelum membuka file.", isCorrect: true },
      { text: "Download file tersebut di server produksi dan ekstrak di sana.", isCorrect: false }
    ],
    explanation: "Akun rekan kerja Anda bisa saja diretas (account takeover) atau disimulasikan. Melakukan verifikasi melalui jalur komunikasi alternatif (out-of-band verification) adalah pertahanan terbaik dari rekayasa sosial."
  }
];

export const HumanElement: React.FC = () => {
  // Campaign State
  const [campaigns, setCampaigns] = useState<Campaign[]>([
    {
      id: "1",
      name: "[Urgent] GCP Billing Threshold Exceeded",
      targetGroup: "Tim Engineering & Devs",
      schedule: "Setiap Awal Bulan",
      status: "Aktif",
      clickRate: "8%",
      reportRate: "72%",
      lastRun: "2026-06-01 09:00"
    },
    {
      id: "2",
      name: "CEO Request: Urgent Wire Transfer Confirmation",
      targetGroup: "Departemen Keuangan",
      schedule: "Jalankan Sekarang (Simulasi)",
      status: "Selesai",
      clickRate: "24%",
      reportRate: "58%",
      lastRun: "2026-06-15 11:30"
    }
  ]);

  const [selectedTemplate, setSelectedTemplate] = useState("gcp_alert");
  const [selectedGroup, setSelectedGroup] = useState("Tim Engineering & Devs");
  const [selectedSchedule, setSelectedSchedule] = useState("Jalankan Sekarang (Simulasi)");

  // Quiz State
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedOption, setSelectedOption] = useState<number | null>(null);
  const [showFeedback, setShowFeedback] = useState(false);
  const [quizScore, setQuizScore] = useState(0);
  const [quizFinished, setQuizFinished] = useState(false);

  // Simulation Logs
  const [simLogs, setSimLogs] = useState<string[]>([
    "[09:00:00] [AWARENESS] Modul simulasi edukasi diaktifkan.",
    "[09:01:05] [DRILL] Kampanye #2 'CEO Request' didistribusikan ke Departemen Keuangan (12 staf).",
    "[09:05:40] [DRILL] Statistik Kampanye #2: 3 staf mengklik link simulasi (24%).",
    "[09:12:15] [DRILL] Statistik Kampanye #2: 7 staf mendeteksi & melaporkan email (58%).",
    "[09:30:00] [DRILL] Kampanye #2 selesai. Tingkat kepatuhan/awareness: Medium-High."
  ]);

  const handleScheduleCampaign = () => {
    const template = CAMPAIGN_TEMPLATES.find(t => t.value === selectedTemplate);
    if (!template) return;

    const newCampaign: Campaign = {
      id: String(campaigns.length + 1),
      name: template.label,
      targetGroup: selectedGroup,
      schedule: selectedSchedule,
      status: selectedSchedule.includes("Sekarang") ? "Selesai" : "Aktif",
      clickRate: selectedSchedule.includes("Sekarang") ? "12%" : "-",
      reportRate: selectedSchedule.includes("Sekarang") ? "80%" : "-",
      lastRun: new Date().toISOString().replace('T', ' ').substring(0, 16)
    };

    setCampaigns([newCampaign, ...campaigns]);

    // Add log
    const timestamp = new Date().toTimeString().split(' ')[0];
    const newLogs = [
      `[${timestamp}] [DRILL] Menjadwalkan kampanye baru: '${template.label}' untuk '${selectedGroup}'.`,
      `[${timestamp}] [DRILL] Trigger penjadwalan mode: ${selectedSchedule}.`,
      ...(selectedSchedule.includes("Sekarang") 
        ? [
            `[${timestamp}] [DRILL] [SIM] Mengirimkan email tiruan ke grup target ${selectedGroup}...`,
            `[${timestamp}] [DRILL] [SIM] Hasil: Click-through rate 12%, Pelaporan insiden 80%.`
          ]
        : [])
    ];

    setSimLogs(prev => [...newLogs, ...prev]);
  };

  const handleAnswerSubmit = (optionIndex: number) => {
    if (showFeedback) return;
    setSelectedOption(optionIndex);
    setShowFeedback(true);
    if (QUIZ_QUESTIONS[currentQuestion].options[optionIndex].isCorrect) {
      setQuizScore(prev => prev + 1);
    }
  };

  const handleNextQuestion = () => {
    setSelectedOption(null);
    setShowFeedback(false);
    if (currentQuestion + 1 < QUIZ_QUESTIONS.length) {
      setCurrentQuestion(prev => prev + 1);
    } else {
      setQuizFinished(true);
    }
  };

  const handleResetQuiz = () => {
    setCurrentQuestion(0);
    setSelectedOption(null);
    setShowFeedback(false);
    setQuizScore(0);
    setQuizFinished(false);
  };

  return (
    <div className="mx-auto max-w-6xl animate-fade-in p-6 space-y-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="bg-nexus-accent/15 p-2 rounded-lg border border-nexus-accent/30">
          <Ic.human className="h-6 w-6 text-nexus-accent animate-pulse" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-nexus-text font-mono tracking-tight">Layer 8 — Human Element</h1>
          <p className="text-xs text-nexus-muted font-mono">Modul Pelatihan & Simulasi Kesadaran Keamanan Siber (Phishing Awareness Scheduler)</p>
        </div>
      </header>

      {/* Grid Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-nexus-panel border border-nexus-hairline p-4 rounded-xl space-y-1">
          <span className="text-[10px] text-nexus-muted font-semibold uppercase tracking-wider font-mono">Simulations Run</span>
          <div className="text-2xl font-bold text-nexus-text font-mono">4 Kampanye</div>
          <span className="text-[10px] text-green-400 font-mono">Active tracking enabled</span>
        </div>
        <div className="bg-nexus-panel border border-nexus-hairline p-4 rounded-xl space-y-1">
          <span className="text-[10px] text-nexus-muted font-semibold uppercase tracking-wider font-mono">Avg Click-Through</span>
          <div className="text-2xl font-bold text-red-400 font-mono">14.7%</div>
          <span className="text-[10px] text-red-500 font-mono">↓ 3.2% dari kuartal lalu</span>
        </div>
        <div className="bg-nexus-panel border border-nexus-hairline p-4 rounded-xl space-y-1">
          <span className="text-[10px] text-nexus-muted font-semibold uppercase tracking-wider font-mono">Incident Report Rate</span>
          <div className="text-2xl font-bold text-green-400 font-mono">70.0%</div>
          <span className="text-[10px] text-green-400 font-mono">↑ 8.5% peningkatan kesadaran</span>
        </div>
        <div className="bg-nexus-panel border border-nexus-hairline p-4 rounded-xl space-y-1">
          <span className="text-[10px] text-nexus-muted font-semibold uppercase tracking-wider font-mono">Quiz Pass Rate</span>
          <div className="text-2xl font-bold text-nexus-accent font-mono">92%</div>
          <span className="text-[10px] text-nexus-accent font-mono">100% staff IT lulus</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_400px] gap-6">
        {/* Left Side: Campaign Manager & Quiz */}
        <div className="space-y-6">
          {/* Campaign Scheduler Section */}
          <div className="bg-nexus-panel border border-nexus-border rounded-xl p-5 space-y-4 shadow-lg">
            <div className="flex items-center gap-2 border-b border-nexus-hairline pb-2">
              <Ic.scheduler className="h-4 w-4 text-nexus-accent" />
              <h2 className="text-sm font-semibold text-nexus-text font-mono">Penjadwal Simulasi Phishing</h2>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-nexus-muted font-mono uppercase">Pilih Template Email</label>
                <select 
                  value={selectedTemplate} 
                  onChange={(e) => setSelectedTemplate(e.target.value)}
                  className="w-full bg-nexus-surface border border-nexus-border text-nexus-text rounded-lg px-3 py-2 text-xs focus:outline-none focus:border-nexus-accent font-mono"
                >
                  {CAMPAIGN_TEMPLATES.map(t => (
                    <option key={t.value} value={t.value}>{t.label} ({t.level})</option>
                  ))}
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-nexus-muted font-mono uppercase">Grup Sasaran (Target Staff)</label>
                <select 
                  value={selectedGroup} 
                  onChange={(e) => setSelectedGroup(e.target.value)}
                  className="w-full bg-nexus-surface border border-nexus-border text-nexus-text rounded-lg px-3 py-2 text-xs focus:outline-none focus:border-nexus-accent font-mono"
                >
                  {TARGET_GROUPS.map(g => (
                    <option key={g} value={g}>{g}</option>
                  ))}
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-nexus-muted font-mono uppercase">Jadwal Pengiriman</label>
                <select 
                  value={selectedSchedule} 
                  onChange={(e) => setSelectedSchedule(e.target.value)}
                  className="w-full bg-nexus-surface border border-nexus-border text-nexus-text rounded-lg px-3 py-2 text-xs focus:outline-none focus:border-nexus-accent font-mono"
                >
                  {SCHEDULES.map(s => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>

              <div className="flex items-end">
                <button
                  onClick={handleScheduleCampaign}
                  className="w-full bg-nexus-accent/20 hover:bg-nexus-accent/30 text-nexus-accent border border-nexus-accent/50 hover:border-nexus-accent transition-all rounded-lg py-2 text-xs font-semibold font-mono flex items-center justify-center gap-2"
                >
                  <Ic.play className="h-3.5 w-3.5" /> Luncurkan Kampanye
                </button>
              </div>
            </div>

            {/* Campaign Status Table */}
            <div className="mt-4 border border-nexus-hairline rounded-lg overflow-hidden">
              <table className="w-full text-xs text-left">
                <thead className="bg-nexus-surface text-nexus-muted font-mono border-b border-nexus-hairline text-[10px] uppercase font-semibold">
                  <tr>
                    <th className="p-3">Nama Kampanye</th>
                    <th className="p-3">Grup Target</th>
                    <th className="p-3">Jadwal</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Klik</th>
                    <th className="p-3">Lapor</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-nexus-hairline">
                  {campaigns.map(c => (
                    <tr key={c.id} className="hover:bg-nexus-surface/20">
                      <td className="p-3 font-semibold text-nexus-text font-mono truncate max-w-[180px]" title={c.name}>{c.name}</td>
                      <td className="p-3 text-nexus-muted">{c.targetGroup}</td>
                      <td className="p-3 text-nexus-muted font-mono text-[10px]">{c.schedule}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${c.status === 'Aktif' ? 'bg-green-950/40 text-green-300 border border-green-800' : 'bg-gray-800 text-gray-400'}`}>
                          {c.status}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-red-300 font-semibold">{c.clickRate}</td>
                      <td className="p-3 font-mono text-green-300 font-semibold">{c.reportRate}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Interactive Quiz Section */}
          <div className="bg-nexus-panel border border-nexus-border rounded-xl p-5 space-y-4 shadow-lg">
            <div className="flex items-center justify-between border-b border-nexus-hairline pb-2">
              <div className="flex items-center gap-2">
                <Ic.wordlistMgr className="h-4 w-4 text-nexus-accent" />
                <h2 className="text-sm font-semibold text-nexus-text font-mono">Interactive Awareness Quiz</h2>
              </div>
              <span className="text-[10px] font-mono text-nexus-muted">Skor: {quizScore} / {QUIZ_QUESTIONS.length}</span>
            </div>

            {!quizFinished ? (
              <div className="space-y-4">
                <div className="text-xs text-nexus-text bg-nexus-surface border border-nexus-hairline p-4 rounded-lg font-mono leading-relaxed">
                  <span className="text-nexus-accent font-bold">PERTANYAAN {currentQuestion + 1}:</span>
                  <p className="mt-2 text-nexus-text/90">{QUIZ_QUESTIONS[currentQuestion].scenario}</p>
                </div>

                <div className="space-y-2.5">
                  {QUIZ_QUESTIONS[currentQuestion].options.map((opt, i) => (
                    <button
                      key={i}
                      onClick={() => handleAnswerSubmit(i)}
                      disabled={showFeedback}
                      className={`w-full text-left p-3 rounded-lg border text-xs font-mono transition-all flex items-start gap-2.5 ${
                        selectedOption === i
                          ? opt.isCorrect
                            ? "bg-green-950/20 border-green-500 text-green-200"
                            : "bg-red-950/20 border-red-500 text-red-200"
                          : showFeedback && opt.isCorrect
                          ? "bg-green-950/20 border-green-500 text-green-200"
                          : "bg-nexus-surface border-nexus-border hover:border-nexus-accent text-nexus-muted hover:text-nexus-text"
                      }`}
                    >
                      <span className="bg-nexus-panel border border-nexus-hairline w-5 h-5 rounded-full flex items-center justify-center font-bold text-[10px] shrink-0">
                        {String.fromCharCode(65 + i)}
                      </span>
                      <span>{opt.text}</span>
                    </button>
                  ))}
                </div>

                {showFeedback && (
                  <div className="p-3 bg-nexus-surface border border-nexus-hairline rounded-lg space-y-2">
                    <div className="flex items-center gap-2 text-xs font-bold font-mono">
                      {QUIZ_QUESTIONS[currentQuestion].options[selectedOption || 0].isCorrect ? (
                        <span className="text-green-400 flex items-center gap-1"><Ic.check className="h-4 w-4" /> Jawaban Benar!</span>
                      ) : (
                        <span className="text-red-400 flex items-center gap-1"><Ic.close className="h-4 w-4" /> Jawaban Salah.</span>
                      )}
                    </div>
                    <p className="text-[11px] text-nexus-muted leading-relaxed font-mono">
                      {QUIZ_QUESTIONS[currentQuestion].explanation}
                    </p>
                    <button
                      onClick={handleNextQuestion}
                      className="mt-2 bg-nexus-accent text-nexus-panel font-bold px-4 py-1.5 rounded-lg text-xs font-mono hover:bg-nexus-accent/90 transition-all"
                    >
                      Pertanyaan Berikutnya →
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-6 space-y-4">
                <div className="inline-block p-4 bg-nexus-surface border border-nexus-accent/20 rounded-full">
                  <Ic.check className="h-10 w-10 text-nexus-accent animate-bounce" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-base font-bold text-nexus-text font-mono">Quiz Selesai!</h3>
                  <p className="text-xs text-nexus-muted font-mono">Skor Akhir Anda: {quizScore} dari {QUIZ_QUESTIONS.length} Pertanyaan</p>
                </div>
                <div className="text-xs text-nexus-muted max-w-sm mx-auto font-mono leading-relaxed bg-nexus-surface p-3 border border-nexus-hairline rounded-lg">
                  {quizScore === QUIZ_QUESTIONS.length 
                    ? "Luar biasa! Kesadaran keamanan Anda sempurna. Terus pertahankan kewaspadaan Anda."
                    : "Bagus! Tinjau kembali penjelasan soal yang salah untuk mengenali tanda-tanda phishing lebih baik."}
                </div>
                <button
                  onClick={handleResetQuiz}
                  className="nx-btn-ghost font-semibold px-5 py-2 border border-nexus-border hover:bg-nexus-surface font-mono"
                >
                  Ulangi Quiz
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Right Side: Educational Checklist & Logs */}
        <div className="space-y-6">
          {/* Awareness Cheat Sheet */}
          <div className="bg-nexus-panel border border-nexus-border rounded-xl p-5 space-y-4 shadow-lg">
            <div className="flex items-center gap-2 border-b border-nexus-hairline pb-2">
              <Ic.info className="h-4 w-4 text-nexus-accent" />
              <h2 className="text-sm font-semibold text-nexus-text font-mono">Security Checklist</h2>
            </div>
            
            <ul className="space-y-3 text-xs text-nexus-muted font-mono">
              <li className="flex items-start gap-2.5">
                <span className="text-nexus-accent font-semibold select-none">✔</span>
                <span>Selalu periksa domain lengkap alamat pengirim email (bukan sekadar display name).</span>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="text-nexus-accent font-semibold select-none">✔</span>
                <span>Jangan mengunduh atau mengekstrak lampiran `.zip` atau `.exe` dari pengirim tak dikenal.</span>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="text-nexus-accent font-semibold select-none">✔</span>
                <span>Gunakan otentikasi alternatif jika menerima instruksi mendadak perihal transfer dana atau kredensial.</span>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="text-nexus-accent font-semibold select-none">✔</span>
                <span>Laporkan email mencurigakan secepatnya ke sistem IT agar filter email dapat memblokir domain penyerang.</span>
              </li>
            </ul>
          </div>

          {/* Simulated Drill Logs console */}
          <div className="bg-nexus-panel border border-nexus-border rounded-xl p-5 space-y-3 shadow-lg flex flex-col h-[320px]">
            <div className="flex items-center justify-between border-b border-nexus-hairline pb-2">
              <div className="flex items-center gap-2">
                <Ic.terminal className="h-4 w-4 text-nexus-accent" />
                <h2 className="text-sm font-semibold text-nexus-text font-mono">Simulation Terminal</h2>
              </div>
              <button 
                onClick={() => setSimLogs([])}
                className="text-[10px] text-nexus-muted hover:text-nexus-text font-mono font-semibold"
              >
                Clear
              </button>
            </div>

            <div className="flex-1 overflow-auto bg-nexus-surface rounded-lg p-3 font-mono text-[11px] text-nexus-text/80 space-y-2 border border-nexus-hairline scrollbar-thin">
              {simLogs.length === 0 ? (
                <div className="text-nexus-subtle italic text-center py-10">Terminal kosong. Menunggu simulasi...</div>
              ) : (
                simLogs.map((log, index) => {
                  let color = "text-nexus-text/85";
                  if (log.includes("[SIM]")) color = "text-nexus-accent2 font-semibold";
                  if (log.includes("Hasil:")) color = "text-green-300 font-bold";
                  if (log.includes("mengklik")) color = "text-red-400 font-semibold";
                  return (
                    <div key={index} className={`${color} leading-relaxed break-words`}>
                      {log}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
