// src/app/router.tsx — routing aplikasi (SDD struktur app/).
import { createHashRouter } from "react-router-dom";
import { Layout } from "../components/Layout";
import { Dashboard } from "../pages/Dashboard";
import { SetupWizard } from "../pages/SetupWizard";
import { PortScanner } from "../pages/PortScanner";
import { NetworkScanner } from "../pages/NetworkScanner";
import { VulnScanner } from "../pages/VulnScanner";
import { PasswordAuditor } from "../pages/PasswordAuditor";
import { LogAnalyzer } from "../pages/LogAnalyzer";
import { NetworkMapper } from "../pages/NetworkMapper";
import { DefenseMonitor } from "../pages/DefenseMonitor";
import { ReportGenerator } from "../pages/ReportGenerator";
import { History } from "../pages/History";
import { Settings } from "../pages/Settings";

// SDD v2
import { SslAuditor } from "../pages/SslAuditor";
import { ExploitLookup } from "../pages/ExploitLookup";
import { ApiTester } from "../pages/ApiTester";
import { ContainerScanner } from "../pages/ContainerScanner";
import { CloudChecker } from "../pages/CloudChecker";
import { WirelessAuditor } from "../pages/WirelessAuditor";
import { SecurityScore } from "../pages/SecurityScore";
import { ScanDiff } from "../pages/ScanDiff";
import { AssetInventory } from "../pages/AssetInventory";
import { WordlistManager } from "../pages/WordlistManager";
import { Scheduler } from "../pages/Scheduler";
import { AttackSimulation } from "../pages/AttackSimulation";
import { DefenseSuite } from "../pages/DefenseSuite";
import { WAF } from "../pages/WAF";

// Terminal interaktif + modul baru
import { Shell } from "../pages/Shell";
import { DnsRecon } from "../pages/DnsRecon";
import { DirFuzzer } from "../pages/DirFuzzer";
import { Listener } from "../pages/Listener";
import { HashTool } from "../pages/HashTool";

export const router = createHashRouter([
  { path: "/setup", element: <SetupWizard /> },
  {
    path: "/",
    element: <Layout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "port-scanner", element: <PortScanner /> },
      { path: "network-scanner", element: <NetworkScanner /> },
      { path: "vuln-scanner", element: <VulnScanner /> },
      { path: "password-auditor", element: <PasswordAuditor /> },
      { path: "log-analyzer", element: <LogAnalyzer /> },
      { path: "network-mapper", element: <NetworkMapper /> },
      { path: "defense-monitor", element: <DefenseMonitor /> },
      { path: "report", element: <ReportGenerator /> },
      { path: "history", element: <History /> },
      { path: "settings", element: <Settings /> },

      // SDD v2
      { path: "ssl-auditor", element: <SslAuditor /> },
      { path: "exploit-lookup", element: <ExploitLookup /> },
      { path: "api-tester", element: <ApiTester /> },
      { path: "container-scanner", element: <ContainerScanner /> },
      { path: "cloud-checker", element: <CloudChecker /> },
      { path: "wireless-auditor", element: <WirelessAuditor /> },
      { path: "security-score", element: <SecurityScore /> },
      { path: "scan-diff", element: <ScanDiff /> },
      { path: "asset-inventory", element: <AssetInventory /> },
      { path: "wordlist-manager", element: <WordlistManager /> },
      { path: "scheduler", element: <Scheduler /> },
      { path: "attack-simulation", element: <AttackSimulation /> },
      { path: "defense-suite", element: <DefenseSuite /> },
      { path: "waf", element: <WAF /> },

      // Terminal interaktif + modul baru
      { path: "terminal", element: <Shell /> },
      { path: "dns-recon", element: <DnsRecon /> },
      { path: "dir-fuzzer", element: <DirFuzzer /> },
      { path: "listener", element: <Listener /> },
      { path: "hash-tool", element: <HashTool /> },
    ],
  },
]);