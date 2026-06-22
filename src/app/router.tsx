// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/app/router.tsx — routing aplikasi (SDD struktur app/).
import { createHashRouter } from "react-router-dom";
import { Layout } from "../components/Layout";
import { ProRouteGuard } from "../components/ProGate";
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
import { SystemHealth } from "../pages/SystemHealth";
import { EbpfSecurity } from "../pages/EbpfSecurity";
import { HumanElement } from "../pages/HumanElement";
import { NexusAgents } from "../pages/NexusAgents";

// Terminal interaktif + modul baru
import { Shell } from "../pages/Shell";
import { DnsRecon } from "../pages/DnsRecon";
import { DirFuzzer } from "../pages/DirFuzzer";
import { Listener } from "../pages/Listener";
import { HashTool } from "../pages/HashTool";

// Fleet / SOC (arsitektur agent <-> manager)
import { FleetManager } from "../pages/FleetManager";
import { FleetAgent } from "../pages/FleetAgent";
// SecOps (Pro) — 9 pilar SOC native
import { SiemSearch } from "../pages/secops/SiemSearch";
import { XdrIncidents } from "../pages/secops/XdrIncidents";
import { EdrTree } from "../pages/secops/EdrTree";
import { Ueba } from "../pages/secops/Ueba";
import { Soar } from "../pages/secops/Soar";
import { ThreatIntel } from "../pages/secops/ThreatIntel";
import { Ndr } from "../pages/secops/Ndr";
import { CloudCspm } from "../pages/secops/CloudCspm";
import { AiTriage } from "../pages/secops/AiTriage";
// Ekosistem (W1-W4)
import NexusNotifications from "../pages/NexusNotifications";
import NexusCanary from "../pages/NexusCanary";
import NexusAudit from "../pages/NexusAudit";
import NexusReplay from "../pages/NexusReplay";
import NexusAirgap from "../pages/NexusAirgap";
import NexusAware from "../pages/NexusAware";
import NexusAtlas from "../pages/NexusAtlas";
import NexusComply from "../pages/NexusComply";
import NexusContentPacks from "../pages/NexusContentPacks";
import NexusSyslog from "../pages/NexusSyslog";

export const router = createHashRouter([
  { path: "/setup", element: <SetupWizard /> },
  {
    path: "/",
    element: <Layout />,
    children: [
      // -------- Free (selalu bisa diakses) --------
      { index: true, element: <Dashboard /> },
      { path: "security-score", element: <SecurityScore /> },
      { path: "terminal", element: <Shell /> },
      { path: "system-health", element: <SystemHealth /> },
      { path: "ebpf-security", element: <EbpfSecurity /> },
      { path: "port-scanner", element: <PortScanner /> },
      { path: "network-scanner", element: <NetworkScanner /> },
      { path: "dns-recon", element: <DnsRecon /> },
      { path: "log-analyzer", element: <LogAnalyzer /> },
      { path: "hash-tool", element: <HashTool /> },
      { path: "wordlist-manager", element: <WordlistManager /> },
      { path: "history", element: <History /> },
      { path: "settings", element: <Settings /> },
      { path: "audit-log", element: <NexusAudit /> },

      // -------- Pro (butuh lisensi; dijaga ProRouteGuard) --------
      // Sinkron dengan lib/proModules.ts PRO_ROUTES & desktop_license.PRO_COMMANDS.
      {
        element: <ProRouteGuard />,
        children: [
          { path: "vuln-scanner", element: <VulnScanner /> },
          { path: "ssl-auditor", element: <SslAuditor /> },
          { path: "api-tester", element: <ApiTester /> },
          { path: "dir-fuzzer", element: <DirFuzzer /> },
          { path: "network-mapper", element: <NetworkMapper /> },
          { path: "asset-inventory", element: <AssetInventory /> },
          { path: "password-auditor", element: <PasswordAuditor /> },
          { path: "exploit-lookup", element: <ExploitLookup /> },
          { path: "attack-simulation", element: <AttackSimulation /> },
          { path: "listener", element: <Listener /> },
          { path: "wireless-auditor", element: <WirelessAuditor /> },
          { path: "container-scanner", element: <ContainerScanner /> },
          { path: "cloud-checker", element: <CloudChecker /> },
          { path: "scan-diff", element: <ScanDiff /> },
          { path: "defense-monitor", element: <DefenseMonitor /> },
          { path: "defense-suite", element: <DefenseSuite /> },
          { path: "nexus-agents", element: <NexusAgents /> },
          { path: "human-element", element: <HumanElement /> },
          { path: "waf", element: <WAF /> },
          { path: "report", element: <ReportGenerator /> },
          { path: "scheduler", element: <Scheduler /> },
          { path: "fleet-manager", element: <FleetManager /> },
          { path: "fleet-agent", element: <FleetAgent /> },
          // -------- SecOps (Pro) — 9 pilar SOC --------
          { path: "siem-search", element: <SiemSearch /> },
          { path: "xdr", element: <XdrIncidents /> },
          { path: "edr", element: <EdrTree /> },
          { path: "ueba", element: <Ueba /> },
          { path: "soar", element: <Soar /> },
          { path: "threat-intel", element: <ThreatIntel /> },
          { path: "ndr", element: <Ndr /> },
          { path: "cloud-cspm", element: <CloudCspm /> },
          { path: "ai-triage", element: <AiTriage /> },
          // -------- Ekosistem (W1-W4) --------
          { path: "notifications", element: <NexusNotifications /> },
          { path: "canary", element: <NexusCanary /> },
          { path: "aware", element: <NexusAware /> },
          { path: "atlas", element: <NexusAtlas /> },
          { path: "comply", element: <NexusComply /> },
          { path: "content-packs", element: <NexusContentPacks /> },
          { path: "replay", element: <NexusReplay /> },
          { path: "airgap", element: <NexusAirgap /> },
          { path: "syslog", element: <NexusSyslog /> },
        ],
      },
    ],
  },
]);