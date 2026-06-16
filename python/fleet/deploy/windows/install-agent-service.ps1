# deploy/windows/install-agent-service.ps1
# Pasang Nexus Agent sebagai Scheduled Task yang jalan saat boot (SYSTEM).
# Jalankan sebagai Administrator. Enroll dulu sebelum ini:
#   python -m nexus_agent enroll --host <manager> --port 8765 --key <ENROLL_KEY>
param(
  [string]$FleetDir = (Resolve-Path "$PSScriptRoot\..\..").Path,   # folder python/fleet
  [string]$Python = "python",
  [string]$AgentDb = "C:\ProgramData\Nexus\fleet_agent.db"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force (Split-Path $AgentDb) | Out-Null

$action = New-ScheduledTaskAction -Execute $Python `
  -Argument "-m nexus_agent start" -WorkingDirectory $FleetDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

# PYTHONPATH agar paket nexus_* ditemukan
$env:PYTHONPATH = $FleetDir
Register-ScheduledTask -TaskName "NexusAgent" -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force
Write-Host "NexusAgent terpasang sebagai Scheduled Task (AtStartup). Mulai sekarang:"
Write-Host "  Start-ScheduledTask -TaskName NexusAgent"
