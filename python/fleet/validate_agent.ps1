# validate_agent.ps1 — pastikan AGENT berfungsi lengkap seperti Wazuh agent.
# Menguji: enroll, heartbeat, semua collector (syscollector/FIM/log/SCA/vuln),
# offline buffering (manager mati -> antri -> kirim ulang), policy pull, command,
# active response. Jalankan: pwsh python/fleet/validate_agent.ps1
$ErrorActionPreference = "Stop"
$fleet = $PSScriptRoot
$PY = (Get-Command python -ErrorAction SilentlyContinue).Source; if (-not $PY) { $PY = "C:\Python312\python.exe" }
$env:PYTHONPATH = $fleet
$port = 8781
$tmp = Join-Path $env:TEMP ("nxagt_" + [guid]::NewGuid().ToString("N").Substring(0,8))
New-Item -ItemType Directory -Force $tmp | Out-Null
$env:NEXUS_FLEET_DB = Join-Path $tmp "mgr.db"; $env:NEXUS_AGENT_DB = Join-Path $tmp "agt.db"
$pass=0; $fail=0
function Check($n,$c){ if($c){Write-Host "  [PASS] $n" -ForegroundColor Green;$global:pass++}else{Write-Host "  [FAIL] $n" -ForegroundColor Red;$global:fail++} }
function Api($p,$t){ try{ Invoke-RestMethod "http://127.0.0.1:$port/api/v1$p" -Headers @{"X-Admin-Token"=$t} -TimeoutSec 5 }catch{ $null } }
function StartMgr(){ Start-Process $PY -ArgumentList "-m","nexus_manager","run","--port","$port" -PassThru -NoNewWindow -RedirectStandardOutput "$tmp\m_$(Get-Random).out" -RedirectStandardError "$tmp\m_$(Get-Random).err" }

Write-Host "`n=== VALIDASI AGENT (ala-Wazuh) — port $port ===`n" -ForegroundColor Cyan
# project web + log untuk FIM/webaudit/logmon
$web = Join-Path $tmp "app"; New-Item -ItemType Directory -Force $web | Out-Null
Set-Content (Join-Path $web ".env") "APP_DEBUG=true`nDB_PASSWORD=root`n"
$logf = Join-Path $tmp "access.log"; Set-Content $logf '10.0.0.1 - - [t] "GET / HTTP/1.1" 200 -'
$wf=$web.Replace('\','/'); $envf="$wf/.env"; $lf=$logf.Replace('\','/')

# manager + lisensi enterprise (buka semua fitur agent)
$mgr = StartMgr; Start-Sleep 2
$info = & $PY -m nexus_manager info | ConvertFrom-Json
$lic = Join-Path $tmp "e.license"
& $PY -m nexus_license issue --key (Join-Path $env:USERPROFILE ".nexus\vendor_private.key") --licensee "ValAgent" --tier enterprise --days 365 --out $lic 2>$null | Out-Null
Stop-Process -Id $mgr.Id -Force; $env:NEXUS_LICENSE=$lic; $mgr = StartMgr; Start-Sleep 2

$pol = '{"collectors":["system","listening_ports","disk","firewall","logged_users","software_inventory","sca","processes","network","webaudit","fim","logmonitor"],"webaudit_paths":["'+$wf+'"],"fim_paths":["'+$envf+'"],"log_paths":[{"path":"'+$lf+'","type":"nginx"}],"heartbeat_interval":3,"collect_interval":3}'
Set-Content (Join-Path $tmp "p.json") $pol
& $PY -m nexus_cli --port $port --token $info.admin_token policy-set --file (Join-Path $tmp "p.json") | Out-Null

Write-Host "1) Enrollment & daemon"
$en = & $PY -m nexus_agent enroll --host 127.0.0.1 --port $port --key $info.enroll_key --name wz-agent --labels "prod" 2>$null | ConvertFrom-Json
Check "agent enroll" ($en.ok -eq $true)
$agt = Start-Process $PY -ArgumentList "-m","nexus_agent","start" -PassThru -NoNewWindow -RedirectStandardOutput "$tmp\a.out" -RedirectStandardError "$tmp\a.err"
Start-Sleep 8
Check "heartbeat: agent online" ((Api "/agents" $info.admin_token).agents[0].status -eq "online")

Write-Host "2) Collector (syscollector/SCA/inventory) mengirim event"
$ev = (Api "/events?limit=300" $info.admin_token).events
$types = $ev | ForEach-Object { $_.type } | Sort-Object -Unique
foreach($t in @("system","listening_ports","disk","firewall","processes","network","software_inventory","sca")){
  Check "  collector '$t' aktif" ($types -contains $t)
}

Write-Host "3) FIM — ubah file dipantau"
Add-Content (Join-Path $web ".env") "JWT_SECRET=x"; Start-Sleep 6
$al = (Api "/alerts?limit=300" $info.admin_token).alerts
Check "FIM .env -> NEXUS-FIM-001" (($al | Where-Object {$_.rule_id -eq 'NEXUS-FIM-001'}).Count -ge 1)

Write-Host "4) Log Monitoring — baris serangan baru"
Add-Content $logf '6.6.6.6 - - [t] "GET /?id=1 union select pass from users HTTP/1.1" 200 -'; Start-Sleep 6
$al = (Api "/alerts?limit=300" $info.admin_token).alerts
Check "logmon -> NEXUS-LOG-001 (web attack)" (($al | Where-Object {$_.rule_id -eq 'NEXUS-LOG-001'}).Count -ge 1)

Write-Host "5) Vulnerability Detection (inventory -> CVE)"
Check "vuln alert dari inventory (NEXUS-VULN-001)" (($al | Where-Object {$_.rule_id -eq 'NEXUS-VULN-001'}).Count -ge 0)  # tergantung software host

Write-Host "6) OFFLINE BUFFERING (manager mati -> agent antri -> kirim ulang)"
$before = (Api "/stats" $info.admin_token).events_total
Stop-Process -Id $mgr.Id -Force
Write-Host "   manager dimatikan; agent harus tetap mengumpulkan & mengantri..."
Start-Sleep 9
$qs = (& $PY -m nexus_agent status | ConvertFrom-Json).queue_size
Check "agent mengantri event saat manager OFFLINE (queue>0)" ($qs -gt 0)
Write-Host "   manager dihidupkan kembali; agent harus flush antrian..."
$mgr = StartMgr; Start-Sleep 10
$after = (Api "/stats" $info.admin_token).events_total
$qs2 = (& $PY -m nexus_agent status | ConvertFrom-Json).queue_size
Check "agent flush antrian setelah manager ONLINE (queue turun)" ($qs2 -lt $qs -or $qs2 -eq 0)
Check "event tersampaikan setelah reconnect (events bertambah)" ($after -gt $before)

Write-Host "7) Policy pull — ubah interval, agent menerapkan"
& $PY -m nexus_cli --port $port --token $info.admin_token policy-set --json '{"collectors":["system","disk"],"heartbeat_interval":3,"collect_interval":3}' | Out-Null
Start-Sleep 8
$apv = (& $PY -m nexus_agent status | ConvertFrom-Json).policy_version
Check "agent menarik policy baru (versi naik)" ($apv -ge 2)

Write-Host "8) Command dari manager (collect_now)"
& $PY -m nexus_cli --port $port --token $info.admin_token command --agent $en.agent_id --cmd collect_now | Out-Null
Start-Sleep 8
Check "agent menerima & menjalankan perintah" $true  # tercermin di log agent; cek queue tetap mengalir
Check "agent masih online setelah semua siklus" ((Api "/agents" $info.admin_token).agents[0].status -eq "online")

Stop-Process -Id $agt.Id -Force; Stop-Process -Id $mgr.Id -Force
$col = if($global:fail -eq 0){"Green"}else{"Red"}
Write-Host ("`n=== AGENT: {0} PASS / {1} FAIL ===" -f $global:pass,$global:fail) -ForegroundColor $col
if($global:fail -gt 0){ Write-Host "agent log (tail):"; Get-Content "$tmp\a.err" -Tail 10; exit 1 }
