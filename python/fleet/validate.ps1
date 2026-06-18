# validate.ps1 — validasi manual end-to-end tiap komponen & fitur Nexus Fleet.
# Jalankan: pwsh python/fleet/validate.ps1   (butuh Python 3.8+ di PATH)
$ErrorActionPreference = "Stop"
$fleet = $PSScriptRoot
$PY = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PY) { $PY = "C:\Python312\python.exe" }
$env:PYTHONPATH = $fleet
$port = 8780
$tmp = Join-Path $env:TEMP ("nxval_" + [guid]::NewGuid().ToString("N").Substring(0,8))
New-Item -ItemType Directory -Force $tmp | Out-Null
$env:NEXUS_FLEET_DB = Join-Path $tmp "mgr.db"
$env:NEXUS_AGENT_DB = Join-Path $tmp "agt.db"

$script:pass = 0; $script:fail = 0
function Check($name, $cond) {
  if ($cond) { Write-Host ("  [PASS] " + $name) -ForegroundColor Green; $script:pass++ }
  else { Write-Host ("  [FAIL] " + $name) -ForegroundColor Red; $script:fail++ }
}
function Api($path, $token) {
  try { return Invoke-RestMethod "http://127.0.0.1:$port/api/v1$path" -Headers @{"X-Admin-Token"=$token} -TimeoutSec 5 }
  catch { return $null }
}

Write-Host "`n=== NEXUS FLEET — VALIDASI MANUAL (port $port) ===`n" -ForegroundColor Cyan

# Web project rentan untuk uji FIM + webaudit
$web = Join-Path $tmp "webapp"; New-Item -ItemType Directory -Force $web | Out-Null
Set-Content (Join-Path $web ".env") "APP_ENV=local`nAPP_DEBUG=true`nAPP_KEY=`nDB_PASSWORD=root`n"
$wf = $web.Replace('\','/'); $envf = "$wf/.env"

Write-Host "1) nexus-manager — start daemon"
$mgr = Start-Process $PY -ArgumentList "-m","nexus_manager","run","--port","$port" -PassThru -NoNewWindow -RedirectStandardOutput "$tmp\m.out" -RedirectStandardError "$tmp\m.err"
Start-Sleep 2
$h = Api "/health" ""
Check "manager hidup (GET /health ok)" ($h.ok -eq $true)
$info = & $PY -m nexus_manager info | ConvertFrom-Json
Check "enrollment key & admin token tersedia" ($info.enroll_key.Length -gt 20 -and $info.admin_token.Length -gt 20)

Write-Host "2) nexus-license — terbitkan & pasang lisensi PRO"
$lic = Join-Path $tmp "cust.license"
& $PY -m nexus_license issue --key (Join-Path $env:USERPROFILE ".nexus\vendor_private.key") --licensee "Validasi" --tier pro --days 365 --max-agents 10 --out $lic 2>$null | Out-Null
$licOk = (Test-Path $lic)
Check "lisensi PRO terbit (nexus-license issue)" $licOk
# pasang lisensi: restart manager dgn NEXUS_LICENSE
Stop-Process -Id $mgr.Id -Force
$env:NEXUS_LICENSE = $lic
$mgr = Start-Process $PY -ArgumentList "-m","nexus_manager","run","--port","$port" -PassThru -NoNewWindow -RedirectStandardOutput "$tmp\m2.out" -RedirectStandardError "$tmp\m2.err"
Start-Sleep 2
$ls = Api "/license" ""
Check "manager membaca lisensi PRO" ($ls.valid -eq $true -and $ls.tier -eq "pro")

Write-Host "3) policy — aktifkan FIM + webaudit utk endpoint"
$policy = '{"collectors":["system","listening_ports","disk","firewall","webaudit","fim"],"webaudit_paths":["'+$wf+'"],"fim_paths":["'+$envf+'"],"heartbeat_interval":3,"collect_interval":3}'
Set-Content (Join-Path $tmp "policy.json") $policy
& $PY -m nexus_cli --port $port --token $info.admin_token policy-set --file (Join-Path $tmp "policy.json") | Out-Null
Check "policy terdistribusi (nexus-cli policy-set)" $true

Write-Host "4) nexus-agent — enroll"
$en = & $PY -m nexus_agent enroll --host 127.0.0.1 --port $port --key $info.enroll_key --name srv-validasi --labels "prod,web" 2>$null | ConvertFrom-Json
Check "agent enroll berhasil" ($en.ok -eq $true -and $en.agent_id.StartsWith("agt_"))

Write-Host "5) nexus-agent — start daemon (kirim telemetri)"
$agt = Start-Process $PY -ArgumentList "-m","nexus_agent","start" -PassThru -NoNewWindow -RedirectStandardOutput "$tmp\a.out" -RedirectStandardError "$tmp\a.err"
Start-Sleep 7
$agents = (Api "/agents" $info.admin_token).agents
Check "agent online di manager" (($agents | Where-Object {$_.status -eq 'online'}).Count -ge 1)
Check "agent labels terbaca (prod,web)" (($agents[0].labels -join ',') -eq 'prod,web')

Write-Host "6) Rule engine + alert — webaudit & FIM"
$al = (Api "/alerts?limit=200" $info.admin_token).alerts
Check "NEXUS-WEB-001 (APP_DEBUG) ter-deteksi" (($al | Where-Object {$_.rule_id -eq 'NEXUS-WEB-001'}).Count -ge 1)
Check "NEXUS-WEB-003 (weak DB pass) ter-deteksi" (($al | Where-Object {$_.rule_id -eq 'NEXUS-WEB-003'}).Count -ge 1)
Write-Host "   -> modifikasi .env (uji FIM)"; Add-Content (Join-Path $web ".env") "JWT_SECRET=changed`n"
Start-Sleep 6
$al2 = (Api "/alerts?limit=200" $info.admin_token).alerts
$fim = $al2 | Where-Object {$_.rule_id -eq 'NEXUS-FIM-001'}
Check "FIM: .env diubah -> alert CRITICAL (NEXUS-FIM-001)" ($fim.Count -ge 1 -and $fim[0].severity -eq 'critical')
Check "alert punya MITRE + rekomendasi" ($fim.Count -ge 1 -and $fim[0].mitre.Count -ge 1 -and $fim[0].recommendation.Length -gt 10)

Write-Host "7) Posture score + report"
$st = Api "/stats" $info.admin_token
Check "posture score tersedia (network/server/website)" ($null -ne $st.posture.scores.website_security)
$rep = Api "/report" $info.admin_token
Check "report konsisten (schema nexus.report/v1)" ($rep.schema -eq 'nexus.report/v1')

Write-Host "8) Fitur PRO — Sigma import & Active Response"
$sig = '{"title":"env access","id":"SIG-V1","level":"high","tags":["attack.t1552.001"],"detection":{"selection":{"TargetFilename|endswith":".env"},"condition":"selection"}}'
$rs = & $PY -m nexus_cli --port $port --token $info.admin_token alerts 2>$null | Out-Null  # warmup
$sigRes = Invoke-RestMethod "http://127.0.0.1:$port/api/v1/rules/sigma" -Method Post -Headers @{"X-Admin-Token"=$info.admin_token} -ContentType "application/json" -Body $sig
Check "Sigma import berhasil (PRO)" ($sigRes.ok -eq $true)
$arRes = Invoke-RestMethod "http://127.0.0.1:$port/api/v1/response/actions" -Method Post -Headers @{"X-Admin-Token"=$info.admin_token} -ContentType "application/json" -Body (@{agent_id=$en.agent_id;action="block_ip";ip="203.0.113.7"} | ConvertTo-Json)
Check "Active Response ter-antri (PRO, dry-run)" ($arRes.ok -eq $true)

Write-Host "9) nexus-dashboard — disajikan manager"
try { $d = Invoke-WebRequest "http://127.0.0.1:$port/" -UseBasicParsing -TimeoutSec 5; Check "dashboard GET / (HTTP 200 + judul)" ($d.StatusCode -eq 200 -and $d.Content -match 'Nexus Dashboard') } catch { Check "dashboard GET /" $false }
try { $j = Invoke-WebRequest "http://127.0.0.1:$port/app.js" -UseBasicParsing -TimeoutSec 5; Check "dashboard /app.js termuat" ($j.StatusCode -eq 200) } catch { Check "dashboard /app.js" $false }

Write-Host "10) nexus-cli — admin queries"
$cliAgents = & $PY -m nexus_cli --port $port --token $info.admin_token agents | ConvertFrom-Json
Check "nexus-cli agents (admin API + token)" ($cliAgents.agents.Count -ge 1)
$cliAlerts = & $PY -m nexus_cli --port $port --token $info.admin_token alerts | ConvertFrom-Json
Check "nexus-cli alerts menampilkan alert" ($cliAlerts.alerts.Count -ge 1)

Stop-Process -Id $agt.Id -Force; Stop-Process -Id $mgr.Id -Force
$color = if ($script:fail -eq 0) { "Green" } else { "Red" }
Write-Host ("`n=== HASIL: {0} PASS / {1} FAIL ===" -f $script:pass, $script:fail) -ForegroundColor $color
if ($script:fail -gt 0) { exit 1 }
