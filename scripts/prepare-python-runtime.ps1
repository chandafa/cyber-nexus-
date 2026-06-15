<#
.SYNOPSIS
  Siapkan runtime Python EMBEDDABLE yang akan di-bundle bersama Nexus.

.DESCRIPTION
  Tanpa runtime ini, aplikasi memanggil `python` dari PATH host — sehingga GAGAL
  di komputer yang belum memasang Python. Script ini mengunduh Python embeddable
  resmi, mengaktifkan pip + site-packages, lalu memasang dependency engine
  (requirements-runtime.txt). Hasilnya di `python-runtime/` (di-bundle via
  tauri.conf.json → resources) dan dipakai backend Rust (executor.rs python_exe()).

  Dipanggil oleh CI (.github/workflows/release.yml) sebelum `tauri build`.
  Bisa juga dijalankan manual sebelum `npm run tauri:build` untuk build lokal
  yang benar-benar portabel.

.PARAMETER PythonVersion
  Versi CPython embeddable (default 3.12.7).
#>
param(
  [string]$PythonVersion = "3.12.7"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root "python-runtime"
$reqFile = Join-Path $root "requirements-runtime.txt"

Write-Host "==> Menyiapkan Python runtime $PythonVersion di $dest" -ForegroundColor Cyan

if (Test-Path $dest) {
  Write-Host "    Membersihkan folder lama..."
  Remove-Item -Recurse -Force $dest
}
New-Item -ItemType Directory -Force -Path $dest | Out-Null

# 1. Unduh embeddable resmi (amd64).
$zipUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
$zipPath = Join-Path $env:TEMP "python-embed-$PythonVersion.zip"
Write-Host "==> Mengunduh $zipUrl"
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
Expand-Archive -Path $zipPath -DestinationPath $dest -Force
Remove-Item $zipPath -Force

# 2. Aktifkan `import site` + site-packages di file ._pth (wajib agar pip jalan).
$pth = Get-ChildItem -Path $dest -Filter "python*._pth" | Select-Object -First 1
if (-not $pth) { throw "File ._pth tidak ditemukan di runtime embeddable." }
Write-Host "==> Mengaktifkan site-packages di $($pth.Name)"
$lines = Get-Content $pth.FullName
$lines = $lines -replace '^\s*#\s*import site\s*$', 'import site'
if ($lines -notcontains 'import site') { $lines += 'import site' }
if ($lines -notcontains 'Lib\site-packages') { $lines += 'Lib\site-packages' }
Set-Content -Path $pth.FullName -Value $lines -Encoding ascii

$py = Join-Path $dest "python.exe"

# 3. Pasang pip (get-pip.py).
$getPip = Join-Path $env:TEMP "get-pip.py"
Write-Host "==> Memasang pip"
Invoke-WebRequest -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $getPip -UseBasicParsing
& $py $getPip --no-warn-script-location
Remove-Item $getPip -Force
if ($LASTEXITCODE -ne 0) { throw "Instalasi pip gagal." }

# 3b. Pasang setuptools + wheel. Python embeddable TIDAK menyertakannya dan
#     get-pip versi baru juga tidak — tanpa ini, paket sdist (mis. yang perlu
#     'setuptools.build_meta') akan GAGAL build. Wajib agar pip install stabil.
Write-Host "==> Memasang setuptools + wheel"
& $py -m pip install --no-warn-script-location --upgrade setuptools wheel
if ($LASTEXITCODE -ne 0) { throw "Instalasi setuptools/wheel gagal." }

# 4. Pasang dependency engine (subset aman untuk bundle — tanpa lib native berat).
#    --prefer-binary: utamakan wheel agar tidak perlu compile dari sdist.
if (Test-Path $reqFile) {
  Write-Host "==> Memasang dependency: $reqFile"
  & $py -m pip install --no-warn-script-location --prefer-binary -r $reqFile
  if ($LASTEXITCODE -ne 0) { throw "Instalasi dependency runtime gagal." }
} else {
  Write-Warning "requirements-runtime.txt tidak ditemukan — melewati instalasi paket."
}

# 5. Verifikasi cepat — semua dependency yang DI-IMPORT engine harus bisa di-load.
Write-Host "==> Verifikasi runtime"
& $py -c "import sys, jinja2, requests, apscheduler; print('Python', sys.version.split()[0], '| jinja2', jinja2.__version__, '| requests', requests.__version__, '| APScheduler', apscheduler.__version__)"
if ($LASTEXITCODE -ne 0) { throw "Verifikasi runtime gagal." }

Write-Host "==> Python runtime siap di $dest" -ForegroundColor Green
