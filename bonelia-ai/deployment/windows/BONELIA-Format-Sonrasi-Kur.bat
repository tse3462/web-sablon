@echo off
rem BONELIA AI - bring the home server back after a format, in one double-click.
rem Run it from the USB stick (BONELIA-Yedek folder written by BONELIA-Yedekle.bat). It:
rem  1. finds the newest backup and checks every file (SHA-256); a damaged backup is never used
rem  2. installs Git, Python, Tailscale, RustDesk and Ollama with winget (skips what is there)
rem  3. puts this PC's Tailscale identity back, so customer PCs find the server at the same address
rem  4. downloads BONELIA AI from GitHub into the same folder as before
rem  5. puts the server data back (server key, database, panel token, server.home.toml)
rem  6. creates the Python environment, sets up hidden autostart and starts server + phone panel
rem  7. loads the AI model and re-registers this PC's own agent (the old entry is revoked)
rem The PowerShell part follows the marker line below; it is read from this file, no extra .ps1 needed.
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
setlocal
set "BONELIA_SELF_DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s = [IO.File]::ReadAllText('%~f0'); iex $s.Substring($s.IndexOf('#==PS' + '=='))"
set "RC=%ERRORLEVEL%"
if not defined CI pause
endlocal & exit /b %RC%

#==PS==
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
Import-Module Microsoft.PowerShell.Utility, Microsoft.PowerShell.Management
$ProgressPreference = 'SilentlyContinue'
function Say([string]$tr, [string]$de) { Write-Host $tr; if ($de) { Write-Host ('   ' + $de) -ForegroundColor DarkGray } }
function Step([string]$t) { Write-Host ''; Write-Host ('== ' + $t) -ForegroundColor Cyan }
function Fail([string]$tr) { Write-Host ''; Write-Host ('*** ' + $tr + ' ***') -ForegroundColor Red; Say 'Ekranin fotografini Claude''a gonderin.'; exit 1 }
function RefreshPath { $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User') }
$todo = New-Object System.Collections.ArrayList

# ---------- 1. the newest backup, checked file by file
Step '1/7 Yedek araniyor ve kontrol ediliyor / Sicherung suchen und pruefen'
function Latest([string]$dir) {
  if (-not $dir -or -not (Test-Path $dir)) { return $null }
  Get-ChildItem -Directory $dir -Filter 'sunucu-*' | Where-Object { Test-Path (Join-Path $_.FullName 'manifest.json') } |
    Sort-Object Name | Select-Object -Last 1
}
$bk = $null
if ($env:BONELIA_BACKUP) { $bk = Get-Item $env:BONELIA_BACKUP }
if (-not $bk) { $bk = Latest $env:BONELIA_SELF_DIR }
if (-not $bk) {
  foreach ($d in [IO.DriveInfo]::GetDrives()) {
    if (-not $d.IsReady) { continue }
    $f = Latest (Join-Path $d.RootDirectory.FullName 'BONELIA-Yedek')
    if ($f -and (-not $bk -or $f.Name -gt $bk.Name)) { $bk = $f }
  }
}
$man = $null
if ($bk) {
  $man = Get-Content -Raw (Join-Path $bk.FullName 'manifest.json') | ConvertFrom-Json
  foreach ($p in $man.files.PSObject.Properties) {
    $f = Join-Path $bk.FullName ($p.Name -replace '/', '\')
    if (-not (Test-Path $f) -or (Get-FileHash -Algorithm SHA256 $f).Hash.ToLower() -ne $p.Value) { Fail ('Yedek bozuk: ' + $p.Name + ' - bu yedek kullanilmaz.') }
  }
  Say ('Yedek: ' + $bk.FullName + '  (' + $man.created + ', saglam)')
} else {
  Say 'YEDEK BULUNAMADI. Devam edilirse YENI ve BOS bir sunucu kurulur:' 'Keine Sicherung gefunden.'
  Say 'musteri bilgisayarlarinin hepsine USB ile yeniden kurulum gerekir.'
  if ($env:CI -or (Read-Host 'Yine de devam edilsin mi? (E/H)').Trim().ToUpper() -ne 'E') { exit 1 }
}
$info = if ($man -and $man.info) { $man.info } else { [pscustomobject]@{} }

$root = if ($env:BONELIA_ROOT) { $env:BONELIA_ROOT } elseif ($info.root) { $info.root } else { 'C:\BoneliaAI\web-sablon\bonelia-ai' }
$repo = Split-Path $root -Parent
$branch = if ($info.branch -and $info.branch -ne 'HEAD') { $info.branch } else { 'claude/bonelia-ai-architecture-z57jp0' }
$url = if ($info.repo_url) { $info.repo_url } else { 'https://github.com/tse3462/web-sablon.git' }
$cfgBackup = if ($bk) { Join-Path $bk.FullName 'extras\config\server.home.toml' } else { '' }
$dataDir = 'C:\BoneliaAI\server-data'
if ($cfgBackup -and (Test-Path $cfgBackup)) {
  $m = Select-String -Path $cfgBackup -Pattern '^\s*data_dir\s*=\s*"([^"]+)"' | Select-Object -First 1
  if ($m) { $dataDir = $m.Matches[0].Groups[1].Value -replace '/', '\' }
}
if ($env:BONELIA_DATA_DIR) { $dataDir = $env:BONELIA_DATA_DIR }

function RestoreData {
  if (-not $bk) { return }
  $key = Join-Path $dataDir 'server_ed25519.key'
  $mine = Join-Path $bk.FullName 'data\server_ed25519.key'
  if ((Test-Path $key) -and ((Get-FileHash $key).Hash -ne (Get-FileHash $mine).Hash)) {
    $aside = $dataDir + '.onceki-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
    Move-Item $dataDir $aside
    Say ('Bu bilgisayarda baska bir sunucu verisi vardi; kenara alindi: ' + $aside)
  }
  New-Item -ItemType Directory -Force $dataDir | Out-Null
  Copy-Item -Force (Join-Path $bk.FullName 'data\*') $dataDir
  Say ('Sunucu verisi geri yuklendi: ' + $dataDir)
}

if ($env:BONELIA_ONLY_DATA) {  # (used by the automatic test) only check and put the data back
  RestoreData
  exit 0
}

# ---------- 2. programs
Step '2/7 Programlar kuruluyor (winget) / Programme installieren'
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { Fail 'winget yok: Microsoft Store''dan "App Installer" kurun, sonra tekrar calistirin.' }
function WinGet([string]$id, [scriptblock]$have) {
  if (& $have) { Say ('  var: ' + $id); return }
  Say ('  kuruluyor: ' + $id + ' ...')
  & winget install -e --id $id --silent --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Null
  RefreshPath
  if (-not (& $have)) { [void]$todo.Add($id + ' kurulamadi - elle kurun') }
}
function FindPython {
  $c = @("$env:LocalAppData\Python\pythoncore-3.14-64\python.exe", "$env:ProgramFiles\Python314\python.exe",
         "$env:LocalAppData\Programs\Python\Python314\python.exe", "$env:ProgramFiles\Python313\python.exe",
         "$env:LocalAppData\Programs\Python\Python313\python.exe")
  foreach ($p in $c) { if (Test-Path $p) { return $p } }
  $g = Get-Command python.exe -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike '*WindowsApps*' } | Select-Object -First 1
  if ($g) { return $g.Source }
  return $null
}
$gitExe = 'C:\Program Files\Git\cmd\git.exe'
WinGet 'Git.Git' { Test-Path $gitExe }
WinGet 'Python.Python.3.14' { [bool](FindPython) }
WinGet 'Tailscale.Tailscale' { Test-Path "$env:ProgramFiles\Tailscale\tailscale.exe" }
WinGet 'RustDesk.RustDesk' { (Test-Path "$env:ProgramFiles\RustDesk\rustdesk.exe") }
WinGet 'Ollama.Ollama' { (Test-Path "$env:LocalAppData\Programs\Ollama\ollama.exe") -or [bool](Get-Command ollama -ErrorAction SilentlyContinue) }
$basePy = FindPython
if (-not $basePy) { Fail 'Python bulunamadi.' }
if (-not (Test-Path $gitExe)) { $g = Get-Command git -ErrorAction SilentlyContinue; if ($g) { $gitExe = $g.Source } else { Fail 'Git bulunamadi.' } }

# ---------- 3. Tailscale identity (same address for the customer PCs)
Step '3/7 Tailscale kimligi / Tailscale-Identitaet'
$tsState = if ($bk) { Join-Path $bk.FullName 'extras\tailscale\server-state.conf' } else { '' }
if ($tsState -and (Test-Path $tsState)) {
  $svc = Get-Service Tailscale -ErrorAction SilentlyContinue
  if ($svc) { Stop-Service Tailscale -Force -ErrorAction SilentlyContinue; Start-Sleep 2 }
  New-Item -ItemType Directory -Force "$env:ProgramData\Tailscale" | Out-Null
  Copy-Item -Force $tsState "$env:ProgramData\Tailscale\server-state.conf"
  if ($svc) { Start-Service Tailscale -ErrorAction SilentlyContinue }
  Say 'Tailscale eski kimligiyle geri geldi (ayni adres).'
  [void]$todo.Add('Tailscale: gorev cubugundaki simgede bagli oldugunu ve adresin eskisiyle ayni (100.x...) oldugunu kontrol edin')
} else {
  [void]$todo.Add('Tailscale: simgeden giris yapin; yonetim panelinde eski bilgisayari silip yeni bilgisayara eski 100.x adresini verin (Edit IP)')
}

# ---------- 4. BONELIA AI from GitHub
Step '4/7 BONELIA AI GitHub''dan indiriliyor / von GitHub laden'
if (-not (Test-Path (Join-Path $repo '.git'))) {
  New-Item -ItemType Directory -Force (Split-Path $repo -Parent) | Out-Null
  & $gitExe clone --branch $branch $url $repo
  if ($LASTEXITCODE -ne 0) { Fail 'GitHub''dan indirilemedi.' }
} else {
  & $gitExe -C $repo pull --ff-only
}
if (-not (Test-Path (Join-Path $root 'pyproject.toml'))) { Fail ('Program klasoru bulunamadi: ' + $root) }

# ---------- 5. server data and settings
Step '5/7 Sunucu verisi geri yukleniyor / Serverdaten zurueck'
RestoreData
$cfg = Join-Path $root 'deployment\server.home.toml'
if ($cfgBackup -and (Test-Path $cfgBackup)) { Copy-Item -Force $cfgBackup $cfg; Say 'server.home.toml geri yuklendi.' }
New-Item -ItemType Directory -Force 'C:\BoneliaAI' | Out-Null

# ---------- 6. Python environment, autostart, start
Step '6/7 Calisma ortami kuruluyor ve baslatiliyor / Umgebung und Start'
$vpy = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path $vpy)) { & $basePy -m venv (Join-Path $root '.venv') }
if (-not (Test-Path $vpy)) { Fail '.venv olusturulamadi.' }
Push-Location $root
& $vpy -m pip install --upgrade pip | Out-Null
& $vpy -m pip install -e '.[server]'
$ok = $LASTEXITCODE
Pop-Location
if ($ok -ne 0) { Fail 'BONELIA kurulamadi (pip).' }
$env:CI = '1'  # the helper scripts below must not wait for a key press
& cmd /c (Join-Path $root 'deployment\windows\BONELIA-Kur-Otomatik.bat')
$up = $false
for ($i = 0; $i -lt 30; $i++) {
  try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 'http://127.0.0.1:8742/v1/health' | Out-Null; $up = $true; break } catch { Start-Sleep 2 }
}
if ($up) { Say 'Sunucu calisiyor.' } else { [void]$todo.Add('Sunucu baslamadi: BONELIA-Server-Baslat.bat calistirin') }

# ---------- 7. AI model and this PC's own agent
Step '7/7 Yapay zeka modeli ve bu bilgisayarin ajani / KI-Modell und Agent'
$model = 'qwen2.5:3b-instruct'
$mm = Select-String -Path $cfg -Pattern '^\s*ollama_model\s*=\s*"([^"]+)"' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($mm) { $model = $mm.Matches[0].Groups[1].Value }
$ol = "$env:LocalAppData\Programs\Ollama\ollama.exe"
if (-not (Test-Path $ol)) { $g = Get-Command ollama -ErrorAction SilentlyContinue; if ($g) { $ol = $g.Source } }
if (Test-Path $ol) {
  try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 'http://127.0.0.1:11434' | Out-Null } catch { Start-Process $ol -ArgumentList 'serve' -WindowStyle Hidden; Start-Sleep 4 }
  Say ('Model indiriliyor: ' + $model + ' (birkac dakika)')
  & $ol pull $model
  if ($LASTEXITCODE -ne 0) { [void]$todo.Add('Yapay zeka modeli: komut satirinda "ollama pull ' + $model + '"') }
} else { [void]$todo.Add('Ollama kurulamadi: ollama.com''dan kurun') }

if ($info.agent_device_id -and $up) {
  $r = (& $vpy -m bonelia.server.cli --config $cfg replace-agent $info.agent_device_id) -join "`n" | ConvertFrom-Json
  & $vpy -m bonelia agent-install --code $r.code --server 'http://127.0.0.1:8742' --label $r.label --yes --no-start | Out-Null
  & cmd /c ('echo.| "' + (Join-Path $root 'deployment\windows\BONELIA-Ajan-Onar.bat') + '"')
  Say ('Bu bilgisayarin ajani yeniden kaydedildi: ' + $r.label + ' (eski kayit iptal edildi)')
} elseif (-not $info.agent_device_id) {
  [void]$todo.Add('Bu bilgisayarda ajan yoktu; isterseniz USB''deki Bu-Bilgisayara-Kur.bat ve sonra BONELIA-Ajan-Onar.bat')
}

Write-Host ''
Write-Host '================================================================' -ForegroundColor Green
Say 'BITTI. Sunucu, telefon paneli ve musteri bilgisayarlari eskisi gibi.' 'Fertig.'
Say 'Telefondaki panel adresi ayni kaldi (anahtar geri yuklendi).'
if ($todo.Count) { Write-Host ''; Say 'Elle bakilacaklar:'; foreach ($t in $todo) { Say (' - ' + $t) } }
Say ' - RustDesk yeni bir ID alir; Kasa''daki sifresini ajan birkac dakika icinde kendisi yeniler.'
Write-Host '================================================================' -ForegroundColor Green
exit 0
