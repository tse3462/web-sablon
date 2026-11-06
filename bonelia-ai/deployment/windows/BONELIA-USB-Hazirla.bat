@echo off
rem BONELIA AI - prepare the USB stick for customer installs, in one double-click (on the owner's PC).
rem Finds the USB (BONELIA-AI-Portable folder), downloads the Tailscale installer (signature checked)
rem and, if missing, the RustDesk installer (checked against GitHub's published SHA-256), then opens
rem the Tailscale key page and saves the pasted key as config\tailscale-authkey.txt.
rem The PowerShell part follows the marker line below; it is read from this file, no extra .ps1 needed.
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s = [IO.File]::ReadAllText('%~f0'); iex $s.Substring($s.IndexOf('#==PS' + '=='))"
set "RC=%ERRORLEVEL%"
if not defined CI pause
endlocal & exit /b %RC%

#==PS==
$ErrorActionPreference = 'Stop'
# Started from PowerShell 7 the module path points at its modules, which Windows PowerShell cannot load.
$env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
Import-Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Say([string]$tr, [string]$de) { Write-Host $tr; if ($de) { Write-Host ('   ' + $de) -ForegroundColor DarkGray } }

# --- the USB folder: given (BONELIA_USB) or found on any drive
$root = $env:BONELIA_USB
if (-not $root) {
  foreach ($d in [IO.DriveInfo]::GetDrives()) {
    if (-not $d.IsReady) { continue }
    $p = Join-Path $d.RootDirectory.FullName 'BONELIA-AI-Portable'
    if (Test-Path (Join-Path $p 'Bu-Bilgisayara-Kur.bat')) { $root = $p; break }
  }
}
if (-not $root -or -not (Test-Path $root)) {
  Say 'USB bulunamadi: BONELIA-AI-Portable klasoru olan USB yi takip tekrar deneyin.' 'USB nicht gefunden: USB-Stick mit dem Ordner BONELIA-AI-Portable einstecken.'
  exit 1
}
Say ('USB: ' + $root)
foreach ($sub in 'tailscale', 'rustdesk', 'config') { New-Item -ItemType Directory -Force (Join-Path $root $sub) | Out-Null }
$ok = $true

# --- 1) Tailscale installer (MSI), only from pkgs.tailscale.com and only with Tailscale's valid signature
$tsDir = Join-Path $root 'tailscale'
if (Get-ChildItem $tsDir -Filter '*.msi' -ErrorAction SilentlyContinue) {
  Say '1) Tailscale kurulum dosyasi zaten var.' 'Tailscale-Installer ist schon da.'
} else {
  try {
    $page = (Invoke-WebRequest 'https://pkgs.tailscale.com/stable/' -UseBasicParsing).Content
    $name = ([regex]::Matches($page, 'tailscale-setup-[0-9.]+-amd64\.msi') | Select-Object -First 1).Value
    if (-not $name) { throw 'MSI not listed' }
    $file = Join-Path $tsDir $name
    Invoke-WebRequest ('https://pkgs.tailscale.com/stable/' + $name) -OutFile $file -UseBasicParsing
    $sig = Get-AuthenticodeSignature $file
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Tailscale') {
      Remove-Item $file -Force
      throw ('signature ' + $sig.Status + ' ' + $sig.SignerCertificate.Subject)
    }
    Say ('1) Tailscale indirildi, imzasi dogru: ' + $name) 'Tailscale geladen, Signatur geprueft.'
  } catch {
    $ok = $false
    Say ('1) Tailscale indirilemedi: ' + $_.Exception.Message) 'Elle: https://pkgs.tailscale.com/stable/ -> amd64 .msi in den Ordner tailscale legen.'
  }
}

# --- 2) RustDesk installer (MSI), if missing: latest GitHub release, checked against its SHA-256
$rdDir = Join-Path $root 'rustdesk'
if (Get-ChildItem $rdDir -Filter '*.msi' -ErrorAction SilentlyContinue) {
  Say '2) RustDesk kurulum dosyasi zaten var.' 'RustDesk-Installer ist schon da.'
} else {
  try {
    $h = @{ 'User-Agent' = 'BONELIA-AI'; 'Accept' = 'application/vnd.github+json' }
    if ($env:GITHUB_TOKEN) { $h['Authorization'] = 'Bearer ' + $env:GITHUB_TOKEN }
    $rel = Invoke-RestMethod 'https://api.github.com/repos/rustdesk/rustdesk/releases/latest' -Headers $h
    $asset = $rel.assets | Where-Object { $_.name -match '^rustdesk-[0-9.]+-x86_64\.msi$' } | Select-Object -First 1
    if (-not $asset) { throw 'MSI not in the latest release' }
    $m = [regex]::Match([string]$asset.digest, '^sha256:([0-9a-f]{64})$')
    if (-not $m.Success) { throw 'no SHA-256 published' }
    $want = $m.Groups[1].Value
    $file = Join-Path $rdDir $asset.name
    Invoke-WebRequest $asset.browser_download_url -OutFile $file -UseBasicParsing
    if ((Get-FileHash $file -Algorithm SHA256).Hash.ToLower() -ne $want) { Remove-Item $file -Force; throw 'SHA-256 mismatch' }
    Say ('2) RustDesk indirildi, dogrulandi: ' + $asset.name) 'RustDesk geladen, SHA-256 geprueft.'
  } catch {
    $ok = $false
    Say ('2) RustDesk indirilemedi: ' + $_.Exception.Message) 'Elle: github.com/rustdesk/rustdesk/releases -> x86_64 .msi in den Ordner rustdesk legen.'
  }
}

# --- 3) Tailscale key: the owner creates it in the Tailscale account, pastes it here once
$keyFile = Join-Path $root 'config\tailscale-authkey.txt'
$have = (Test-Path $keyFile) -and ([IO.File]::ReadAllText($keyFile) -match 'tskey-auth-')
if ($have -and -not $env:BONELIA_TS_KEY) {
  Say '3) Tailscale anahtari zaten var (90 gunde bir yenileyin).' 'Tailscale-Schluessel ist schon da (alle 90 Tage erneuern).'
} else {
  $key = $env:BONELIA_TS_KEY
  if (-not $key) {
    Write-Host ''
    Say '3) Tailscale anahtari: tarayicida Tailscale sayfasi aciliyor.' 'Tailscale-Schluessel: die Tailscale-Seite oeffnet sich im Browser.'
    Say '   Generate auth key -> Reusable: AN, Ephemeral: AUS, Pre-approved: AN -> Generate -> Kopieren.'
    Start-Process 'https://login.tailscale.com/admin/settings/keys'
    $key = Read-Host '   Anahtari buraya yapistirin ve Enter / Schluessel einfuegen und Enter'
  }
  $key = ([string]$key).Trim()
  if ($key -match '^tskey-auth-[A-Za-z0-9_-]+$') {
    [IO.File]::WriteAllText($keyFile, $key)
    Say '3) Tailscale anahtari USB ye kaydedildi.' 'Tailscale-Schluessel gespeichert.'
  } else {
    $ok = $false
    Say '3) Bu bir Tailscale anahtari degil (tskey-auth- ile baslamali). Dosyayi tekrar calistirin.' 'Kein Tailscale-Schluessel (beginnt mit tskey-auth-).'
  }
}

Write-Host ''
if ($ok) {
  Say 'USB HAZIR. Musteri bilgisayarinda: Bu-Bilgisayara-Kur -> Tailscale, RustDesk ve BONELIA birlikte kurulur.' 'USB FERTIG.'
  exit 0
}
Say 'Bazi adimlar tamamlanamadi; yukaridaki satirlara bakin.' 'Nicht alles erledigt; siehe oben.'
exit 1
