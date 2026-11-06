@echo off
rem BONELIA AI - back up the home server before a format, in one double-click.
rem Copies what is NOT on GitHub to a USB stick / second drive (folder BONELIA-Yedek):
rem the server key every customer agent trusts, the database (customers, PCs, vault, settings),
rem the phone panel token, the local server.home.toml and this PC's Tailscale identity, each
rem checked with SHA-256. It also puts BONELIA-Format-Sonrasi-Kur.bat next to the backups:
rem after the format, double-click that file on the stick and everything comes back.
rem The PowerShell part follows the marker line below; it is read from this file, no extra .ps1 needed.
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
setlocal
cd /d "%~dp0..\.."
set "BONELIA_ROOT=%CD%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s = [IO.File]::ReadAllText('%~f0'); iex $s.Substring($s.IndexOf('#==PS' + '=='))"
set "RC=%ERRORLEVEL%"
if not defined CI pause
endlocal & exit /b %RC%

#==PS==
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
Import-Module Microsoft.PowerShell.Utility
function Say([string]$tr, [string]$de) { Write-Host $tr; if ($de) { Write-Host ('   ' + $de) -ForegroundColor DarkGray } }
function Fail([string]$tr) { Write-Host ''; Write-Host ('*** ' + $tr + ' ***') -ForegroundColor Red; exit 1 }

$root = $env:BONELIA_ROOT
$py = if ($env:BONELIA_PY) { $env:BONELIA_PY } else { Join-Path $root '.venv\Scripts\python.exe' }
if (-not (Test-Path $py)) { Fail 'BONELIA kurulumu bulunamadi (.venv yok). Once BONELIA-Kurulumu-Onar.bat calistirin.' }
$cfg = if ($env:BONELIA_CONFIG) { $env:BONELIA_CONFIG } else { Join-Path $root 'deployment\server.home.toml' }

# --- where to: given (BONELIA_BACKUP_DEST) or a USB stick / second drive
$dest = $env:BONELIA_BACKUP_DEST
if (-not $dest) {
  $c = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.Name -ne 'C:\' -and $_.AvailableFreeSpace -gt 300MB -and
        ($_.DriveType -eq 'Removable' -or $_.DriveType -eq 'Fixed' -or $_.DriveType -eq 'Network') })
  if ($c.Count -eq 0) { Fail 'USB bellek veya ikinci disk bulunamadi. Bir USB takip tekrar calistirin. / Kein USB-Stick gefunden.' }
  $pick = @($c | Where-Object { Test-Path (Join-Path $_.RootDirectory.FullName 'BONELIA-Yedek') })
  if ($pick.Count -ge 1) { $drive = $pick[0] }
  elseif ($c.Count -eq 1) { $drive = $c[0] }
  else {
    Say 'Yedek nereye yazilsin? / Wohin sichern?'
    foreach ($d in $c) { Write-Host ('  ' + $d.Name.Substring(0, 2) + '  ' + $d.VolumeLabel + '  (' + [math]::Round($d.AvailableFreeSpace / 1GB, 1) + ' GB bos)') }
    $l = (Read-Host 'Surucu harfi / Laufwerksbuchstabe (or. E)').Trim().TrimEnd(':').ToUpper()
    $drive = $c | Where-Object { $_.Name -eq ($l + ':\') } | Select-Object -First 1
    if (-not $drive) { Fail 'Gecersiz surucu.' }
  }
  $dest = Join-Path $drive.RootDirectory.FullName 'BONELIA-Yedek'
}
New-Item -ItemType Directory -Force $dest | Out-Null
Say ('Yedek hedefi / Ziel: ' + $dest)

# --- what this PC needs to come back exactly as it was
$info = @()
try { $st = (& $py -m bonelia agent-status) -join "`n" | ConvertFrom-Json; if ($st.device_id) { $info += "agent_device_id=$($st.device_id)" } } catch { }
$info += "root=$root"
$git = Get-Command git -ErrorAction SilentlyContinue
if ($git) {
  $repo = Split-Path $root -Parent
  try { $info += "branch=$((& git -C $repo rev-parse --abbrev-ref HEAD).Trim())" } catch { }
  try { $info += "repo_url=$((& git -C $repo remote get-url origin).Trim())" } catch { }
}
$info += "computer=$env:COMPUTERNAME"
$extras = @()
if (Test-Path $cfg) { $extras += "config/server.home.toml=$cfg" }
$ts = Join-Path $env:ProgramData 'Tailscale\server-state.conf'
if (Test-Path $ts) { $extras += "tailscale/server-state.conf=$ts" } else { Say 'Not: Tailscale kimligi bulunamadi; format sonrasi Tailscale''e yeniden giris gerekecek.' }

$a = @('-m', 'bonelia.server.backup', 'make', '--dest', $dest)
if (Test-Path $cfg) { $a += @('--config', $cfg) }
foreach ($x in $extras) { $a += @('--extra', $x) }
foreach ($x in $info) { $a += @('--info', $x) }
Say 'Yedekleniyor ve her dosya kontrol ediliyor... / Sichere und pruefe...'
$out = (& $py @a) -join "`n"
$r = $out | ConvertFrom-Json
if (-not $r.ok) { Fail ('Yedek alinamadi: ' + $r.error) }

$restore = Join-Path $root 'deployment\windows\BONELIA-Format-Sonrasi-Kur.bat'
if (Test-Path $restore) { Copy-Item -Force $restore (Join-Path $dest 'BONELIA-Format-Sonrasi-Kur.bat') }

Write-Host ''
Write-Host '================================================================' -ForegroundColor Green
Say ('YEDEK HAZIR: ' + $r.folder) ('Sicherung fertig.')
Say 'Format sonrasi: bu USB''yi takin, BONELIA-Yedek klasorundeki'
Say 'BONELIA-Format-Sonrasi-Kur.bat dosyasina cift tiklayin. Gerisi kendiliginden.'
Say 'DIKKAT: bu yedekte sunucunun anahtari var. USB''yi guvenli yerde saklayin.'
Write-Host '================================================================' -ForegroundColor Green
exit 0
