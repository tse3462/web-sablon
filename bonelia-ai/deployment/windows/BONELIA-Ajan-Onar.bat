@echo off
rem Starts the background agent on the OWNER'S OWN PC and makes it auto-start at every logon.
rem
rem Why not the normal SYSTEM task: this PC's Python 3.14 lives in the user's profile
rem (PyManager), which the SYSTEM account cannot launch -- so the SYSTEM agent task never
rem runs and the PC shows red. Instead we run the agent as the logged-in user WITH admin
rem rights (/RL HIGHEST /IT): that Python works for the user, and HIGHEST still gives the
rem rights needed to write C:\ProgramData and perform admin repairs.
rem
rem Needs admin, so it self-elevates (click "Ja"/"Yes").
rem /auto: called by the hidden update task, which already runs with admin rights: no window, no question.
set "BONELIA_AUTO="
if /i "%~1"=="/auto" set "BONELIA_AUTO=1"
net session >nul 2>&1 || (if defined BONELIA_AUTO (exit /b 2) else (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b))
cd /d "%~dp0..\.."
set "ROOT=%CD%"
set "PY=%ROOT%\.venv\Scripts\python.exe"
set "PYW=%ROOT%\.venv\Scripts\pythonw.exe"

if not exist "%PY%" (
  echo .venv bulunamadi. Once BONELIA-Kurulumu-Onar.bat calistirin.
  if not defined BONELIA_AUTO pause
  exit /b 1
)

echo [1/5] Sunucu ve panel calisiyor mu kontrol ediliyor...
call "%~dp0BONELIA-Server-Baslat.bat" /quiet
call "%~dp0BONELIA-Panel-Baslat.bat" /quiet

echo.
echo [2/5] Onceki ajan surecleri durduruluyor (cift calismasin)...
schtasks /End /TN "BONELIA AI Agent" >nul 2>&1
rem Stop only our own agent process(es), not other Python apps.
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='pythonw.exe' OR Name='python.exe'\" | Where-Object { $_.CommandLine -like '*bonelia*agent*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1

echo.
echo [3/5] Ajan SIMDI surekli calisacak sekilde baslatiliyor (yonetici, arka plan)...
rem Detached, windowless, elevated (inherits this admin window). Stays alive and heartbeats
rem every 5 min, so the PC stays GREEN -- not just a one-off cycle.
start "BONELIA-AGENT" /min "%PYW%" -m bonelia agent

echo.
echo [4/5] Her acilista otomatik baslatma ayarlaniyor (bu kullanici + yonetici, gizli)...
schtasks /Delete /F /TN "BONELIA AI Agent" >nul 2>&1
schtasks /Create /F /TN "BONELIA AI Agent" /SC ONLOGON /RL HIGHEST /IT /TR "\"%PYW%\" -m bonelia agent"
powershell -NoProfile -Command "try{$t=Get-ScheduledTask -TaskName 'BONELIA AI Agent' -ErrorAction Stop; $t.Settings.Hidden=$true; Set-ScheduledTask -InputObject $t | Out-Null}catch{}" >nul 2>&1
rem Automatic update (07.11.2026): every 30 minutes a hidden look at GitHub; updates only to tested code.
powershell -NoProfile -Command "try{$w=Join-Path '%~dp0' 'gizli-calistir.vbs'; $u=Join-Path '%~dp0' 'BONELIA-Server-Guncelle.bat'; $a=New-ScheduledTaskAction -Execute 'wscript.exe' -Argument ('\"'+$w+'\" \"'+$u+'\" /auto'); $g=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 30); $p=New-ScheduledTaskPrincipal -UserId ($env:USERDOMAIN+'\'+$env:USERNAME) -LogonType Interactive -RunLevel Highest; $s=New-ScheduledTaskSettingsSet -StartWhenAvailable -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1); Register-ScheduledTask -TaskName 'BONELIA AI Guncelle' -Action $a -Trigger $g -Principal $p -Settings $s -Force | Out-Null; Write-Host 'Otomatik guncelleme ayarlandi (30 dakikada bir).'}catch{Write-Host 'Not: otomatik guncelleme ayarlanamadi.'}"

echo.
echo [5/5] Kontrol (ajan sureci ayakta mi + durum)...
timeout /t 6 /nobreak >nul
tasklist /FI "IMAGENAME eq pythonw.exe" | find /I "pythonw.exe" >nul && (echo AJAN SURECI: CALISIYOR) || (echo AJAN SURECI: BULUNAMADI ^(sorun var^))
"%PY%" -m bonelia agent-status

echo.
echo ================================================================
echo  Bitti. Panelde bu bilgisayar birkac dakika icinde YESILE donmeli
echo  ve oyle kalmali. Hala kirmizi ise bu ekranin fotografini gonderin.
echo ================================================================
if not defined BONELIA_AUTO pause
