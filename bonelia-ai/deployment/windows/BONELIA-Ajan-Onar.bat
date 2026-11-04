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
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
cd /d "%~dp0..\.."
set "ROOT=%CD%"
set "PY=%ROOT%\.venv\Scripts\python.exe"
set "PYW=%ROOT%\.venv\Scripts\pythonw.exe"

if not exist "%PY%" (
  echo .venv bulunamadi. Once BONELIA-Kurulumu-Onar.bat calistirin.
  pause
  exit /b 1
)

echo [1/4] Sunucu calisiyor mu kontrol ediliyor...
call "%~dp0BONELIA-Server-Baslat.bat" /quiet

echo.
echo [2/4] Ajan simdi bir kez calistiriliyor (panelde YESILE donmeli)...
"%PY%" -m bonelia agent --once

echo.
echo [3/4] Her acilista otomatik baslatma ayarlaniyor (bu kullanici + yonetici)...
schtasks /Delete /F /TN "BONELIA AI Agent" >nul 2>&1
schtasks /Create /F /TN "BONELIA AI Agent" /SC ONLOGON /RL HIGHEST /IT /TR "\"%PYW%\" -m bonelia agent"
rem Hide the task in Task Scheduler (best effort; it still works if this fails).
powershell -NoProfile -Command "try{$t=Get-ScheduledTask -TaskName 'BONELIA AI Agent' -ErrorAction Stop; $t.Settings.Hidden=$true; Set-ScheduledTask -InputObject $t | Out-Null}catch{}" >nul 2>&1
schtasks /Run /TN "BONELIA AI Agent" >nul 2>&1

echo.
echo [4/4] Durum:
"%PY%" -m bonelia agent-status

echo.
echo ================================================================
echo  Bitti. Panelde bu bilgisayar birkac dakika icinde YESILE donmeli.
echo  Bundan sonra her bilgisayar acilisinda kendiliginden calisacak.
echo ================================================================
pause
