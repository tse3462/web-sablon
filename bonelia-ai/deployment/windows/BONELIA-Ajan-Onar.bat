@echo off
rem Repairs and starts the background agent (the SYSTEM task that does unattended
rem monitoring, auto-repair and the daily disk cleanup). Needs admin, so it elevates
rem itself (click "Ja"/"Yes" on the Windows prompt). Run this after the .venv was
rem recreated, so the agent points at the working Python and comes back online (green).
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
cd /d "%~dp0..\.."
set "ROOT=%CD%"
set "MON=%ROOT%\.venv\Scripts\bonelia-monitor.exe"

if not exist "%MON%" (
  echo bonelia-monitor bulunamadi. Once BONELIA-Kurulumu-Onar.bat calistirin.
  pause
  exit /b 1
)

echo Arka plan ajani yeniden kuruluyor ve baslatiliyor (yonetici)...
echo.
"%MON%" agent-install --yes --label "%COMPUTERNAME%"
echo.
echo --- Durum ---
"%MON%" agent-status

echo.
echo ================================================================
echo  Ajan baslatildi. Panelde bu bilgisayar (kurulu bilgisayar)
echo  birkac dakika icinde YESILE donmeli.
echo ================================================================
pause
