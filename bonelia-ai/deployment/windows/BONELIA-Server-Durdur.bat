@echo off
rem Stops the BONELIA AI Server and phone panel started in the background: the current way
rem (python.exe -m bonelia.server) and the old one (bonelia-server.exe).
rem BONELIA-Ajan-Onar starts them with admin rights; such processes can only be stopped with admin
rem rights, so when they are still running this script asks once for "Ja" and repeats itself elevated.
set "STOPPED="
call :stop
call :alive
if defined ALIVE (
  net session >nul 2>&1 || (
    echo Sunucu yonetici izniyle calisiyor - durdurmak icin izin isteniyor, lutfen Ja deyin.
    echo Server laeuft mit Admin-Rechten - bitte mit Ja bestaetigen.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -Wait"
    set "STOPPED=1"
  )
)
if defined STOPPED (echo BONELIA AI Server durduruldu / gestoppt.) else (echo Calisan sunucu yok / kein laufender Server.)
if not defined CI timeout /t 3 >nul
exit /b 0

:stop
taskkill /IM bonelia-server.exe /T /F >nul 2>&1 && set "STOPPED=1"
powershell -NoProfile -Command "$p = @(Get-CimInstance Win32_Process -Filter \"Name='python.exe' OR Name='pythonw.exe'\" | Where-Object { $_.CommandLine -like '*-m bonelia.server*' }); $p | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; if ($p.Count -gt 0) { exit 0 } else { exit 1 }" >nul 2>&1 && set "STOPPED=1"
timeout /t 1 /nobreak >nul
exit /b 0

:alive
set "ALIVE="
tasklist /FI "IMAGENAME eq bonelia-server.exe" 2>nul | find /I "bonelia-server.exe" >nul && set "ALIVE=1"
powershell -NoProfile -Command "if (@(Get-CimInstance Win32_Process -Filter \"Name='python.exe' OR Name='pythonw.exe'\" | Where-Object { $_.CommandLine -like '*-m bonelia.server*' }).Count -gt 0) { exit 0 } else { exit 1 }" >nul 2>&1 && set "ALIVE=1"
exit /b 0
