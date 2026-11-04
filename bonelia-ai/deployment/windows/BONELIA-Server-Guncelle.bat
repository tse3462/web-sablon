@echo off
rem Updates BONELIA AI from GitHub: server + background agent, in one double-click.
rem Stops the server, pulls the latest code, reinstalls, then restarts the background
rem agent (so it loads the new code) and starts the server again.
cd /d "%~dp0..\.."
call "%~dp0BONELIA-Server-Durdur.bat"

git pull
if errorlevel 1 (
  echo.
  echo GUNCELLEME BASARISIZ / UPDATE FEHLGESCHLAGEN: git pull hata verdi.
  echo Internet baglantisini kontrol edin / Internetverbindung pruefen.
  pause
  exit /b 1
)

call ".venv\Scripts\activate.bat"
pip install -e ".[server]"

rem Restart the background agent so the new code takes effect (safe if it is not installed).
schtasks /End /TN "BONELIA AI Agent" >nul 2>&1
schtasks /Run /TN "BONELIA AI Agent" >nul 2>&1

rem Bring the server AND the phone panel back up in the background with the new code.
rem (Durdur above stopped both, since they are the same bonelia-server.exe; both must
rem be restarted or the panel keeps serving the old version and the old phone link.)
call "%~dp0BONELIA-Server-Baslat.bat" /quiet
call "%~dp0BONELIA-Panel-Baslat.bat" /quiet

echo.
echo Guncelleme bitti / Update fertig. Sunucu, telefon paneli ve arka plan ajani
echo guncel surumle calisiyor. Telefon adresi: C:\BoneliaAI\server-data\panel-url.txt
echo (Server, Panel und Hintergrund-Agent laufen mit der neuen Version.)
pause
