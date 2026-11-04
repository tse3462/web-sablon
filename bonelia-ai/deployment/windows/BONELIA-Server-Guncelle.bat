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

rem Bring the server back up in the background.
call "%~dp0BONELIA-Server-Baslat.bat" /quiet

echo.
echo Guncelleme bitti / Update fertig. Sunucu ve arka plan ajani guncel surumle calisiyor.
echo (Server und Hintergrund-Agent laufen mit der neuen Version.)
pause
