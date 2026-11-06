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


rem Bring the server AND the phone panel back up in the background with the new code.
rem (Durdur above stopped both, since they are the same server program; both must
rem be restarted or the panel keeps serving the old version and the old phone link.)
call "%~dp0BONELIA-Server-Baslat.bat" /quiet
call "%~dp0BONELIA-Panel-Baslat.bat" /quiet

rem Restart the background agent on the new code. It runs with admin rights, so this needs
rem one "Ja/Yes" (UAC). BONELIA-Ajan-Onar stops every old agent process first, so exactly one
rem agent runs afterwards (two agents at once would double some actions).
call "%~dp0BONELIA-Ajan-Onar.bat"

echo.
echo Guncelleme bitti / Update fertig. Sunucu, telefon paneli ve arka plan ajani
echo guncel surumle calisiyor. Telefon adresi: C:\BoneliaAI\server-data\panel-url.txt
echo (Server, Panel und Hintergrund-Agent laufen mit der neuen Version.)
pause
