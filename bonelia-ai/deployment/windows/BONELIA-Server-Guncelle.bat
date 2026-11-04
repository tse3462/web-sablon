@echo off
rem Updates the home server from GitHub (stops it first so the file is not locked).
cd /d "%~dp0..\.."
call "%~dp0BONELIA-Server-Durdur.bat"
git pull
call ".venv\Scripts\activate.bat"
pip install -e ".[server]"
echo.
echo Guncelleme bitti / Update fertig. Sunucuyu baslatin: BONELIA-Server-Baslat.bat
pause
