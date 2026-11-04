@echo off
rem Starts the BONELIA AI Server automatically when this Windows user logs in.
rem Undo with Otomatik-Baslatma-KAPAT.bat. Changes only the current user's Startup folder.
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
(
  echo @echo off
  echo call "%~dp0BONELIA-Server-Baslat.bat"
) > "%STARTUP%\BONELIA-AI-Server.bat"
echo Otomatik baslatma ACIK / Autostart AKTIV: "%STARTUP%\BONELIA-AI-Server.bat"
if not defined CI timeout /t 4 >nul
