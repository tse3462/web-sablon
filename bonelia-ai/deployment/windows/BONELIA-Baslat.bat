@echo off
rem BONELIA AI: start the home server and the phone panel in the background (double-click).
rem Pass /quiet to start both without any prompt or pause (used by the hidden autostart).
cd /d "%~dp0"
call "%~dp0BONELIA-Server-Baslat.bat" %1
call "%~dp0BONELIA-Panel-Baslat.bat" %1
exit /b 0
