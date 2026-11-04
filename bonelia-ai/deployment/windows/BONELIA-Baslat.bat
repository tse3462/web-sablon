@echo off
rem BONELIA AI: start the home server and the phone panel in the background (double-click).
cd /d "%~dp0"
call "%~dp0BONELIA-Server-Baslat.bat"
call "%~dp0BONELIA-Panel-Baslat.bat"
exit /b 0
