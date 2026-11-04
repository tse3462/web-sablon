@echo off
rem One time: make BOTH the home server and the phone panel start at every login.
setlocal
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
(
  echo @echo off
  echo call "%~dp0BONELIA-Server-Baslat.bat" /quiet
  echo call "%~dp0BONELIA-Panel-Baslat.bat" /quiet
) > "%STARTUP%\BONELIA-AI.bat"
del "%STARTUP%\BONELIA-AI-Server.bat" 2>nul
del "%STARTUP%\BONELIA-AI-Panel.bat" 2>nul
echo Otomatik baslatma ayarlandi (sunucu + panel) / Autostart eingerichtet.
echo Simdi baslatiliyor... / Starte jetzt...
call "%~dp0BONELIA-Server-Baslat.bat"
call "%~dp0BONELIA-Panel-Baslat.bat"
endlocal
