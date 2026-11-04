@echo off
rem One time: make the phone control panel start automatically at every login, then start it now.
setlocal
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
(
  echo @echo off
  echo call "%~dp0BONELIA-Panel-Baslat.bat" /quiet
) > "%STARTUP%\BONELIA-AI-Panel.bat"
echo Telefon paneli otomatik baslatmaya eklendi / Autostart aktiv.
call "%~dp0BONELIA-Panel-Baslat.bat"
endlocal
