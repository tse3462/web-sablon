@echo off
rem One time: start the home server + phone panel HIDDEN at every login.
rem Uses a hidden logon scheduled task (no window flash, not shown in the Windows
rem "Startup apps" list) instead of the visible Startup folder.
setlocal
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

rem Remove old visible Startup-folder entries from earlier versions.
del "%STARTUP%\BONELIA-AI.bat" 2>nul
del "%STARTUP%\BONELIA-AI-Server.bat" 2>nul
del "%STARTUP%\BONELIA-AI-Panel.bat" 2>nul

set "VBS=%~dp0baslatici-gizli.vbs"
schtasks /Create /F /TN "BONELIA AI" /SC ONLOGON /IT /TR "wscript.exe \"%VBS%\"" >nul

rem Hide the task in Task Scheduler (best effort; the task still works if this fails).
powershell -NoProfile -Command "try{$t=Get-ScheduledTask -TaskName 'BONELIA AI' -ErrorAction Stop; $t.Settings.Hidden=$true; Set-ScheduledTask -InputObject $t | Out-Null}catch{}" >nul 2>&1

echo Otomatik baslatma ayarlandi - GIZLI (pencere gorunmez).
echo Autostart eingerichtet - versteckt (kein Fenster).
echo.
echo Simdi baslatiliyor... / Starte jetzt...
wscript.exe "%VBS%"
endlocal
if not defined CI timeout /t 4 >nul
exit /b 0
