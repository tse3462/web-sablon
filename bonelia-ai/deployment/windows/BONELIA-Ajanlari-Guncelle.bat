@echo off
rem BONELIA AI - update the agent on EVERY installed PC from home, in one double-click.
rem Plug in the USB with the new BONELIA-AI-Portable package first. This publishes its agent program,
rem signed with this server's key; the installed PCs (switched on and online) download it within
rem about 15 minutes, check the signature and update themselves. Nobody has to visit them.
setlocal
cd /d "%~dp0..\.."
set "ROOT=%CD%"
set "CFG=%ROOT%\deployment\server.home.toml"
if defined BONELIA_CONFIG set "CFG=%BONELIA_CONFIG%"

rem Signed python.exe, not pip's unsigned bonelia-server.exe: Windows Smart App Control blocks the latter.
set "PY=%ROOT%\.venv\Scripts\python.exe"
if not exist "%PY%" (
  set "PYF="
  for /f "delims=" %%i in ('where python.exe 2^>nul') do if not defined PYF set "PYF=%%i"
  call set "PY=%%PYF%%"
)
if not exist "%PY%" (
  echo Kurulum bulunamadi / Installation nicht gefunden: %ROOT%\.venv
  goto :fail
)

rem The agent program: given as argument, or found on the USB stick (any drive letter).
set "AGENT=%~1"
if not defined AGENT for %%d in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
  if not defined AGENT if exist "%%d:\BONELIA-AI-Portable\BoneliaAI-Konsol.exe" set "AGENT=%%d:\BONELIA-AI-Portable\BoneliaAI-Konsol.exe"
)
if not defined AGENT for %%d in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
  if not defined AGENT if exist "%%d:\BoneliaAI-Konsol.exe" set "AGENT=%%d:\BoneliaAI-Konsol.exe"
)
if not defined AGENT (
  echo USB bulunamadi. Yeni BONELIA-AI-Portable paketinin oldugu USB'yi takip tekrar deneyin.
  echo USB nicht gefunden. USB-Stick mit dem neuen BONELIA-AI-Portable-Paket einstecken und erneut starten.
  goto :fail
)

echo Gonderiliyor / Wird veroeffentlicht: %AGENT%
"%PY%" -m bonelia.server --config "%CFG%" publish-agent "%AGENT%"
if errorlevel 1 goto :fail

echo.
echo TAMAM. Kurulu bilgisayarlar yaklasik 15 dakika icinde kendini gunceller
echo (acik ve internete bagli olanlar; kapali olanlar acilinca).
echo FERTIG. Die installierten PCs aktualisieren sich in etwa 15 Minuten.
if not defined CI pause
endlocal & exit /b 0

:fail
echo.
echo GUNCELLEME GONDERILEMEDI / NICHT VEROEFFENTLICHT.
if not defined CI pause
endlocal & exit /b 1
