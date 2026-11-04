@echo off
rem BONELIA AI control panel in the background on the Tailscale address (phone access). No console window.
setlocal
cd /d "%~dp0..\.."
set "ROOT=%CD%"
set "CFG=%ROOT%\deployment\server.home.toml"
if defined BONELIA_CONFIG set "CFG=%BONELIA_CONFIG%"
set "PORT=8750"

curl.exe -s -o nul --max-time 2 "http://127.0.0.1:%PORT%/" 2>nul
if %ERRORLEVEL%==0 goto :running

set "EXE=%ROOT%\.venv\Scripts\bonelia-server.exe"
if not exist "%EXE%" (
  for /f "delims=" %%i in ('where bonelia-server.exe 2^>nul') do set "EXE=%%i"
)
if not exist "%EXE%" (
  echo Kurulum bulunamadi / Installation nicht gefunden.
  if not defined CI timeout /t 5 >nul
  exit /b 1
)
powershell -NoProfile -Command "Start-Process -FilePath '%EXE%' -ArgumentList '--config','\"%CFG%\"','dashboard','--host','auto','--port','%PORT%','--no-browser' -WorkingDirectory '%ROOT%' -WindowStyle Hidden"
:running
if "%~1"=="/quiet" exit /b 0
timeout /t 3 /nobreak >nul
if exist "C:\BoneliaAI\server-data\panel-url.txt" (
  start notepad "C:\BoneliaAI\server-data\panel-url.txt"
) else (
  echo Panel calisiyor: http://127.0.0.1:%PORT%/  (telefon icin Tailscale adresi panel-url.txt'de)
  if not defined CI timeout /t 5 >nul
)
endlocal
exit /b 0
