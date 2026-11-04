@echo off
rem BONELIA AI Control Center: opens in the browser (this PC only). Close it with the "Kapat" button.
setlocal
cd /d "%~dp0..\.."
set "EXE=%CD%\.venv\Scripts\bonelia-server.exe"
if not exist "%EXE%" (
  for /f "delims=" %%i in ('where bonelia-server.exe 2^>nul') do set "EXE=%%i"
)
if not exist "%EXE%" (
  echo Kurulum bulunamadi / Installation nicht gefunden.
  timeout /t 5 >nul
  exit /b 1
)
set "CFG=%CD%\deployment\server.home.toml"
if defined BONELIA_CONFIG set "CFG=%BONELIA_CONFIG%"
powershell -NoProfile -Command "Start-Process -FilePath '%EXE%' -ArgumentList '--config','\"%CFG%\"','dashboard' -WorkingDirectory '%CD%' -WindowStyle Hidden"
endlocal
