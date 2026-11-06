@echo off
rem BONELIA AI Control Center: opens in the browser (this PC only). Close it with the "Kapat" button.
setlocal
cd /d "%~dp0..\.."
set "ROOT=%CD%"
rem Signed python.exe, not pip's unsigned bonelia-server.exe: Windows Smart App Control blocks the latter.
set "PY=%ROOT%\.venv\Scripts\python.exe"
if not exist "%PY%" (
  set "PYF="
  for /f "delims=" %%i in ('where python.exe 2^>nul') do if not defined PYF set "PYF=%%i"
  call set "PY=%%PYF%%"
)
if not exist "%PY%" (
  echo Kurulum bulunamadi / Installation nicht gefunden.
  timeout /t 5 >nul
  exit /b 1
)
set "CFG=%CD%\deployment\server.home.toml"
if defined BONELIA_CONFIG set "CFG=%BONELIA_CONFIG%"
powershell -NoProfile -Command "Start-Process -FilePath '%PY%' -ArgumentList '-m','bonelia.server','--config','\"%CFG%\"','dashboard' -WorkingDirectory '%CD%' -WindowStyle Hidden"
endlocal
